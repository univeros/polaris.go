package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/netguard"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
)

// Drain types and statuses.
const (
	DrainWebhook = "webhook"
	DrainActive  = "active"
	DrainPaused  = "paused"
)

// Drain is a per-organization delivery target (polaris_audit_drain): the organization's events
// matching Filter are posted to Endpoint, signed with Secret (encrypted at rest, never answered).
type Drain struct {
	ID             string
	OrganizationID string
	Type           string
	Endpoint       string
	Secret         string
	Filter         []string // names or "prefix.*" patterns; empty means every event
	Status         string
	LastDeliveryAt *time.Time
	LastError      string
	CreatedAt      time.Time
	CreatedBy      string
}

// Accepts reports whether the drain's filter takes name.
func (d Drain) Accepts(name string) bool {
	if len(d.Filter) == 0 {
		return true
	}
	for _, p := range d.Filter {
		if p == name || (strings.HasSuffix(p, ".*") && strings.HasPrefix(name, strings.TrimSuffix(p, "*"))) {
			return true
		}
	}
	return false
}

// Map is the drain's wire shape, without the secret.
func (d Drain) Map() map[string]any {
	filter := d.Filter
	if filter == nil {
		filter = []string{}
	}
	var last any
	if d.LastDeliveryAt != nil {
		last = timestamp(*d.LastDeliveryAt)
	}
	return map[string]any{
		"id":               d.ID,
		"organization_id":  d.OrganizationID,
		"type":             d.Type,
		"endpoint":         d.Endpoint,
		"filter":           filter,
		"status":           d.Status,
		"last_delivery_at": last,
		"last_error":       null(d.LastError),
		"created_at":       timestamp(d.CreatedAt),
	}
}

// Drains manages the per-organization drains (admin routes) and is read at delivery time.
type Drains struct {
	db        store.Adapter
	encrypter security.Encrypter
	clock     clock.Clock
}

// NewDrains returns the drain service.
func NewDrains(db store.Adapter, encrypter security.Encrypter, clk clock.Clock) *Drains {
	return &Drains{db: db, encrypter: encrypter, clock: clk}
}

// Create adds an active webhook drain for organizationID.
func (d *Drains) Create(ctx context.Context, organizationID, endpoint, secret string, filter []string, createdBy string) (Drain, error) {
	sealed, err := d.encrypter.Encrypt(secret)
	if err != nil {
		return Drain{}, err
	}
	if filter == nil {
		filter = []string{}
	}
	encodedFilter, err := store.JSONValue(filter)
	if err != nil {
		return Drain{}, err
	}
	dr := Drain{
		ID: repository.NewID(), OrganizationID: organizationID, Type: DrainWebhook, Endpoint: endpoint,
		Secret: secret, Filter: filter, Status: DrainActive, CreatedAt: d.clock.Now().UTC().Truncate(time.Second), CreatedBy: createdBy,
	}
	return dr, d.db.Insert(ctx, TableDrains, store.Row{
		"id": dr.ID, "organization_id": organizationID, "type": dr.Type, "endpoint": endpoint,
		"secret": sealed, "filter": encodedFilter, "status": dr.Status, "last_delivery_at": nil,
		"last_error": nil, "created_at": dr.CreatedAt, "created_by": null(createdBy),
	})
}

// Find returns the drain id names, ok false when absent.
func (d *Drains) Find(ctx context.Context, id string) (Drain, bool, error) {
	r, err := d.db.FindOne(ctx, TableDrains, store.Criteria{"id": id})
	if err != nil || r == nil {
		return Drain{}, false, err
	}
	dr, err := d.hydrate(r)
	return dr, err == nil, err
}

// ForOrganization lists an organization's drains, oldest first; activeOnly skips paused ones.
func (d *Drains) ForOrganization(ctx context.Context, organizationID string, activeOnly bool) ([]Drain, error) {
	c := store.Criteria{"organization_id": organizationID}
	if activeOnly {
		c["status"] = DrainActive
	}
	rows, err := d.db.FindMany(ctx, TableDrains, c, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Drain, 0, len(rows))
	for _, r := range rows {
		dr, err := d.hydrate(r)
		if err != nil {
			return nil, err
		}
		out = append(out, dr)
	}
	return out, nil
}

// SetStatus pauses (DrainPaused) or resumes (DrainActive) a drain.
func (d *Drains) SetStatus(ctx context.Context, id, status string) error {
	_, err := d.db.Update(ctx, TableDrains, store.Criteria{"id": id}, store.Data{"status": status})
	return err
}

// Delete removes a drain; false when it did not exist.
func (d *Drains) Delete(ctx context.Context, id string) (bool, error) {
	n, err := d.db.Delete(ctx, TableDrains, store.Criteria{"id": id})
	return n > 0, err
}

// RecordDelivery stamps the last delivery and its error ("" on success). The drain's owner reads
// it: pass a category (DrainRefused, …), not a transport error.
func (d *Drains) RecordDelivery(ctx context.Context, id, deliveryErr string) error {
	_, err := d.db.Update(ctx, TableDrains, store.Criteria{"id": id}, store.Data{"last_delivery_at": d.clock.Now(), "last_error": null(deliveryErr)})
	return err
}

func (d *Drains) hydrate(r store.Row) (Drain, error) {
	secret, err := d.encrypter.Decrypt(r.String("secret"))
	if err != nil {
		return Drain{}, err
	}
	dr := Drain{
		ID: r.String("id"), OrganizationID: r.String("organization_id"), Type: r.String("type"),
		Endpoint: r.String("endpoint"), Secret: secret, Status: r.String("status"),
		LastDeliveryAt: r.TimePtr("last_delivery_at"), LastError: r.String("last_error"), CreatedBy: r.String("created_by"),
		Filter: []string{},
	}
	dr.CreatedAt, _ = r.Time("created_at")
	_ = r.JSON("filter", &dr.Filter)
	return dr, nil
}

// Delivery bounds: one batch to an organization's drains gets drainTimeout in all (retries
// included), and at most maxDrainDeliveries batches are in flight; a batch beyond that is dropped
// and logged, so a slow endpoint cannot pile work up behind it.
const (
	drainTimeout       = 15 * time.Second
	maxDrainDeliveries = 32
)

// The categories a drain's last_error holds. The transport's own words (addresses, DNS answers,
// TLS errors) are logged, never stored: the drain's owner reads this field, and they would tell
// it what this server can reach.
const (
	DrainRefused     = "refused"     // the endpoint is not a public address
	DrainTimeout     = "timeout"     // no answer in time
	DrainUnreachable = "unreachable" // any other transport failure
)

// drainFailure is the category of a failed delivery: one of the constants above, or "HTTP <status>".
func drainFailure(err error) string {
	var failed *webhookError
	var timeout interface{ Timeout() bool }
	switch {
	case errors.Is(err, netguard.ErrNonPublicAddress):
		return DrainRefused
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()):
		return DrainTimeout
	case errors.As(err, &failed) && failed.status != 0:
		return fmt.Sprintf("HTTP %d", failed.status)
	}
	return DrainUnreachable
}

// drainBatch carries a delivery through wiring.Graph.Deferred, which delays listeners: it is an
// event only for that.
type drainBatch struct{ run func() }

func (drainBatch) EventName() string { return "audit.drain_batch" }

// drainSink delivers each organization's events to its active drains, one WebhookSink per drain,
// and records the outcome on the drain; a failing drain affects nothing else. Delivery never
// runs on the writer: it starts after the transaction that recorded the events commits (never
// when it rolls back), on its own goroutine, under drainTimeout.
type drainSink struct {
	drains   *Drains
	client   *http.Client
	attempts int
	sleep    func(time.Duration)
	logger   *slog.Logger
	// after runs fn once the transaction of ctx commits (nil: at once).
	after func(ctx context.Context, fn func())

	mu       sync.Mutex
	inflight int
	idle     chan struct{} // closed when inflight returns to zero
}

func (s *drainSink) Write(ctx context.Context, events ...Event) error {
	var orgs []string
	byOrg := map[string][]Event{}
	for _, e := range events {
		if e.OrganizationID == "" {
			continue
		}
		if _, seen := byOrg[e.OrganizationID]; !seen {
			orgs = append(orgs, e.OrganizationID)
		}
		byOrg[e.OrganizationID] = append(byOrg[e.OrganizationID], e)
	}
	if len(orgs) == 0 {
		return nil
	}
	start := func() { s.start(orgs, byOrg) } //nolint:contextcheck // the delivery outlives the writer and must not join its transaction: start makes its own context
	if s.after == nil {
		start()
	} else {
		s.after(ctx, start)
	}
	return nil
}

// start delivers on a new goroutine. The delivery's context is its own: the writer's may carry a
// transaction (the host's, under sqlstore.WithTx) or end with the request.
func (s *drainSink) start(orgs []string, byOrg map[string][]Event) {
	s.mu.Lock()
	if s.inflight >= maxDrainDeliveries {
		s.mu.Unlock()
		s.logger.Warn("Audit drain delivery dropped: too many in flight", "organizations", len(orgs))
		return
	}
	if s.inflight++; s.inflight == 1 {
		s.idle = make(chan struct{})
	}
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			if s.inflight--; s.inflight == 0 {
				close(s.idle)
			}
			s.mu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		for _, org := range orgs {
			drains, err := s.drains.ForOrganization(ctx, org, true)
			if err != nil {
				s.logger.ErrorContext(ctx, "Audit drains not read", "organization", org, "reason", err.Error())
				continue
			}
			for _, dr := range drains {
				s.deliver(ctx, dr, byOrg[org])
			}
		}
	}()
}

// wait returns when no delivery is in flight, or when ctx ends.
func (s *drainSink) wait(ctx context.Context) {
	s.mu.Lock()
	idle, busy := s.idle, s.inflight > 0
	s.mu.Unlock()
	if !busy {
		return
	}
	select {
	case <-idle:
	case <-ctx.Done():
	}
}

func (s *drainSink) deliver(ctx context.Context, dr Drain, batch []Event) {
	var accepted []Event
	for _, e := range batch {
		if dr.Accepts(e.Name) {
			accepted = append(accepted, e)
		}
	}
	if len(accepted) == 0 {
		return
	}
	hook := WebhookSink{URL: dr.Endpoint, Secret: dr.Secret, Client: s.client, Attempts: s.attempts, Sleep: s.sleep}
	failure := ""
	if err := hook.Write(ctx, accepted...); err != nil {
		failure = drainFailure(err)
		s.logger.WarnContext(ctx, "Audit drain failed", "drain", dr.ID, "failure", failure, "reason", err.Error())
	}
	// The outcome is recorded even when the delivery used the whole budget.
	if err := s.drains.RecordDelivery(context.WithoutCancel(ctx), dr.ID, failure); err != nil {
		s.logger.ErrorContext(ctx, "Audit drain outcome not recorded", "drain", dr.ID, "reason", err.Error())
	}
}
