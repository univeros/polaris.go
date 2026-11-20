package sentinel

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// dateAtom is PHP's DATE_ATOM: UTC is written "+00:00".
const dateAtom = "2006-01-02T15:04:05-07:00"

// Page sizes of the decision list.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

func now(c clock.Clock) time.Time { return c.Now().UTC().Truncate(time.Second) }

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Decisions stores the decisions where a signal spoke, for the operators.
type Decisions struct {
	db    store.Adapter
	clock clock.Clock
}

// Filter narrows List; empty fields match everything.
type Filter struct {
	Email, IP, Action string
	Cursor            string // the id the previous page ended with
	Limit             int    // clamped to 1..MaxLimit; 0 means DefaultLimit
}

func (s *Decisions) record(ctx context.Context, a Attempt, d Decision) error {
	signals, err := store.JSONValue(d.Signals())
	if err != nil {
		return err
	}
	reasons, err := store.JSONValue(d.Reasons())
	if err != nil {
		return err
	}
	return s.db.Insert(ctx, TableDecisions, store.Row{
		"id": repository.NewID(), "kind": a.Kind, "email": null(a.Email), "ip": null(a.IP), "score": d.Score,
		"action": d.Action, "enforced": d.Enforced, "signals": signals, "reasons": reasons, "created_at": now(s.clock),
	})
}

// List answers the decisions newest first, in the wire shape {data, next_cursor}.
func (s *Decisions) List(ctx context.Context, f Filter) (map[string]any, error) {
	limit := f.Limit
	if limit == 0 {
		limit = DefaultLimit
	}
	limit = max(1, min(MaxLimit, limit))
	c := store.Criteria{}
	for col, v := range map[string]string{"email": f.Email, "ip": f.IP, "action": f.Action} {
		if v != "" {
			c[col] = v
		}
	}
	if f.Cursor != "" {
		c["id"] = store.Lt(f.Cursor)
	}
	rows, err := s.db.FindMany(ctx, TableDecisions, c, store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}, Limit: limit + 1})
	if err != nil {
		return nil, fmt.Errorf("sentinel: decisions: %w", err)
	}
	data := []map[string]any{}
	for i, r := range rows {
		if i == limit {
			break
		}
		data = append(data, decisionView(r))
	}
	var next any
	if len(rows) > limit {
		next = data[len(data)-1]["id"]
	}
	return map[string]any{"data": data, "next_cursor": next}, nil
}

func decisionView(r store.Row) map[string]any {
	created, _ := r.Time("created_at")
	return map[string]any{
		"id": r.String("id"), "kind": r.String("kind"), "email": null(r.String("email")), "ip": null(r.String("ip")),
		"score": r.Int("score"), "action": r.String("action"), "enforced": r.Bool("enforced"),
		"signals": stringList(r, "signals"), "reasons": stringList(r, "reasons"), "created_at": created.Format(dateAtom),
	}
}

// stringList reads a JSON list column, keeping its strings only.
func stringList(r store.Row, col string) []string {
	var raw []any
	_ = r.JSON(col, &raw)
	out := []string{}
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// IPRule is an operator's allow or block rule for an address or a CIDR block.
type IPRule struct {
	ID, CIDR, Action string
	Note             string // "" for none
	CreatedBy        string // the operator's id, "" for none
	CreatedAt        time.Time
}

// Map is the rule's wire shape.
func (r IPRule) Map() map[string]any {
	return map[string]any{"id": r.ID, "cidr": r.CIDR, "action": r.Action, "note": null(r.Note),
		"created_by": null(r.CreatedBy), "created_at": r.CreatedAt.Format(dateAtom)}
}

// IPRules stores the instance's allow and block rules; the first match in creation order wins.
type IPRules struct {
	db    store.Adapter
	clock clock.Clock
}

// All returns every rule in creation (and matching) order.
func (s *IPRules) All(ctx context.Context) ([]IPRule, error) {
	// ponytail: one query per guarded request; cache with invalidation if the table grows large.
	rows, err := s.db.FindMany(ctx, TableIPRules, store.Criteria{}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, fmt.Errorf("sentinel: ip rules: %w", err)
	}
	out := make([]IPRule, 0, len(rows))
	for _, r := range rows {
		created, _ := r.Time("created_at")
		out = append(out, IPRule{ID: r.String("id"), CIDR: r.String("cidr"), Action: r.String("action"),
			Note: r.String("note"), CreatedBy: r.String("created_by"), CreatedAt: created})
	}
	return out, nil
}

// Match returns the first rule matching ip; ok is false when none does.
func (s *IPRules) Match(ctx context.Context, ip string) (IPRule, bool, error) {
	rules, err := s.All(ctx)
	if err != nil {
		return IPRule{}, false, err
	}
	for _, r := range rules {
		if admin.AllowlistAllows([]string{r.CIDR}, ip) {
			return r, true, nil
		}
	}
	return IPRule{}, false, nil
}

// ErrInvalidRule wraps the refusal of a rule with a bad address or action.
var ErrInvalidRule = errors.New("sentinel: invalid ip rule")

// Add stores a rule: cidr an address or a CIDR block (both families), action Allow or Block.
func (s *IPRules) Add(ctx context.Context, cidr, action, note, createdBy string) (IPRule, error) {
	if !admin.ValidAllowlistEntry(cidr) || (action != Allow && action != Block) {
		return IPRule{}, fmt.Errorf("%w: %q %q", ErrInvalidRule, cidr, action)
	}
	r := IPRule{ID: repository.NewID(), CIDR: cidr, Action: action, Note: note, CreatedBy: createdBy, CreatedAt: now(s.clock)}
	err := s.db.Insert(ctx, TableIPRules, store.Row{"id": r.ID, "cidr": cidr, "action": action, "note": null(note),
		"created_by": null(createdBy), "created_at": r.CreatedAt})
	if err != nil {
		return IPRule{}, fmt.Errorf("sentinel: add ip rule: %w", err)
	}
	return r, nil
}

// Remove deletes a rule; false when it did not exist.
func (s *IPRules) Remove(ctx context.Context, id string) (bool, error) {
	n, err := s.db.Delete(ctx, TableIPRules, store.Criteria{"id": id})
	if err != nil {
		return false, fmt.Errorf("sentinel: remove ip rule: %w", err)
	}
	return n > 0, nil
}

// Device is a device a user signed in from: the hashed device cookie, the last address and, with
// a geo resolver, where.
type Device struct {
	UserID     string
	IP         string
	Location   *GeoPoint
	LastSeenAt time.Time
}

// devices stores the devices users signed in from.
type devices struct {
	db    store.Adapter
	clock clock.Clock
}

func (s *devices) find(ctx context.Context, userID, deviceID string) (bool, error) {
	n, err := s.db.Count(ctx, TableDevices, store.Criteria{"user_id": userID, "device_hash": sha256Hex(deviceID)})
	return n > 0, err
}

func (s *devices) count(ctx context.Context, userID string) (int64, error) {
	return s.db.Count(ctx, TableDevices, store.Criteria{"user_id": userID})
}

// latest is the device the user last signed in from; ok false when none.
func (s *devices) latest(ctx context.Context, userID string) (Device, bool, error) {
	rows, err := s.db.FindMany(ctx, TableDevices, store.Criteria{"user_id": userID},
		store.Query{OrderBy: []store.Order{{Column: "last_seen_at", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return Device{}, false, err
	}
	r := rows[0]
	seen, _ := r.Time("last_seen_at")
	d := Device{UserID: userID, IP: r.String("ip"), LastSeenAt: seen}
	lat, errLat := strconv.ParseFloat(r.String("latitude"), 64)
	lon, errLon := strconv.ParseFloat(r.String("longitude"), 64)
	if errLat == nil && errLon == nil {
		d.Location = &GeoPoint{Latitude: lat, Longitude: lon}
	}
	return d, true, nil
}

// record upserts the user's device with the address and location of this sign-in.
func (s *devices) record(ctx context.Context, userID, deviceID, ip string, at *GeoPoint) error {
	t := now(s.clock)
	data := store.Data{"ip": null(ip), "latitude": nil, "longitude": nil, "last_seen_at": t}
	if at != nil {
		data["latitude"] = strconv.FormatFloat(at.Latitude, 'f', -1, 64)
		data["longitude"] = strconv.FormatFloat(at.Longitude, 'f', -1, 64)
	}
	c := store.Criteria{"user_id": userID, "device_hash": sha256Hex(deviceID)}
	for range 2 { // a concurrent first sign-in may insert between the update and the insert
		if n, err := s.db.Update(ctx, TableDevices, c, data); err != nil || n > 0 {
			return err
		}
		row := store.Row{"id": repository.NewID(), "user_id": userID, "device_hash": c["device_hash"], "created_at": t}
		for k, v := range data {
			row[k] = v
		}
		err := s.db.Insert(ctx, TableDevices, row)
		if !errors.Is(err, store.ErrDuplicate) {
			return err
		}
	}
	return nil
}
