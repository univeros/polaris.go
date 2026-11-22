// Package audit is the audit plugin: every Polaris event becomes a
// catalogued, redacted, append-only record in polaris_audit_event that callers query per user
// (GET /audit/me) and per organization (GET /audit/organization/{id}, audit.read), streamed to
// extra sinks and to each organization's drains, pruned by a retention policy and, optionally,
// chained by SHA-256 for tamper evidence.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{})},
//	})
//
// Every field of Config is optional. Run Plugin.Prune from a scheduled job and Plugin.Verify to
// check the chain.
package audit

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/internal/maintenance"
	"github.com/univeros/polaris.go/internal/netguard"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.audit.*.
const ID = "audit"

// Config configures the plugin; the zero value keeps 90 days, no chain, the database sink only.
type Config struct {
	// Retention is how long events are kept; zero: DefaultRetention for every name.
	Retention Retention
	// HashChain links each row to the previous one by SHA-256 (Verify checks it); writers in every
	// process append through the polaris_audit_chain lock row, one at a time.
	HashChain bool
	// Sinks receive every event beside the database (LogSink, FileSink, WebhookSink, yours).
	Sinks []Sink
	// Names are the application's own event names (name => description); a plugin implementing
	// NameProvider adds its own.
	Names map[string]string
	// ActivityInterval bounds how often a user's last activity is written; zero: 5 minutes.
	ActivityInterval time.Duration
	// Drains delivers the organizations' drains: each batch after the transaction that recorded
	// it commits, off the writer's goroutine, to public addresses only (decided after DNS
	// resolution), without following redirects.
	Drains bool
	// HTTPClient is the client drains are delivered with instead of that default; the addresses
	// it may reach are then yours to bound (an egress proxy, a dialer of your own). Redirects are
	// never followed, whichever client is used. Setting it also turns Drains on.
	HTTPClient *http.Client
	// WebhookAttempts per drain delivery; zero: 3.
	WebhookAttempts int
}

// Plugin is the audit plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg      Config
	sleep    func(time.Duration) // tests replace the webhook pause
	policy   policy
	catalog  *Catalog
	store    *Store
	drains   *Drains
	sink     *drainSink // nil when drains are not delivered
	recorder *Recorder
	activity *Activity
	clock    clock.Clock
	logger   *slog.Logger
	db       store.Adapter
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_audit_event, polaris_audit_drain, polaris_audit_activity and
// polaris_audit_chain (the hash chain's lock row).
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (declared in internal/apispec/api/audit).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/audit")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// Init builds the plugin's services from the graph.
func (p *Plugin) Init(g *wiring.Graph) error {
	var err error
	if p.policy, err = p.cfg.Retention.parse(); err != nil {
		return err
	}
	names := []map[string]string{p.cfg.Names}
	for _, other := range g.Plugins() {
		if np, ok := other.(NameProvider); ok {
			names = append(names, np.AuditNames())
		}
	}
	if p.catalog, err = NewCatalog(names...); err != nil {
		return err
	}
	p.clock, p.logger, p.db = g.Clock(), g.Logger(), g.DB()
	p.store = NewStore(g.DB(), p.cfg.HashChain)
	p.drains = NewDrains(g.DB(), g.Encrypter(), g.Clock())
	sinks := append([]Sink{databaseSink{p.store}}, p.cfg.Sinks...)
	if p.cfg.Drains || p.cfg.HTTPClient != nil {
		deferred := g.Deferred(func(_ context.Context, e event.Event) {
			if b, ok := e.(drainBatch); ok {
				b.run()
			}
		})
		p.sink = &drainSink{
			drains: p.drains, client: netguard.NoRedirects(p.cfg.HTTPClient), attempts: p.cfg.WebhookAttempts, sleep: p.sleep, logger: g.Logger(),
			after: func(ctx context.Context, fn func()) { deferred(ctx, drainBatch{run: fn}) },
		}
		sinks = append(sinks, p.sink)
	}
	p.recorder = NewRecorder(p.catalog, chain{sinks: sinks, logger: g.Logger()}, g.Clock(), g.Logger())
	p.activity = NewActivity(g.DB(), g.Cache(), g.Clock(), p.cfg.ActivityInterval, g.Logger())
	return nil
}

// Seed creates the hash chain's lock row (Polaris.Migrate calls it), so the first writes never
// race to create it. A no-op without HashChain.
func (p *Plugin) Seed(ctx context.Context) error {
	if !p.cfg.HashChain {
		return nil
	}
	return p.store.ensureHead(ctx)
}

// Endpoints serves the audit routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Listeners subscribes the recorder and the activity tracker.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{p.recorder.Listen, p.activity.Listen}
}

// EraseUser implements wiring.UserEraser: an erased user's activity row goes with the account, in
// its transaction (the events stay: the trail outlives the account).
func (p *Plugin) EraseUser(ctx context.Context, userID string) error {
	return maintenance.EraseUser(ctx, p.db, userID, maintenance.UserRows{Table: TableActivity, Column: "user_id"})
}

// Catalog is the closed list of event names.
func (p *Plugin) Catalog() *Catalog { return p.catalog }

// Store reads and writes the events.
func (p *Plugin) Store() *Store { return p.store }

// Drains manages the organizations' drains.
func (p *Plugin) Drains() *Drains { return p.drains }

// WaitDrains returns when no drain delivery is in flight, or when ctx ends: call it before the
// process exits (deliveries run on their own goroutines, 15 s at most each), and in a test before
// reading a drain's outcome.
func (p *Plugin) WaitDrains(ctx context.Context) {
	if p.sink != nil {
		p.sink.wait(ctx)
	}
}

// Activity is the last-activity tracker.
func (p *Plugin) Activity() *Activity { return p.activity }

// Record emits an event of the application (its name in Config.Names): checked, redacted, written
// to every sink.
func (p *Plugin) Record(ctx context.Context, e Event) error { return p.recorder.Record(ctx, e) }

// Of returns the audit plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}
