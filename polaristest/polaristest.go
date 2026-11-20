// Package polaristest boots a complete Polaris server for tests: a fresh database (SQLite in a temp
// file by default; see WithDialect and EnvDB) with the schema and permission catalog installed, test RSA keys, recording mailer, SMS sender and event
// log, and a frozen rate-limit clock — the environment upstream's functional suite uses, so the
// contract fixtures replay. Applications built on Polaris use it for their own tests too.
//
//	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) { c.Hooks = myHooks }))
//	ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
//	tokens, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID})
//	// or over HTTP: httptest.NewServer(srv.Handler()); srv.Mailer.Sent() holds the mails sent
package polaristest

import (
	"context"
	"os"
	"sync"
	"testing"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/ratelimit"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
	"github.com/univeros/polaris-go/store/storetest"
	"github.com/univeros/polaris-go/wiring"
)

// Server is a booted Polaris with its recorders.
type Server struct {
	*polaris.Polaris
	DB     *sqlstore.Store
	Mailer *notifytest.Mailer
	SMS    *notifytest.SMSSender
	Events *Events
}

// Option adjusts the server before it boots.
type Option func(*options)

type options struct {
	auth    func(*config.Auth)
	plugins []polaris.Plugin
	prefix  string
	db      *sqlstore.Store
	secrets func(*config.Secrets)
	noRec   bool
	dialect store.Dialect
	hasher  security.PasswordHasher
	config  []func(*polaris.Config)
}

// EnvDB names the environment variable that picks the database every server boots on when no
// WithDialect is given: "sqlite" (default), "postgres" or "mysql". PostgreSQL and MySQL also need
// storetest.EnvPostgresDSN / storetest.EnvMySQLDSN; each server gets its own schema / database,
// dropped when the test ends. scripts/test-db-matrix.sh runs the suites this way.
const EnvDB = "POLARIS_TEST_DB"

// WithDialect boots on a fresh database of dialect d (store.SQLite, store.Postgres or store.MySQL),
// overriding EnvDB.
func WithDialect(d store.Dialect) Option { return func(o *options) { o.dialect = d } }

// WithAuth edits the auth configuration (start: config.Defaults with the test issuer).
func WithAuth(f func(*config.Auth)) Option { return func(o *options) { o.auth = f } }

// WithPlugins installs plugins (their tables, routes, permissions).
func WithPlugins(p ...polaris.Plugin) Option {
	return func(o *options) { o.plugins = append(o.plugins, p...) }
}

// WithSecrets edits the secrets (start: the test APP_KEY and RSA key pair), e.g. to add a
// previous key for a rotation test.
func WithSecrets(f func(*config.Secrets)) Option { return func(o *options) { o.secrets = f } }

// WithoutRecorders leaves Config.Mailer and Config.SMS unset, so a plugin's ports (messaging) or the
// log defaults serve them; srv.Mailer and srv.SMS stay non-nil but receive nothing.
func WithoutRecorders() Option { return func(o *options) { o.noRec = true } }

// WithPathPrefix mounts the routes under prefix.
func WithPathPrefix(prefix string) Option { return func(o *options) { o.prefix = prefix } }

// WithDB reuses a database from an earlier boot (a test that reboots with other flags keeps its
// data, as upstream's boot() does).
func WithDB(db *sqlstore.Store) Option { return func(o *options) { o.db = db } }

// WithHasher replaces the cheap test Argon2id (Memory 1 MiB, Time 1, Threads 1), e.g. with
// security.Argon2id{} to measure production parameters.
func WithHasher(h security.PasswordHasher) Option { return func(o *options) { o.hasher = h } }

// WithConfig edits the configuration last, before polaris.New: Hooks, Permissions, Middleware,
// Listeners, anything the other options do not cover.
func WithConfig(f func(*polaris.Config)) Option {
	return func(o *options) { o.config = append(o.config, f) }
}

// New boots a server; failures stop the test.
func New(t testing.TB, opts ...Option) *Server {
	t.Helper()
	o := options{}
	for _, opt := range opts {
		opt(&o)
	}
	ctx := context.Background()

	auth := config.Defaults()
	auth.Issuer = contracttest.Issuer
	auth.Audience = contracttest.Audience
	if o.auth != nil {
		o.auth(&auth)
	}
	private, public := contracttest.TestRSAKeyPEM()
	secrets := config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public}
	if o.secrets != nil {
		o.secrets(&secrets)
	}

	db := o.db
	if db == nil {
		db = openDB(t, ctx, o.dialect, o.plugins)
	}
	srv := &Server{DB: db, Mailer: &notifytest.Mailer{}, SMS: &notifytest.SMSSender{}, Events: &Events{}}
	cfg := polaris.Config{
		Secrets: secrets,
		Auth:    auth,
		DB:      db,
		Mailer:  srv.Mailer,
		SMS:     srv.SMS,
		Events:  srv.Events,
		// Cheap Argon2id: the suite hashes hundreds of passwords; the format is unchanged.
		Hasher:     security.Argon2id{Memory: 1024, Time: 1, Threads: 1},
		RateStore:  ratelimit.NewCacheStore(cache.NewMemory(contracttest.NewRateClock()), contracttest.NewRateClock()),
		PathPrefix: o.prefix,
		Plugins:    o.plugins,
	}
	if o.noRec {
		cfg.Mailer, cfg.SMS = nil, nil
	}
	if o.hasher != nil {
		cfg.Hasher = o.hasher
	}
	for _, f := range o.config {
		f(&cfg)
	}
	p, err := polaris.New(cfg)
	if err != nil {
		t.Fatalf("polaristest: %v", err)
	}
	srv.Polaris = p
	g := p.Graph()
	srv.Events.bus.Subscribe(g.Listeners()...)
	if o.db == nil {
		if err := authz.Seed(ctx, db, g.Catalog(), g.Clock()); err != nil {
			t.Fatalf("polaristest: seed: %v", err)
		}
	}
	return srv
}

// Graph is the server's service graph.
func (s *Server) Graph() *wiring.Graph { return s.Polaris.Graph() }

func openDB(t testing.TB, ctx context.Context, d store.Dialect, plugins []polaris.Plugin) *sqlstore.Store {
	t.Helper()
	if d == "" {
		d = store.Dialect(os.Getenv(EnvDB))
	}
	if d == "" {
		d = store.SQLite
	}
	db := storetest.OpenSQL(t, d)
	var extra [][]schema.Model
	for _, p := range plugins {
		if sp, ok := p.(wiring.SchemaProvider); ok {
			extra = append(extra, sp.Schema())
		}
	}
	models, err := schema.Merge(schema.Core(), extra...)
	if err != nil {
		t.Fatalf("polaristest: %v", err)
	}
	if err := db.CreateSchema(ctx, models); err != nil {
		t.Fatalf("polaristest: %v", err)
	}
	return db
}

// Events records every dispatched event and forwards it to Polaris's own listeners.
type Events struct {
	mu     sync.Mutex
	events []event.Event
	bus    event.Bus
}

// Dispatch implements event.Dispatcher.
func (e *Events) Dispatch(ctx context.Context, ev event.Event) {
	e.mu.Lock()
	e.events = append(e.events, ev)
	e.mu.Unlock()
	e.bus.Dispatch(ctx, ev)
}

// All returns the events dispatched so far, in order.
func (e *Events) All() []event.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]event.Event(nil), e.events...)
}

// Names returns the names of the events dispatched so far, in order.
func (e *Events) Names() []string {
	var names []string
	for _, ev := range e.All() {
		names = append(names, ev.EventName())
	}
	return names
}
