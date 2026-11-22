// Package wiring builds every Polaris service from a Config, explicitly and once, without a
// container.
//
// It is the plugin SDK, with packages endpoint, manifest, event and token: a plugin implements
// Plugin (plus the optional interfaces it needs) and receives the *Graph, whose accessor methods
// expose the services read-only. Hosts use the root package (polaris.New) and never need this one.
// API.md at the repository root is the API promise.
package wiring

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"slices"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/internal/identity"
	"github.com/univeros/polaris.go/internal/mfa"
	"github.com/univeros/polaris.go/internal/observe"
	"github.com/univeros/polaris.go/internal/orgs"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/internal/session"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/metrics"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/ratelimit"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// Config is everything a host decides. Secrets, Auth and DB are required; every other port has a
// working default.
type Config struct {
	Secrets config.Secrets // APP_KEY and the JWT keys; config.FromEnv reads them
	Auth    config.Auth    // start from config.Defaults(); config.FromEnv reads it
	DB      store.Adapter  // sqlstore.Open(...) in production, memstore.New(...) in tests

	Mailer   notify.Mailer                  // default: notify.NewLogMailer(Logger)
	SMS      notify.SMSSender               // default: notify.NewLogSMS(Logger)
	Breaches security.BreachedPasswordCheck // default: security.HIBP when Auth.Password.BreachCheck, else none
	// Hasher hashes passwords; default: security.Argon2id{} (64 MiB, 4 passes, 1 lane). Tests may
	// pass cheaper Argon2id parameters; hashes stay verifiable by any parameters.
	Hasher security.PasswordHasher
	Cache  cache.Cache // default: in-memory (not shared across replicas)
	// RateStore counts rate-limit hits; default: on Cache.
	RateStore ratelimit.Store
	Metrics   metrics.Metrics // default: metrics.NewLog(Logger)
	Clock     clock.Clock     // default: clock.System
	Logger    *slog.Logger    // default: slog.Default()
	// Events receives every domain event. Default: an in-process event.Bus with core's, the
	// plugins' and Listeners already subscribed. A host passing its own dispatcher subscribes
	// Graph.Listeners (which include Listeners) itself. It receives every event when it is
	// raised, inside the transaction if there is one; the listeners Graph.Listeners returns
	// already wait for the commit where they should (Graph.Deferred).
	Events event.Dispatcher
	// Listeners are the host's own event listeners for effects outside the database (mail,
	// webhooks, queues, telemetry), subscribed after core's and the plugins'. An event raised
	// inside a transaction (sqlstore.Store.Tx) reaches them right after it commits, and never if
	// it rolls back (Graph.Deferred). Package event names the events (a type switch on
	// event.UserRegistered, …).
	Listeners []event.Listener
	// TxListeners are the host's listeners that write to the database: they run when the event is
	// raised, inside its transaction, so a write made with their ctx (sqlstore.Store.Conn(ctx))
	// commits or rolls back with the action, as Polaris's own audit and erasure listeners do.
	// Keep them to database work; anything else belongs in Listeners.
	TxListeners []event.Listener

	// Hooks keep the host's own user data and token claims in step with Polaris; see Hooks.
	Hooks Hooks
	// Middleware wraps every Polaris handler (Handler and each Protect), outermost first:
	// Middleware[0] sees the request before anything else (tracing, request ids, recovery). A
	// host route behind none of them gets it through Polaris.Wrap.
	Middleware []func(http.Handler) http.Handler

	// Permissions are the host's own permission keys and descriptions ("billing.refund": "Refund an
	// invoice"), joined to the catalog so roles, API keys, OAuth scopes and agent capabilities can
	// carry them and Protect can require them. Migrate seeds them.
	Permissions map[string]string
	// RolePermissions gives the system roles of every organization the host's (or a plugin's)
	// permissions: role slug ("owner", "admin" or "member") → permission keys, e.g.
	// {"owner": {"invoices.read", "invoices.void"}, "admin": {"invoices.read"}}. New organizations
	// start with them; Migrate adds a newly declared one to every existing organization once (a
	// tenant may later remove it from admin or member; the owner role is not editable). Only an
	// actor holding a permission can grant it to a custom role, so without this a host
	// permission is grantable by a superadmin only. New refuses another slug or an undeclared or
	// core key. Removing a key here revokes nothing already granted.
	RolePermissions map[string][]string

	// PathPrefix is where the Polaris routes are mounted ("/api"); default "/".
	PathPrefix string
	// MaxBodyBytes bounds the request body of every Polaris route (a larger one is answered 413);
	// default pipeline.DefaultMaxBodyBytes (1 MiB), negative means no limit.
	MaxBodyBytes int64
	// Plugins extend Polaris; see Plugin.
	Plugins []Plugin
}

// Graph holds every service, built once by New and read through its accessor methods; nothing
// can replace a service after New returns. Services are safe for concurrent use.
type Graph struct {
	config  Config
	auth    config.Auth
	clock   clock.Clock
	logger  *slog.Logger
	events  event.Dispatcher
	cache   cache.Cache
	metrics metrics.Metrics
	mailer  notify.Mailer
	sms     notify.SMSSender

	db       store.Adapter
	schema   []schema.Model // core + plugin tables
	repos    *repository.Repos
	manifest *manifest.Manifest

	pepper    *security.Pepper
	encrypter security.Encrypter
	hasher    security.PasswordHasher
	breaches  security.BreachedPasswordCheck

	tokens   *token.Codec // access tokens
	jwks     token.JWKSet
	tickets  *session.MFATickets
	denylist *session.Denylist

	catalog    authz.Catalog
	resolver   *authz.Resolver
	gate       *authz.Gate
	principals *authz.Principals
	escalation *authz.EscalationGuard

	sessions *session.Service
	mfa      *mfa.Service
	identity *identity.Service
	orgs     *orgs.Service

	rateStore ratelimit.Store

	plugins   []Plugin
	byID      map[string]Plugin
	listeners []event.Listener
	bus       *event.Bus     // the default dispatcher, nil when the host passed its own
	committer afterCommitter // DB's AfterCommit, for Deferred; nil without one

	core *services.Services // the concrete services, for core only (internal/services)
}

// Plugin returns the plugin registered under id, nil when absent. Plugins that cooperate (agents on
// oauth) type-assert the result to the concrete plugin type.
func (g *Graph) Plugin(id string) Plugin { return g.byID[id] }

// Plugins returns the registered plugins in order.
func (g *Graph) Plugins() []Plugin { return slices.Clone(g.plugins) }

// Listeners returns core's and the plugins' event listeners, for a host that passed its own
// Config.Events dispatcher.
func (g *Graph) Listeners() []event.Listener { return slices.Clone(g.listeners) }

// New validates cfg and builds the graph. Every problem found is reported at once, each naming its
// fix.
func New(cfg Config) (*Graph, error) {
	var errs []error
	if cfg.DB == nil {
		errs = append(errs, errors.New("polaris: Config.DB is required: pass sqlstore.Open(ctx, dialect, dsn) or memstore.New(schema.Core()...)"))
	}
	if err := cfg.Secrets.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := cfg.Auth.Validate(); err != nil {
		errs = append(errs, err)
	}
	if slices.ContainsFunc(cfg.Listeners, func(l event.Listener) bool { return l == nil }) {
		errs = append(errs, errors.New("polaris: Config.Listeners holds a nil listener; remove it"))
	}
	if slices.ContainsFunc(cfg.TxListeners, func(l event.Listener) bool { return l == nil }) {
		errs = append(errs, errors.New("polaris: Config.TxListeners holds a nil listener; remove it"))
	}
	if slices.ContainsFunc(cfg.Middleware, func(m func(http.Handler) http.Handler) bool { return m == nil }) {
		errs = append(errs, errors.New("polaris: Config.Middleware holds a nil middleware; remove it"))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	g := &Graph{config: cfg, auth: cfg.Auth, db: cfg.DB, byID: map[string]Plugin{}}
	if err := g.registerPlugins(); err != nil {
		return nil, err
	}
	g.defaults()
	if err := g.buildCore(); err != nil {
		return nil, err
	}
	for _, p := range g.plugins {
		if in, ok := p.(Initializer); ok {
			if err := in.Init(g); err != nil {
				return nil, fmt.Errorf("polaris: plugin %q: %w", p.ID(), err)
			}
		}
	}
	g.collectListeners()
	return g, nil
}

func (g *Graph) defaults() {
	cfg := g.config
	g.clock = cfg.Clock
	if g.clock == nil {
		g.clock = clock.System{}
	}
	g.logger = cfg.Logger
	if g.logger == nil {
		g.logger = slog.Default()
	}
	g.cache = cfg.Cache
	if g.cache == nil {
		g.cache = cache.NewMemory(g.clock)
	}
	g.rateStore = cfg.RateStore
	if g.rateStore == nil {
		g.rateStore = ratelimit.NewCacheStore(g.cache, g.clock)
	}
	g.metrics = cfg.Metrics
	if g.metrics == nil {
		g.metrics = metrics.NewLog(g.logger)
	}
	ports := g.pluginPorts()
	g.mailer = cfg.Mailer
	if g.mailer == nil {
		g.mailer = ports.Mailer
	}
	if g.mailer == nil {
		g.mailer = notify.NewLogMailer(g.logger)
	}
	g.sms = cfg.SMS
	if g.sms == nil {
		g.sms = ports.SMS
	}
	if g.sms == nil {
		g.sms = notify.NewLogSMS(g.logger)
	}
	g.breaches = cfg.Breaches
	if g.breaches == nil {
		g.breaches = ports.Breaches
	}
	if g.breaches == nil {
		if cfg.Auth.Password.BreachCheck {
			g.breaches = &security.HIBP{Logger: g.logger}
		} else {
			g.breaches = security.NoBreachCheck{}
		}
	}
	g.events = cfg.Events
	if g.events == nil {
		g.bus = &event.Bus{}
		g.events = g.bus
	}
	g.committer = committerOf(g.db)
}

// pluginPorts merges the ports plugins serve: the first plugin (registration order) providing a
// port wins.
func (g *Graph) pluginPorts() Ports {
	var out Ports
	for _, p := range g.plugins {
		pp, ok := p.(PortsProvider)
		if !ok {
			continue
		}
		got := pp.Ports()
		if out.Mailer == nil {
			out.Mailer = got.Mailer
		}
		if out.SMS == nil {
			out.SMS = got.SMS
		}
		if out.Breaches == nil {
			out.Breaches = got.Breaches
		}
	}
	return out
}

func (g *Graph) registerPlugins() error {
	var errs []error
	for _, p := range g.config.Plugins {
		if p == nil || p.ID() == "" {
			errs = append(errs, errors.New("polaris: a plugin is nil or has an empty ID"))
			continue
		}
		if _, dup := g.byID[p.ID()]; dup {
			errs = append(errs, fmt.Errorf("polaris: plugin %q is registered twice", p.ID()))
			continue
		}
		g.byID[p.ID()] = p
		g.plugins = append(g.plugins, p)
	}
	return errors.Join(errs...)
}

func (g *Graph) buildCore() error {
	var err error
	// Schema: core + plugins.
	var pluginModels [][]schema.Model
	for _, p := range g.plugins {
		if sp, ok := p.(SchemaProvider); ok {
			pluginModels = append(pluginModels, sp.Schema())
		}
	}
	if g.schema, err = schema.Merge(schema.Core(), pluginModels...); err != nil {
		return fmt.Errorf("polaris: %w", err)
	}

	// Manifest: core first, then each plugin's routes.
	core, err := fs.Sub(apispec.API, "api/core")
	if err != nil {
		return err
	}
	dirs := []fs.FS{core}
	for _, p := range g.plugins {
		if mp, ok := p.(ManifestProvider); ok && mp.Manifest() != nil {
			dirs = append(dirs, mp.Manifest())
		}
	}
	if g.manifest, err = manifest.Load(dirs...); err != nil {
		return fmt.Errorf("polaris: %w", err)
	}

	g.repos = repository.New(g.db)
	secrets := g.config.Secrets
	if g.pepper, err = security.NewPepper(secrets.AppKey); err != nil {
		return fmt.Errorf("polaris: APP_KEY: %w", err)
	}
	if g.encrypter, err = security.NewXChaCha20Poly1305(secrets.AppKey); err != nil {
		return fmt.Errorf("polaris: APP_KEY: %w", err)
	}
	g.hasher = g.config.Hasher
	if g.hasher == nil {
		g.hasher = security.Argon2id{}
	}

	if err := g.buildTokens(); err != nil {
		return err
	}
	if err := g.buildAuthz(); err != nil {
		return err
	}
	return g.buildServices()
}

func (g *Graph) buildTokens() error {
	s, a := g.config.Secrets, g.auth
	codecCfg := token.Config{
		Algorithm:  token.Algorithm(a.AccessToken.Signer),
		PublicKey:  s.JWTPublicKey,
		PrivateKey: s.JWTPrivateKey,
		KeyID:      s.KeyID(),
		Issuer:     a.Issuer,
		Audience:   a.Audience,
		TTL:        a.AccessToken.TTL,
		Clock:      g.clock,
	}
	if s.JWTPreviousPublicKey != "" {
		codecCfg.PreviousPublicKey, codecCfg.PreviousKeyID = s.JWTPreviousPublicKey, s.PreviousKeyID()
	}
	var err error
	if g.tokens, err = token.New(codecCfg); err != nil {
		return fmt.Errorf("polaris: AUTH_JWT_* keys: %w", err)
	}
	keys := []token.PublicKey{{KeyID: s.KeyID(), PEM: s.JWTPublicKey}}
	if s.JWTPreviousPublicKey != "" {
		keys = append(keys, token.PublicKey{KeyID: s.PreviousKeyID(), PEM: s.JWTPreviousPublicKey})
	}
	if g.jwks, err = token.NewJWKSet(codecCfg.Algorithm, keys...); err != nil {
		return fmt.Errorf("polaris: JWKS: %w", err)
	}
	if g.tickets, err = session.NewMFATickets(codecCfg, a.MFA.LoginTokenTTL); err != nil {
		return fmt.Errorf("polaris: MFA tickets: %w", err)
	}
	g.denylist = session.NewDenylist(g.cache, g.clock, a.AccessToken.TTL)
	return nil
}

func (g *Graph) buildAuthz() error {
	var contributions []map[string]string
	if len(g.config.Permissions) > 0 {
		contributions = append(contributions, g.config.Permissions)
	}
	for _, p := range g.plugins {
		if pp, ok := p.(PermissionProvider); ok {
			contributions = append(contributions, pp.Permissions())
		}
	}
	catalog, err := authz.NewCatalog(contributions...).WithRoleGrants(g.config.RolePermissions)
	if err != nil {
		return fmt.Errorf("polaris: Config.RolePermissions: %w", err)
	}
	g.catalog = catalog
	g.resolver = authz.NewResolver(g.repos)
	g.gate = authz.NewGate(g.resolver)
	g.principals = authz.NewPrincipals(g.repos, g.resolver, g.auth.AccessToken.EmbedScope)
	g.escalation = authz.NewEscalationGuard(g.repos)
	return nil
}

func (g *Graph) buildServices() error {
	var err error
	if g.sessions, err = session.New(session.Config{
		DB: g.db, Pepper: g.pepper, Access: g.tokens, Principals: g.principals, Denylist: g.denylist,
		Auth: g.auth, Clock: g.clock, Events: g.events, Claims: g.config.Hooks.claims(),
	}); err != nil {
		return fmt.Errorf("polaris: sessions: %w", err)
	}

	totp, err := mfa.NewTOTP(g.auth.OTP.TOTP, g.clock)
	if err != nil {
		return fmt.Errorf("polaris: TOTP: %w", err)
	}
	var factorTypes []mfa.FactorType
	for _, p := range g.plugins {
		if fp, ok := p.(MFAFactorTypeProvider); ok {
			factorTypes = append(factorTypes, fp.MFAFactorTypes()...)
		}
	}
	if g.mfa, err = mfa.New(mfa.Config{
		DB: g.db, Pepper: g.pepper, Encrypter: g.encrypter, TOTP: totp, SMS: g.sms, Mailer: g.mailer,
		Cache: g.cache, Sessions: g.sessions, Tickets: g.tickets, Principals: g.principals,
		FactorTypes: factorTypes, Auth: g.auth, Clock: g.clock, Events: g.events,
	}); err != nil {
		return fmt.Errorf("polaris: MFA: %w", err)
	}

	if g.identity, err = identity.New(identity.Config{
		DB: g.db, Hasher: g.hasher, Pepper: g.pepper, Sessions: g.sessions, MFA: g.mfa,
		Tickets: g.tickets, Authority: g.resolver, Auth: g.auth, Breaches: g.breaches,
		Clock: g.clock, Events: g.events,
		OnUserCreated: g.config.Hooks.onUserCreated(), OnUserDeleted: g.config.Hooks.OnUserDeleted,
		OnEmailProven: g.eraseAccess,
	}); err != nil {
		return fmt.Errorf("polaris: identity: %w", err)
	}
	if g.orgs, err = orgs.New(orgs.Config{
		DB: g.db, Sessions: g.sessions, Pepper: g.pepper, Clock: g.clock, Events: g.events, Catalog: g.catalog,
	}); err != nil {
		return fmt.Errorf("polaris: organizations: %w", err)
	}
	g.core = &services.Services{
		Identity: g.identity, Sessions: g.sessions, MFA: g.mfa, Orgs: g.orgs, Tickets: g.tickets,
		Denylist: g.denylist, Catalog: g.catalog, Resolver: g.resolver, Gate: g.gate,
		Principals: g.principals, Escalation: g.escalation, Pepper: g.pepper,
	}
	return nil
}

// eraseAccess runs every AccessEraser plugin for a mailbox's first proof (identity.ProveEmail).
func (g *Graph) eraseAccess(ctx context.Context, userID string) error {
	for _, p := range g.plugins {
		if e, ok := p.(AccessEraser); ok {
			if err := e.EraseAccess(ctx, userID); err != nil {
				return fmt.Errorf("plugin %q: %w", p.ID(), err)
			}
		}
	}
	return nil
}

func (g *Graph) collectListeners() {
	// Listeners that write to the store run inside the transaction that raised the event; the
	// ones whose effect leaves the database wait for its commit (Deferred).
	g.listeners = []event.Listener{
		observe.AuditLog(g.repos.AuditLog, g.clock, g.logger),
		g.Deferred(observe.Mail(g.mailer, g.repos.Users, g.logger)),
		g.Deferred(observe.Metrics(g.metrics)),
	}
	for _, p := range g.plugins {
		if lp, ok := p.(ListenerProvider); ok {
			g.listeners = append(g.listeners, lp.Listeners(g)...)
		}
	}
	g.listeners = append(g.listeners, g.config.TxListeners...)
	for _, l := range g.config.Listeners {
		g.listeners = append(g.listeners, g.Deferred(l))
	}
	if g.bus != nil {
		g.bus.Subscribe(g.listeners...)
	}
}

// Read-only accessors: the plugin SDK's view of the services New built. Every service is safe for
// concurrent use.

// Config returns the host's configuration as given to New.
func (g *Graph) Config() Config { return g.config }

// Auth returns the validated auth configuration.
func (g *Graph) Auth() config.Auth { return g.auth }

// Clock returns the clock every service reads.
func (g *Graph) Clock() clock.Clock { return g.clock }

// Logger returns the logger.
func (g *Graph) Logger() *slog.Logger { return g.logger }

// Events returns the event dispatcher.
func (g *Graph) Events() event.Dispatcher { return g.events }

// Cache returns the cache.
func (g *Graph) Cache() cache.Cache { return g.cache }

// Metrics returns the metrics sink.
func (g *Graph) Metrics() metrics.Metrics { return g.metrics }

// Mailer returns the mail port (the host's, a plugin's or the logging default).
func (g *Graph) Mailer() notify.Mailer { return g.mailer }

// SMS returns the SMS port (the host's, a plugin's or the logging default).
func (g *Graph) SMS() notify.SMSSender { return g.sms }

// DB returns the store adapter.
func (g *Graph) DB() store.Adapter { return g.db }

// Schema returns core's and the plugins' tables.
func (g *Graph) Schema() []schema.Model { return slices.Clone(g.schema) }

// Repos returns the core repositories over DB.
func (g *Graph) Repos() *repository.Repos { return g.repos }

// Manifest returns the loaded route manifest (core and plugins).
func (g *Graph) Manifest() *manifest.Manifest { return g.manifest }

// Encrypter returns the authenticated cipher derived from APP_KEY.
func (g *Graph) Encrypter() security.Encrypter { return g.encrypter }

// Hasher returns the password hasher.
func (g *Graph) Hasher() security.PasswordHasher { return g.hasher }

// Breaches returns the breached-password check.
func (g *Graph) Breaches() security.BreachedPasswordCheck { return g.breaches }

// Tokens returns the access-token codec.
func (g *Graph) Tokens() *token.Codec { return g.tokens }

// JWKS returns the published verification keys.
func (g *Graph) JWKS() token.JWKSet { return g.jwks }

// RateStore returns the rate-limit store.
func (g *Graph) RateStore() ratelimit.Store { return g.rateStore }
