// Package wiring builds every Polaris service from a Config, explicitly and once: the Go form of
// upstream's Polaris\Wiring\Graph, without a container. Hosts use the root package (polaris.New);
// plugins receive the *Graph and read the services they need from its fields.
package wiring

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/metrics"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/notify"
	"github.com/univeros/polaris-go/observe"
	"github.com/univeros/polaris-go/orgs"
	"github.com/univeros/polaris-go/ratelimit"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/session"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/upstream"
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
	// Hasher hashes passwords; default: security.Argon2id{} (PHP's password_hash defaults). Tests may
	// pass cheaper Argon2id parameters; hashes stay verifiable by any parameters.
	Hasher security.PasswordHasher
	Cache  cache.Cache // default: in-memory (not shared across replicas)
	// RateStore counts rate-limit hits; default: on Cache.
	RateStore ratelimit.Store
	Metrics   metrics.Metrics // default: metrics.NewLog(Logger)
	Clock     clock.Clock     // default: clock.System
	Logger    *slog.Logger    // default: slog.Default()
	// Events receives every domain event. Default: an in-process event.Bus with core's and the
	// plugins' listeners already subscribed. A host passing its own dispatcher subscribes
	// Graph.Listeners itself.
	Events event.Dispatcher

	// Permissions are the host's own permission keys and descriptions ("billing.refund": "Refund an
	// invoice"), joined to the catalog so roles, API keys, OAuth scopes and agent capabilities can
	// carry them and Protect can require them. Migrate seeds them.
	Permissions map[string]string

	// PathPrefix is where the Polaris routes are mounted ("/api"); default "/".
	PathPrefix string
	// MaxBodyBytes bounds the request body of every Polaris route (a larger one is answered 413);
	// default pipeline.DefaultMaxBodyBytes (1 MiB), negative means no limit.
	MaxBodyBytes int64
	// Plugins extend Polaris; see Plugin.
	Plugins []Plugin
}

// Graph holds every service, built once by New. Fields are read-only after New returns; services
// are safe for concurrent use.
type Graph struct {
	Config  Config
	Auth    config.Auth
	Clock   clock.Clock
	Logger  *slog.Logger
	Events  event.Dispatcher
	Cache   cache.Cache
	Metrics metrics.Metrics
	Mailer  notify.Mailer
	SMS     notify.SMSSender

	DB       store.Adapter
	Schema   []schema.Model // core + plugin tables
	Repos    *repository.Repos
	Manifest *manifest.Manifest

	Pepper    *security.Pepper
	Encrypter security.Encrypter
	Hasher    security.PasswordHasher
	Breaches  security.BreachedPasswordCheck

	Tokens   *token.Codec // access tokens
	JWKS     token.JWKSet
	Tickets  *session.MFATickets
	Denylist *session.Denylist

	Catalog    authz.Catalog
	Resolver   *authz.Resolver
	Gate       *authz.Gate
	Principals *authz.Principals
	Escalation *authz.EscalationGuard

	Sessions *session.Service
	MFA      *mfa.Service
	Identity *identity.Service
	Orgs     *orgs.Service

	RateStore ratelimit.Store

	plugins   []Plugin
	byID      map[string]Plugin
	listeners []event.Listener
	bus       *event.Bus // the default dispatcher, nil when the host passed its own
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
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	g := &Graph{Config: cfg, Auth: cfg.Auth, DB: cfg.DB, byID: map[string]Plugin{}}
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
	cfg := g.Config
	g.Clock = cfg.Clock
	if g.Clock == nil {
		g.Clock = clock.System{}
	}
	g.Logger = cfg.Logger
	if g.Logger == nil {
		g.Logger = slog.Default()
	}
	g.Cache = cfg.Cache
	if g.Cache == nil {
		g.Cache = cache.NewMemory(g.Clock)
	}
	g.RateStore = cfg.RateStore
	if g.RateStore == nil {
		g.RateStore = ratelimit.NewCacheStore(g.Cache, g.Clock)
	}
	g.Metrics = cfg.Metrics
	if g.Metrics == nil {
		g.Metrics = metrics.NewLog(g.Logger)
	}
	ports := g.pluginPorts()
	g.Mailer = cfg.Mailer
	if g.Mailer == nil {
		g.Mailer = ports.Mailer
	}
	if g.Mailer == nil {
		g.Mailer = notify.NewLogMailer(g.Logger)
	}
	g.SMS = cfg.SMS
	if g.SMS == nil {
		g.SMS = ports.SMS
	}
	if g.SMS == nil {
		g.SMS = notify.NewLogSMS(g.Logger)
	}
	g.Breaches = cfg.Breaches
	if g.Breaches == nil {
		g.Breaches = ports.Breaches
	}
	if g.Breaches == nil {
		if cfg.Auth.Password.BreachCheck {
			g.Breaches = &security.HIBP{Logger: g.Logger}
		} else {
			g.Breaches = security.NoBreachCheck{}
		}
	}
	g.Events = cfg.Events
	if g.Events == nil {
		g.bus = &event.Bus{}
		g.Events = g.bus
	}
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
	for _, p := range g.Config.Plugins {
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
	if g.Schema, err = schema.Merge(schema.Core(), pluginModels...); err != nil {
		return fmt.Errorf("polaris: %w", err)
	}

	// Manifest: core first, then each plugin's routes.
	core, err := fs.Sub(upstream.API, "api/core")
	if err != nil {
		return err
	}
	dirs := []fs.FS{core}
	for _, p := range g.plugins {
		if mp, ok := p.(ManifestProvider); ok && mp.Manifest() != nil {
			dirs = append(dirs, mp.Manifest())
		}
	}
	if g.Manifest, err = manifest.Load(dirs...); err != nil {
		return fmt.Errorf("polaris: %w", err)
	}

	g.Repos = repository.New(g.DB)
	secrets := g.Config.Secrets
	if g.Pepper, err = security.NewPepper(secrets.AppKey); err != nil {
		return fmt.Errorf("polaris: APP_KEY: %w", err)
	}
	if g.Encrypter, err = security.NewXChaCha20Poly1305(secrets.AppKey); err != nil {
		return fmt.Errorf("polaris: APP_KEY: %w", err)
	}
	g.Hasher = g.Config.Hasher
	if g.Hasher == nil {
		g.Hasher = security.Argon2id{}
	}

	if err := g.buildTokens(); err != nil {
		return err
	}
	g.buildAuthz()
	return g.buildServices()
}

func (g *Graph) buildTokens() error {
	s, a := g.Config.Secrets, g.Auth
	codecCfg := token.Config{
		Algorithm:  token.Algorithm(a.AccessToken.Signer),
		PublicKey:  s.JWTPublicKey,
		PrivateKey: s.JWTPrivateKey,
		KeyID:      s.KeyID(),
		Issuer:     a.Issuer,
		Audience:   a.Audience,
		TTL:        a.AccessToken.TTL,
		Clock:      g.Clock,
	}
	if s.JWTPreviousPublicKey != "" {
		codecCfg.PreviousPublicKey, codecCfg.PreviousKeyID = s.JWTPreviousPublicKey, s.PreviousKeyID()
	}
	var err error
	if g.Tokens, err = token.New(codecCfg); err != nil {
		return fmt.Errorf("polaris: AUTH_JWT_* keys: %w", err)
	}
	keys := []token.PublicKey{{KeyID: s.KeyID(), PEM: s.JWTPublicKey}}
	if s.JWTPreviousPublicKey != "" {
		keys = append(keys, token.PublicKey{KeyID: s.PreviousKeyID(), PEM: s.JWTPreviousPublicKey})
	}
	if g.JWKS, err = token.NewJWKSet(codecCfg.Algorithm, keys...); err != nil {
		return fmt.Errorf("polaris: JWKS: %w", err)
	}
	if g.Tickets, err = session.NewMFATickets(codecCfg, a.MFA.LoginTokenTTL); err != nil {
		return fmt.Errorf("polaris: MFA tickets: %w", err)
	}
	g.Denylist = session.NewDenylist(g.Cache, g.Clock, a.AccessToken.TTL)
	return nil
}

func (g *Graph) buildAuthz() {
	var contributions []map[string]string
	if len(g.Config.Permissions) > 0 {
		contributions = append(contributions, g.Config.Permissions)
	}
	for _, p := range g.plugins {
		if pp, ok := p.(PermissionProvider); ok {
			contributions = append(contributions, pp.Permissions())
		}
	}
	g.Catalog = authz.NewCatalog(contributions...)
	g.Resolver = authz.NewResolver(g.Repos)
	g.Gate = authz.NewGate(g.Resolver)
	g.Principals = authz.NewPrincipals(g.Repos, g.Resolver, g.Auth.AccessToken.EmbedScope)
	g.Escalation = authz.NewEscalationGuard(g.Repos)
}

func (g *Graph) buildServices() error {
	var err error
	if g.Sessions, err = session.New(session.Config{
		DB: g.DB, Pepper: g.Pepper, Access: g.Tokens, Principals: g.Principals, Denylist: g.Denylist,
		Auth: g.Auth, Clock: g.Clock, Events: g.Events,
	}); err != nil {
		return fmt.Errorf("polaris: sessions: %w", err)
	}

	totp, err := mfa.NewTOTP(g.Auth.OTP.TOTP, g.Clock)
	if err != nil {
		return fmt.Errorf("polaris: TOTP: %w", err)
	}
	var factorTypes []mfa.FactorType
	for _, p := range g.plugins {
		if fp, ok := p.(MFAFactorTypeProvider); ok {
			factorTypes = append(factorTypes, fp.MFAFactorTypes()...)
		}
	}
	if g.MFA, err = mfa.New(mfa.Config{
		DB: g.DB, Pepper: g.Pepper, Encrypter: g.Encrypter, TOTP: totp, SMS: g.SMS, Mailer: g.Mailer,
		Cache: g.Cache, Sessions: g.Sessions, Tickets: g.Tickets, Principals: g.Principals,
		FactorTypes: factorTypes, Auth: g.Auth, Clock: g.Clock, Events: g.Events,
	}); err != nil {
		return fmt.Errorf("polaris: MFA: %w", err)
	}

	if g.Identity, err = identity.New(identity.Config{
		DB: g.DB, Hasher: g.Hasher, Pepper: g.Pepper, Sessions: g.Sessions, MFA: g.MFA,
		Tickets: g.Tickets, Authority: g.Resolver, Auth: g.Auth, Breaches: g.Breaches,
		Clock: g.Clock, Events: g.Events,
	}); err != nil {
		return fmt.Errorf("polaris: identity: %w", err)
	}
	if g.Orgs, err = orgs.New(orgs.Config{
		DB: g.DB, Sessions: g.Sessions, Pepper: g.Pepper, Clock: g.Clock, Events: g.Events,
	}); err != nil {
		return fmt.Errorf("polaris: organizations: %w", err)
	}
	return nil
}

func (g *Graph) collectListeners() {
	g.listeners = []event.Listener{
		observe.AuditLog(g.Repos.AuditLog, g.Clock, g.Logger),
		notify.Listener(g.Mailer, g.Repos.Users, g.Logger),
		observe.Metrics(g.Metrics),
	}
	for _, p := range g.plugins {
		if lp, ok := p.(ListenerProvider); ok {
			g.listeners = append(g.listeners, lp.Listeners(g)...)
		}
	}
	if g.bus != nil {
		g.bus.Subscribe(g.listeners...)
	}
}
