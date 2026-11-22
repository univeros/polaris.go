// Package apikeys is the API-keys plugin: keys owned by users and by
// organizations (pk_live_…, pk_test_…), each with a subset of its owner's permissions, an optional
// rate limit of its own, an expiry, rotation with a grace window and revocation. Presented as
// "Authorization: Bearer pk_…" or "x-api-key: pk_…", a key authenticates every Polaris route and
// every host route guarded by polaris.Protect as its owner, delegated: the gate intersects the
// owner's current permissions with the key's, so a key never does more than its owner may.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), apikeys.New(apikeys.Config{})},
//	})
//	mux.Handle("/api/", p.Protect(api, "invoices.read")) // polaris.Principal(ctx).Delegation()
//
// With the audit plugin registered, every creation, change, rotation and revocation is an
// api_keys.* audit event.
package apikeys

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.api-keys.*.
const ID = "api-keys"

// Environments: the key prefix pk_<environment>_.
const (
	EnvLive = "live"
	EnvTest = "test"
)

// Defaults.
const (
	DefaultRotationGrace = 24 * time.Hour
	DefaultMaxPerOwner   = 50
)

// dateAtom is RFC 3339 to the second with UTC written "+00:00" (not "Z"): the timestamp format
// the API emits and stored rows keep.
const dateAtom = "2006-01-02T15:04:05-07:00"

// Config configures the plugin; the zero value is the defaults.
type Config struct {
	// Environment is the prefix of keys created without one: EnvLive (default) or EnvTest.
	Environment string
	// RotationGrace is how long a rotated key's predecessor keeps answering; zero: 24 hours,
	// negative: it stops at once.
	RotationGrace time.Duration
	// MaxPerOwner bounds the live keys of a user or an organization; zero: 50.
	MaxPerOwner int
}

type settings struct {
	environment   string
	rotationGrace time.Duration
	maxPerOwner   int
}

func (c Config) settings() (settings, error) {
	s := settings{environment: c.Environment, rotationGrace: c.RotationGrace, maxPerOwner: c.MaxPerOwner}
	if s.environment == "" {
		s.environment = EnvLive
	}
	if s.environment != EnvLive && s.environment != EnvTest {
		return s, fmt.Errorf("apikeys: Config.Environment is %q, want %q or %q", c.Environment, EnvLive, EnvTest)
	}
	switch {
	case s.rotationGrace == 0:
		s.rotationGrace = DefaultRotationGrace
	case s.rotationGrace < 0:
		s.rotationGrace = 0
	}
	switch {
	case s.maxPerOwner == 0:
		s.maxPerOwner = DefaultMaxPerOwner
	case s.maxPerOwner < 0:
		return s, fmt.Errorf("apikeys: Config.MaxPerOwner is %d, want at least 1 (0 means %d)", c.MaxPerOwner, DefaultMaxPerOwner)
	}
	return s, nil
}

// Plugin is the API-keys plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg  Config
	keys *Keys
	g    *wiring.Graph
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_api_key.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (declared in internal/apispec/api/api-keys).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/api-keys")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// AuditNames adds the api_keys.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string {
	return map[string]string{
		AuditCreated: "An API key was created (owner, name, permissions, expiry)",
		AuditUpdated: "An API key was updated (what changed)",
		AuditRotated: "An API key was rotated: a new secret, the old one valid for the grace window (new key id)",
		AuditRevoked: "An API key was revoked",
	}
}

// Init builds the key service.
func (p *Plugin) Init(g *wiring.Graph) error {
	s, err := p.cfg.settings()
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, perm := range g.Catalog().Permissions() {
		known[perm.Key] = true
	}
	p.g = g
	p.keys = &Keys{db: g.DB(), pepper: g.Pepper(), permissions: known, settings: s, clock: g.Clock()}
	return nil
}

// Keys is the key service.
func (p *Plugin) Keys() *Keys { return p.keys }

// Endpoints serves the /api-keys routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// BearerResolvers authenticates pk_ secrets on every Polaris route and on Protect.
func (p *Plugin) BearerResolvers(*wiring.Graph) []pipeline.BearerResolver {
	return []pipeline.BearerResolver{resolver{p}}
}

// Middleware refuses step-up routes to keys and applies a key's own rate limit.
func (p *Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{p.middleware}
}

// EraseAccess implements wiring.AccessEraser: the keys minted before anyone proved the user's
// mailbox go with its first proof.
func (p *Plugin) EraseAccess(ctx context.Context, userID string) error {
	return p.keys.DeleteForUser(ctx, userID)
}

// Listeners erase the keys of an erased user or organization, and the organization keys a
// departing member acts for.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		var err error
		switch e := e.(type) {
		case event.UserDeleted:
			err = p.keys.DeleteForUser(ctx, e.UserID)
		case event.OrganizationDeleted:
			err = p.keys.DeleteForOrganization(ctx, e.OrganizationID)
		case event.MemberRemoved:
			err = p.keys.DeleteForMember(ctx, e.OrganizationID, e.UserID)
		default:
			return
		}
		if err != nil {
			p.g.Logger().ErrorContext(ctx, "apikeys: keys not erased", "event", e.EventName(), "reason", err.Error())
		}
	}}
}

// Of returns the api-keys plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// Kind classifies a refused operation; it names the problem type api-keys/<kind>.
type Kind string

// Kinds.
const (
	KindNotFound          Kind = "not_found"
	KindInvalidInput      Kind = "invalid_input"
	KindForbidden         Kind = "forbidden"
	KindTooMany           Kind = "too_many"
	KindPermissionNotHeld Kind = "permission_not_held"
)

// Error is a refused key operation; Detail is what the client may read.
type Error struct {
	Kind   Kind
	Detail string
}

func (e *Error) Error() string { return "apikeys: " + string(e.Kind) + ": " + e.Detail }

// Is matches the sentinels by kind: errors.Is(err, apikeys.ErrTooMany).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Kind == e.Kind && t.Detail == ""
}

// Sentinels for errors.Is.
var (
	ErrNotFound          error = &Error{Kind: KindNotFound}
	ErrInvalidInput      error = &Error{Kind: KindInvalidInput}
	ErrForbidden         error = &Error{Kind: KindForbidden}
	ErrTooMany           error = &Error{Kind: KindTooMany}
	ErrPermissionNotHeld error = &Error{Kind: KindPermissionNotHeld}
)

func invalid(detail string) error { return &Error{Kind: KindInvalidInput, Detail: detail} }

func asError(err error) (*Error, bool) {
	var e *Error
	return e, errors.As(err, &e)
}
