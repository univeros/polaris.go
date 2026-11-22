package admin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.admin.*.
const ID = "admin"

// Tag marks an admin route in a manifest: on a route carrying it (declared auth: public), the
// admin middleware resolves the operator before the endpoint runs.
const Tag = "admin"

// Impersonation token claims and method.
const (
	ClaimImpersonatedBy   = "impersonated_by"   // the operator's id
	ClaimImpersonatorType = "impersonator_type" // TypeUser or TypeAPIKey
	AMRImpersonation      = "impersonation"
)

// Config configures the plugin. It has no options yet.
type Config struct{}

// Plugin is the admin plugin. Its services exist once polaris.New has run.
type Plugin struct {
	g      *wiring.Graph
	audit  *audit.Plugin
	grants *Grants
	keys   *Keys
}

// New returns the plugin. It needs the audit plugin registered too (any order).
func New(Config) *Plugin { return &Plugin{} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_admin_grant and polaris_admin_key.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (declared in internal/apispec/api/admin).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/admin")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// AuditNames adds the admin.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string { return auditNames }

// Init builds the grant and key services; it fails when the audit plugin is not registered.
func (p *Plugin) Init(g *wiring.Graph) error {
	if p.audit = audit.Of(g); p.audit == nil {
		return errors.New(`admin: the audit plugin is required (every admin action is recorded through it): add audit.New(audit.Config{}) to Config.Plugins`)
	}
	p.g = g
	p.grants = &Grants{db: g.DB(), clock: g.Clock()}
	p.keys = &Keys{db: g.DB(), pepper: g.Pepper(), clock: g.Clock()}
	return nil
}

// Endpoints serves the /admin routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Middleware resolves the operator on every route tagged "admin" (see Operator and Authorize).
func (p *Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{p.middleware}
}

// Grants is the grant service (the admin:grant command's work).
func (p *Plugin) Grants() *Grants { return p.grants }

// Keys is the operator API key service (the admin:key command's work).
func (p *Plugin) Keys() *Keys { return p.keys }

// Of returns the admin plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if rt := endpoint.Route(ctx); rt == nil || !slices.Contains(rt.Tags, Tag) {
			next.ServeHTTP(w, r)
			return
		}
		res, err := p.Resolve(ctx, bearerOf(r), endpoint.Client(ctx).IP)
		if err != nil {
			p.g.Logger().ErrorContext(ctx, "admin: operator resolution failed", "error", err)
			endpoint.Write(w, serverError())
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxKey{}, res)))
	})
}

// bearerOf is the credential of an "Authorization: Bearer" header, "" when there is none.
func bearerOf(r *http.Request) string {
	bearer, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found {
		return ""
	}
	return bearer
}

// OperatorOf resolves the operator of any request (its bearer and client address), for code
// that runs outside the admin routes, where the middleware has not resolved one: ok is false for
// nobody and for an impersonation token; err is only a failing store.
func (p *Plugin) OperatorOf(r *http.Request) (Principal, bool, error) {
	ip := endpoint.Client(r.Context()).IP
	if ip == "" {
		ip = r.RemoteAddr
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}
	}
	res, err := p.Resolve(r.Context(), bearerOf(r), ip)
	if err != nil || res.Principal == nil {
		return Principal{}, false, err
	}
	return *res.Principal, true, nil
}

// IsOperator reports whether a raw credential (an admin user's access token or a "pak_" key) is an
// operator's: false for an impersonation token or nobody. No client address is known, so a key
// with an IP allowlist is refused.
func (p *Plugin) IsOperator(ctx context.Context, credential string) (bool, error) {
	res, err := p.Resolve(ctx, credential, "")
	return res.Principal != nil, err
}

func serverError() endpoint.Result {
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// Resolve tells who a credential is, from the client address ip ("" when unknown): a "pak_" key
// (hash, expiry, allowlist), or a Polaris access token whose user is not disabled and holds a
// live grant or core's superadmin role (an owner on the instance). An impersonation token
// resolves to nobody, marked Impersonated. An unknown, expired or forged credential is nobody;
// err is only a failing store.
func (p *Plugin) Resolve(ctx context.Context, bearer, ip string) (Resolution, error) {
	if bearer == "" {
		return Resolution{}, nil
	}
	if strings.HasPrefix(bearer, KeyPrefix) {
		k, ok, err := p.keys.Authenticate(ctx, bearer, ip)
		if !ok || err != nil {
			return Resolution{}, err
		}
		return Resolution{Principal: &Principal{ID: k.ID, Type: TypeAPIKey, Role: k.Role, Scope: k.Scope}}, nil
	}
	tok, err := p.g.Tokens().Parse(bearer)
	if err != nil {
		return Resolution{}, nil
	}
	if tok.Claim(ClaimImpersonatedBy) != nil {
		return Resolution{Impersonated: true}, nil
	}
	userID := tok.Subject()
	if userID == "" {
		return Resolution{}, nil
	}
	if p.g.Auth().AccessToken.Denylist {
		if revoked, err := p.g.Denylist().IsRevoked(ctx, userID, tok.IssuedAt()); err != nil || revoked {
			return Resolution{}, err
		}
	}
	user, err := p.g.Repos().Users.Get(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && user.Status == model.UserStatusDisabled) {
		return Resolution{}, nil
	}
	if err != nil {
		return Resolution{}, fmt.Errorf("admin: resolve: %w", err)
	}
	grant, ok, err := p.grants.For(ctx, userID)
	if err != nil {
		return Resolution{}, err
	}
	if ok {
		return Resolution{Principal: &Principal{ID: userID, Type: TypeUser, Role: grant.Role, Scope: grant.Scope}}, nil
	}
	authority, err := p.g.Resolver().Resolve(ctx, userID, "")
	if err != nil || !authority.IsSuperadmin() {
		return Resolution{}, err
	}
	return Resolution{Principal: &Principal{ID: userID, Type: TypeUser, Role: RoleOwner, Scope: ScopeInstance}}, nil
}
