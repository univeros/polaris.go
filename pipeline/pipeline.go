// Package pipeline is the HTTP face of Polaris: it routes requests by the endpoint manifest and runs
// them through the contractual middleware order (docs/port/spec.md §4.3) to the registered
// endpoint:
//
//  1. route match (404 / 405 in core's envelope); the body is read, at most Options.MaxBodyBytes (413)
//  2. client context (IP, user agent)
//  3. per-IP rate limit of the route's rate_limit group
//  4. refresh cookie (cookie token delivery only)
//  5. MFA ticket authentication (auth: mfa_token)
//  6. bearer authentication (auth: bearer): the bearer resolvers first, then the JWT parse
//  7. plugin middleware, in registration order
//  8. step-up (step_up: true)
//  9. denylist (auth.access_token.denylist)
//  10. per-principal rate limit
//  11. authorization (requires_permissions through the Gate; delegated credentials)
//  12. the endpoint
//
// Handler serves every Polaris route; Protect guards a host's own routes with Polaris principals.
// The principal of a request is endpoint.Token(r.Context()); the authority the gate resolved is
// endpoint.Authority(r.Context()).
//
// The services the pipeline consumes are the small interfaces declared here (TokenParser,
// BearerResolver, MFATickets, StepUpVerifier, Denylist, Gate); the wiring layer adapts the domain
// services to them.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/ratelimit"
	"github.com/univeros/polaris-go/token"
)

// TokenParser verifies a bearer access token. *token.Codec satisfies it.
type TokenParser interface {
	Parse(raw string) (*token.Token, error)
}

// BearerResolver recognises a plugin's own credential (an API key, an OAuth access token, an agent
// JWT). It returns nil, nil when the request does not carry a credential of its kind, and an error
// when it does but the credential does not authenticate (revoked, expired, over its limit): the
// request is then answered 401 without asking the next resolver.
type BearerResolver interface {
	Resolve(r *http.Request) (*token.Token, error)
}

// MFATickets authenticates a login_mfa ticket (the bearer of an auth: mfa_token route) and returns
// the user id it was issued for. Any error answers 401.
type MFATickets interface {
	Authenticate(ctx context.Context, ticket string) (userID string, err error)
}

// StepUpVerifier reports whether the user has a confirmed MFA factor: only such users must step
// up on a step_up route.
type StepUpVerifier interface {
	HasConfirmedFactor(ctx context.Context, userID string) (bool, error)
}

// Denylist reports whether access tokens of userID issued at issuedAt were revoked by a later
// logout-everywhere.
type Denylist interface {
	Revoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error)
}

// Gate resolves a principal's database-backed authority, already intersected with what a
// delegated credential carries.
type Gate interface {
	Authority(ctx context.Context, tok *token.Token) (Authority, error)
}

// Authority is a resolved authority. It is recorded with endpoint.WithAuthority as returned, so
// endpoints can type-assert it back to the concrete type.
type Authority interface {
	Allows(permissions ...string) bool
}

// Options configures a Pipeline. Manifest, Endpoints, Auth and Tokens are required; the other
// services are required only when a route needs them.
type Options struct {
	// Manifest is every route served.
	Manifest *manifest.Manifest
	// PathPrefix is stripped from request paths before matching ("/api"); "" means "/".
	PathPrefix string
	// Endpoints maps each route name ("polaris.auth.login") to its endpoint. Every manifest route
	// must have one.
	Endpoints map[string]endpoint.Endpoint
	// Auth supplies rate limits, cookie delivery, refresh TTL, step-up max age and the denylist
	// switch. Start from config.Defaults.
	Auth config.Auth

	Tokens          TokenParser      // required
	BearerResolvers []BearerResolver // asked in order before Tokens
	MFATickets      MFATickets       // required when a route has auth: mfa_token
	StepUp          StepUpVerifier   // required when a route has step_up: true
	Denylist        Denylist         // required when Auth.AccessToken.Denylist is on
	Gate            Gate             // required when a route has requires_permissions, and by Protect with permissions

	// RateStore counts rate-limit hits; nil means an in-process store (not shared across replicas).
	RateStore ratelimit.Store
	// PluginMiddleware runs after bearer authentication, before step-up, in order.
	PluginMiddleware []func(http.Handler) http.Handler
	// Clock is the time source for step-up and Retry-After; nil means clock.System.
	Clock clock.Clock
	// Logger receives the errors behind 500 responses; nil means slog.Default.
	Logger *slog.Logger
	// MaxBodyBytes bounds the request body of every Polaris route (Protect leaves a host route's
	// body alone): a larger body is answered 413 before any middleware reads it. 0 means
	// DefaultMaxBodyBytes (1 MiB); negative means no limit.
	MaxBodyBytes int64
}

// Pipeline is the Polaris request pipeline. It is immutable and safe for concurrent use.
type Pipeline struct {
	opts    Options
	router  *router
	rates   ratelimit.Store
	clock   clock.Clock
	log     *slog.Logger
	handler http.Handler
}

// New validates opts and builds the pipeline. It fails listing every problem at once: a missing
// service, an invalid Auth, and every manifest route without an endpoint.
func New(opts Options) (*Pipeline, error) {
	if err := validate(opts); err != nil {
		return nil, err
	}
	p := &Pipeline{opts: opts, router: newRouter(opts.Manifest, opts.PathPrefix), rates: opts.RateStore, clock: opts.Clock, log: opts.Logger}
	if p.clock == nil {
		p.clock = clock.System{}
	}
	if p.rates == nil {
		p.rates = ratelimit.NewCacheStore(cache.NewMemory(p.clock), p.clock)
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	p.handler = chain(http.HandlerFunc(p.dispatch), p.Middleware())
	return p, nil
}

func validate(o Options) error {
	var errs []error
	if o.Manifest == nil {
		return errors.New("pipeline: Options.Manifest is nil: load it with manifest.Load")
	}
	if err := o.Auth.Validate(); err != nil {
		errs = append(errs, fmt.Errorf("pipeline: Options.Auth: %w (start from config.Defaults)", err))
	}
	if o.Tokens == nil {
		errs = append(errs, errors.New("pipeline: Options.Tokens is nil: pass the token.Codec"))
	}
	if o.Auth.AccessToken.Denylist && o.Denylist == nil {
		errs = append(errs, errors.New("pipeline: Options.Denylist is nil but Auth.AccessToken.Denylist is on (AUTH_ACCESS_TOKEN_DENYLIST)"))
	}
	var missing []string
	var needTickets, needStepUp, needGate bool
	for _, rt := range o.Manifest.Routes() {
		if o.Endpoints[rt.Name] == nil {
			missing = append(missing, rt.Name+" ("+rt.Pattern()+")")
		}
		needTickets = needTickets || rt.Auth == manifest.AuthMfaToken
		needStepUp = needStepUp || rt.StepUp
		needGate = needGate || len(rt.RequiresPermissions) > 0
	}
	if needTickets && o.MFATickets == nil {
		errs = append(errs, errors.New("pipeline: Options.MFATickets is nil but a route has auth: mfa_token"))
	}
	if needStepUp && o.StepUp == nil {
		errs = append(errs, errors.New("pipeline: Options.StepUp is nil but a route has step_up: true"))
	}
	if needGate && o.Gate == nil {
		errs = append(errs, errors.New("pipeline: Options.Gate is nil but a route has requires_permissions"))
	}
	if len(missing) > 0 {
		errs = append(errs, fmt.Errorf("pipeline: no endpoint registered for %d route(s), add them to Options.Endpoints: %s", len(missing), strings.Join(missing, ", ")))
	}
	return errors.Join(errs...)
}

// Handler serves every manifest route through the whole stack.
func (p *Pipeline) Handler() http.Handler { return p.handler }

// Middleware returns the stack in order, outermost first, for hosts composing their own: wrap
// Endpoints with it (the first element outermost) to get Handler.
func (p *Pipeline) Middleware() []func(http.Handler) http.Handler {
	mw := []func(http.Handler) http.Handler{p.route, clientContext, p.ipRateLimit}
	if p.opts.Auth.Flows.TokenDelivery == config.DeliveryCookie {
		mw = append(mw, p.refreshCookie)
	}
	mw = append(mw, p.mfaTicket, p.bearer)
	mw = append(mw, p.opts.PluginMiddleware...)
	return append(mw, p.stepUp, p.denylist, p.principalRateLimit, p.authorize)
}

// Endpoints is the end of the stack: it runs the routed endpoint and writes its Result. Without
// the route middleware in front it routes the request itself.
func (p *Pipeline) Endpoints() http.Handler { return http.HandlerFunc(p.dispatch) }

// Protect guards a host route with Polaris principals: the bearer (resolvers, then the access
// token), the denylist and, when permissions are given, the Gate, answering core's 401 / 403
// envelope. next reads the principal with endpoint.Token and the authority with
// endpoint.Authority. Protect panics when permissions are given and Options.Gate is nil.
func (p *Pipeline) Protect(next http.Handler, permissions ...string) http.Handler {
	if len(permissions) > 0 && p.opts.Gate == nil {
		panic("pipeline: Protect with permissions needs Options.Gate")
	}
	required := append([]string(nil), permissions...)
	return chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.permit(w, r, required, next)
	}), append(append([]func(http.Handler) http.Handler{clientContext, p.authenticate}, p.opts.PluginMiddleware...), p.denylist))
}

// chain wraps h so that mw[0] runs first.
func chain(h http.Handler, mw []func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// fail answers 500 for an error of a consumed service, logging it.
func (p *Pipeline) fail(w http.ResponseWriter, r *http.Request, step string, err error) {
	p.log.ErrorContext(r.Context(), "polaris pipeline: "+step+" failed", "method", r.Method, "path", r.URL.Path, "error", err)
	endpoint.Write(w, endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request."))
}
