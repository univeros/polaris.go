package endpoint

import (
	"context"
	"sync"

	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/token"
)

// Request-scoped values the pipeline sets before an endpoint runs (upstream's request attributes).
type ctxKey int

const (
	keyToken ctxKey = iota
	keyMFATicket
	keyAuthority
	keyClient
	keyRoute
	keyObserved
)

// Observed is what the pipeline resolved for a request, for middleware wrapped outside it
// (telemetry, access logs) that cannot see the contexts the pipeline derives. Install one with
// WithObserved before calling the pipeline and read it after it returns: WithRoute and WithToken
// record into it. It is written on the request's goroutine; read it only once ServeHTTP returned.
type Observed struct {
	Route *manifest.Route // nil when no route matched (or outside Handler, e.g. Protect)
	Token *token.Token    // nil when unauthenticated
}

// WithObserved returns ctx carrying o; the pipeline fills it as it routes and authenticates.
func WithObserved(ctx context.Context, o *Observed) context.Context {
	return context.WithValue(ctx, keyObserved, o)
}

func observed(ctx context.Context) *Observed {
	o, _ := ctx.Value(keyObserved).(*Observed)
	return o
}

// WithToken records the verified bearer token (the principal) of the request.
func WithToken(ctx context.Context, t *token.Token) context.Context {
	if o := observed(ctx); o != nil {
		o.Token = t
	}
	return context.WithValue(ctx, keyToken, t)
}

// Token is the request's verified bearer token, nil when unauthenticated.
func Token(ctx context.Context) *token.Token {
	t, _ := ctx.Value(keyToken).(*token.Token)
	return t
}

// WithMFATicket records the user id of a verified login_mfa ticket.
func WithMFATicket(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, keyMFATicket, userID)
}

// MFATicket is the user id of the request's login_mfa ticket; ok is false without one.
func MFATicket(ctx context.Context) (userID string, ok bool) {
	userID, ok = ctx.Value(keyMFATicket).(string)
	return userID, ok
}

// authorityFunc yields the request's authority, resolving it at most once.
type authorityFunc func() (any, error)

// WithAuthority records the database-resolved authority the authorization step computed. Its type
// belongs to the authz package; endpoints read it through authz.
func WithAuthority(ctx context.Context, a any) context.Context {
	return context.WithValue(ctx, keyAuthority, authorityFunc(func() (any, error) { return a, nil }))
}

// WithLazyAuthority records how to resolve the request's authority without resolving it: resolve
// runs on the first Authority / ResolveAuthority call, at most once per request (its result, error
// included, is kept). Protect without permissions uses it, so a handler that never asks costs no
// query.
func WithLazyAuthority(ctx context.Context, resolve func() (any, error)) context.Context {
	return context.WithValue(ctx, keyAuthority, authorityFunc(sync.OnceValues(resolve)))
}

// ResolveAuthority is the request's authority, resolving a lazy one now; nil, nil when none was
// recorded.
func ResolveAuthority(ctx context.Context) (any, error) {
	f, ok := ctx.Value(keyAuthority).(authorityFunc)
	if !ok {
		return nil, nil
	}
	return f()
}

// Authority is the request's authority (ResolveAuthority), nil when none was recorded or a lazy
// resolution failed.
func Authority(ctx context.Context) any {
	a, err := ResolveAuthority(ctx)
	if err != nil {
		return nil
	}
	return a
}

// WithClient records the caller's IP and user agent.
func WithClient(ctx context.Context, c token.ClientContext) context.Context {
	return context.WithValue(ctx, keyClient, c)
}

// Client is the caller's IP and user agent (zero when unknown).
func Client(ctx context.Context) token.ClientContext {
	c, _ := ctx.Value(keyClient).(token.ClientContext)
	return c
}

// WithRoute records the matched route.
func WithRoute(ctx context.Context, r *manifest.Route) context.Context {
	if o := observed(ctx); o != nil {
		o.Route = r
	}
	return context.WithValue(ctx, keyRoute, r)
}

// Route is the matched route, nil outside the pipeline.
func Route(ctx context.Context) *manifest.Route {
	r, _ := ctx.Value(keyRoute).(*manifest.Route)
	return r
}

// ActorOrganization is the active organization claim of t, "" when none.
func ActorOrganization(t *token.Token) string {
	s, _ := t.Claim("org").(string)
	return s
}
