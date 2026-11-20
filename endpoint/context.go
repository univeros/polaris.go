package endpoint

import (
	"context"

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
)

// WithToken records the verified bearer token (the principal) of the request.
func WithToken(ctx context.Context, t *token.Token) context.Context {
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

// WithAuthority records the database-resolved authority the authorization step computed. Its type
// belongs to the authz package; endpoints read it through authz.
func WithAuthority(ctx context.Context, a any) context.Context {
	return context.WithValue(ctx, keyAuthority, a)
}

// Authority is the value recorded by WithAuthority, nil when none.
func Authority(ctx context.Context) any { return ctx.Value(keyAuthority) }

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
