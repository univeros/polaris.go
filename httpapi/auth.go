package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/wiring"
)

// authEndpoints serves the account and session routes of upstream/api/core/auth (registration,
// verification, login, sessions, passwords, JWKS). The MFA routes, switch-org and invites-accept
// live with their areas.
func authEndpoints(g *wiring.Graph) map[string]endpoint.Endpoint {
	a := &authAPI{g: g}
	return map[string]endpoint.Endpoint{
		"polaris.auth.register":            endpoint.Func(a.register),
		"polaris.auth.email-verify":        endpoint.Func(a.verifyEmail),
		"polaris.auth.email-verify-resend": endpoint.Func(a.resendVerification),
		"polaris.auth.login":               endpoint.Func(a.login),
		"polaris.auth.me":                  endpoint.Func(a.me),
		"polaris.auth.logout":              endpoint.Func(a.logout),
		"polaris.auth.logout-all":          endpoint.Func(a.logoutAll),
		"polaris.auth.token-refresh":       endpoint.Func(a.refresh),
		"polaris.auth.sessions-list":       endpoint.Func(a.sessions),
		"polaris.auth.session-revoke":      endpoint.Func(a.revokeSession),
		"polaris.auth.password.forgot":     endpoint.Func(a.forgotPassword),
		"polaris.auth.password.reset":      endpoint.Func(a.resetPassword),
		"polaris.auth.password.change":     endpoint.Func(a.changePassword),
		"polaris.auth.jwks":                endpoint.Func(a.jwks),
	}
}

// authAPI holds the graph the auth endpoints read their services from.
type authAPI struct{ g *wiring.Graph }

// authDateAtom is PHP's DATE_ATOM: a UTC offset is written "+00:00", never "Z".
const authDateAtom = "2006-01-02T15:04:05-07:00"

// fail answers 500 for an error of a consumed service, logging it (decision 14).
func (a *authAPI) fail(ctx context.Context, op string, err error) endpoint.Result {
	a.g.Logger.ErrorContext(ctx, "polaris auth: "+op+" failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// authString reads key as upstream's (string) cast of a scalar does: strings as they are,
// numbers in their JSON form, true as "1"; anything else is "".
func authString(in *endpoint.Input, key string) string {
	switch v := in.Value(key).(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "1"
		}
	}
	return ""
}

// authTrim is PHP's trim(): only " \t\n\r\0\x0B" are stripped.
func authTrim(s string) string { return strings.Trim(s, " \t\n\r\x00\x0B") }

// authSubject is the caller's user id and the token's session id; ok is false without a
// principal or a subject.
func authSubject(ctx context.Context) (tok *token.Token, userID string, ok bool) {
	tok = endpoint.Token(ctx)
	if tok == nil || tok.Subject() == "" {
		return nil, "", false
	}
	return tok, tok.Subject(), true
}

// authSessionID is the sid claim of tok, "" when it has none.
func authSessionID(tok *token.Token) string {
	sid, _ := tok.Claim("sid").(string)
	return sid
}

func (a *authAPI) jwks(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if a.g.JWKSErr != nil {
		return a.fail(ctx, "jwks", a.g.JWKSErr)
	}
	return endpoint.JSON(http.StatusOK, a.g.JWKS)
}
