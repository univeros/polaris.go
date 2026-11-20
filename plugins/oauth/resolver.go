package oauth

import (
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

// Claims the resolver puts on a principal built from one of the provider's access tokens.
const (
	// AMR is the principal's amr: it came through an OAuth client.
	AMR = "oauth"
	// ClaimClientID names the client acting.
	ClaimClientID = "client_id"
	// ClaimScope is the token's scope, space-separated.
	ClaimScope = "scope"
	// ClaimAct is the actor chain of an exchanged token.
	ClaimAct = "act"
)

var authorizationScheme = regexp.MustCompile(`(?i)^(Bearer|DPoP)\s+(\S+)$`)

// errResolve is the generic refusal of a recognised but unusable access token (the pipeline
// answers 401 without detail).
func errResolve(reason string) error { return errors.New("oauth: " + reason) }

// ResolveBearer authenticates one of the provider's access tokens (typ at+jwt) on any Polaris
// route: verified with core's keys, meant for this server (aud is the issuer or one of
// Config.Audiences), live in the token table, presented the way it was bound (a DPoP-bound token
// with the DPoP scheme and a proof for this request, a bearer one with Bearer), its user active.
// The principal is the token's user (the client itself for client credentials) in the token's
// organization, delegated with the token's permission scopes; it never passes a step-up gate.
// It returns nil, nil for any other credential (pipeline.BearerResolver).
func (p *Plugin) ResolveBearer(r *http.Request) (*token.Token, error) {
	m := authorizationScheme.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		return nil, nil
	}
	scheme, raw := m[1], m[2]
	if header := JWTHeader(raw); header == nil || header["typ"] != AccessTokenType {
		return nil, nil
	}
	ctx := r.Context()
	claims, err := p.tokens.verifyAccess(raw)
	if err != nil {
		return nil, err
	}
	if !audienceIncludes(claims["aud"], append([]string{p.issuer}, p.settings.audiences...)...) {
		return nil, errResolve("the token is meant for another resource")
	}
	jti, _ := claims["jti"].(string)
	var rec *record
	if jti != "" {
		if rec, err = p.tokens.find(ctx, jti); err != nil {
			return nil, err
		}
	}
	if rec == nil || !rec.live(p.graph.Clock().Now()) {
		return nil, errResolve("the token is revoked or unknown")
	}
	if err := p.assertBinding(r, scheme, raw, rec.DPoPJKT); err != nil {
		return nil, err
	}
	emailVerified := false
	if rec.UserID != "" {
		user, err := p.graph.Repos().Users.Get(ctx, rec.UserID)
		if errors.Is(err, repository.ErrNotFound) || (err == nil && !active(user)) {
			return nil, errResolve("the token's user cannot sign in")
		}
		if err != nil {
			return nil, err
		}
		emailVerified = user.EmailVerifiedAt != nil
	}
	sub := rec.UserID
	if sub == "" {
		sub = rec.ClientID
	}
	claims["iat"], claims["exp"] = rec.CreatedAt, rec.ExpiresAt
	delete(claims, "auth_time") // the user's re-authentication is theirs, not the client's
	claims["sub"] = sub
	claims["org"] = null(rec.OrganizationID)
	claims["roles"] = []any{}
	claims["email_verified"] = emailVerified
	claims["mfa"] = false
	claims["amr"] = []any{AMR}
	claims[ClaimClientID] = rec.ClientID
	claims[ClaimScope] = strings.Join(rec.Scopes, " ")
	return token.NewPrincipal(claims).Delegate(p.scopes.permissions(rec.Scopes)), nil
}

// assertBinding checks the token is presented as it was bound.
func (p *Plugin) assertBinding(r *http.Request, scheme, raw, boundJKT string) error {
	dpopScheme := strings.EqualFold(scheme, "dpop")
	if boundJKT == "" {
		if dpopScheme {
			return errResolve("a bearer token is presented with the Bearer scheme")
		}
		return nil
	}
	if !dpopScheme || p.settings.dpop == DPoPOff {
		return errResolve("a DPoP-bound token is presented with the DPoP scheme and a proof")
	}
	jkt, err := p.dpop.verify(r.Context(), r.Header.Get(DPoPHeader), r.Method, requestURL(r), raw)
	if err != nil {
		return err
	}
	if jkt != boundJKT {
		return errResolve("the DPoP proof is not for the key the token is bound to")
	}
	return nil
}

// requestURL is the URL the client called, as a DPoP proof's htu names it. Behind a
// TLS-terminating proxy the host must set r.TLS for the scheme to read https.
func requestURL(r *http.Request) string {
	if r.Host == "" {
		return r.URL.RequestURI()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.RequestURI()
}

// hasAMR reports whether a principal came through this provider.
func hasAMR(t *token.Token) bool {
	switch amr := t.Claim("amr").(type) {
	case []any:
		return slices.Contains(amr, any(AMR))
	case []string:
		return slices.Contains(amr, AMR)
	}
	return false
}
