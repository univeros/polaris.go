package mcp

import (
	"testing"
)

// The issuer signs more than access tokens with one key: a login-MFA ticket (password only), a
// DPoP proof, an agent request JWT, a receipt. mcp.Protect must take none of them for an access
// token even when their aud names the resource (an AUTH_AUDIENCE configured as an Audience).
func TestOnlyAccessTokensAreAccepted(t *testing.T) {
	c := newProtectCase(t)
	now := c.now()
	pr := c.local(nil)
	claims := map[string]any{"iss": issuerURL, "sub": "ada", "aud": testResource, "iat": now.Unix(), "exp": now.Unix() + 600, "scope": "org.read"}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range claims {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	for name, token := range map[string]string{
		"a login-MFA ticket": sign(t, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "test"}, with(map[string]any{"purpose": "login_mfa"}), issuerKey()),
		"a DPoP proof":       sign(t, map[string]any{"typ": "dpop+jwt", "alg": "RS256", "kid": "test"}, claims, issuerKey()),
		"an agent JWT":       sign(t, map[string]any{"typ": "agent+jwt", "alg": "RS256", "kid": "test"}, claims, issuerKey()),
		"a receipt":          sign(t, map[string]any{"typ": "polaris-receipt+jwt", "alg": "RS256", "kid": "test"}, claims, issuerKey()),
	} {
		status(t, pr, request(token, "Bearer", "", nil), 401, name)
	}
	// A session access token (typ JWT) always carries its roles list; an OpenID ID token never
	// does. at+jwt (RFC 9068) needs no roles.
	session := with(map[string]any{"roles": []any{}})
	for name, c := range map[string]struct {
		typ    any
		claims map[string]any
		want   int
	}{
		"at+jwt":                    {"at+jwt", claims, 200},
		"a core access token":       {"JWT", session, 200},
		"no typ, a session's shape": {nil, session, 200},
		"typ JWT without roles":     {"JWT", claims, 401},
		"no typ without roles":      {nil, claims, 401},
		"roles that are not a list": {"JWT", with(map[string]any{"roles": "admin"}), 401},
	} {
		header := map[string]any{"alg": "RS256", "kid": "test"}
		if c.typ != nil {
			header["typ"] = c.typ
		}
		status(t, pr, request(sign(t, header, c.claims, issuerKey()), "Bearer", "", nil), c.want, name)
	}
}
