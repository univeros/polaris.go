package mcp

import "testing"

// An OpenID ID token (plugins/oauth mintIDToken: typ JWT, the issuer's key, aud = client_id) is
// not an access token. A resource whose Resource or Audiences equals a client_id (a CIMD client's
// client_id is an https URL) accepts one today. This test fails on the current mcp.Protect.
func TestAnIDTokenIsNotAnAccessToken(t *testing.T) {
	c := newProtectCase(t)
	now := c.now()
	pr := c.local(nil)
	idToken := sign(t, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "test"}, map[string]any{
		"iss": issuerURL, "sub": "ada", "aud": testResource, "jti": "id1", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Unix() + 600,
		"email": "ada@example.com", "email_verified": true, "auth_time": now.Unix(), "nonce": "n-0S6",
	}, issuerKey())
	status(t, pr, request(idToken, "Bearer", "", nil), 401, "an ID token whose aud is the resource")
}
