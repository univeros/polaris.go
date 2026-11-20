// Package oauth makes Polaris an OAuth 2.1 and OpenID Connect provider (the port of upstream's
// polaris/oauth-provider, plugin id "oauth"): authorization code with PKCE (S256 only) and consent,
// rotating refresh tokens, client credentials, the device flow (RFC 8628), backchannel
// authentication (OpenID CIBA, poll mode), token exchange (RFC 8693, with act), DPoP (RFC 9449),
// dynamic registration (RFC 7591, off by default), client ID metadata documents (an https
// client_id fetched, validated and cached), introspection, revocation, userinfo and the discovery
// documents. Its access tokens (typ at+jwt, signed with core's key) are accepted on every Polaris
// route within their scopes: a scope is a permission name.
//
// Install it with zero configuration:
//
//	p, err := polaris.New(polaris.Config{Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{oauth.New(oauth.Config{ConsentURL: "https://app.example/consent"})}})
//
// Other plugins (polaris/agents) reach it with g.Plugin(oauth.ID).(*oauth.Plugin) and use its
// client, token and DPoP methods.
package oauth
