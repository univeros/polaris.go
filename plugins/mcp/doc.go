// Package mcp is Polaris and the Model Context Protocol (port of polaris/mcp), two halves sharing
// token verification.
//
// Protect any Go MCP server (one built with github.com/modelcontextprotocol/go-sdk, or any other
// http.Handler) with Polaris-issued access tokens, in its own service against a remote issuer:
//
//	h, err := mcp.Protect(mcpHandler, mcp.ProtectConfig{
//		Resource: "https://tools.example.com/mcp",
//		Issuer:   "https://auth.example.com",
//		JWKSURL:  "https://auth.example.com/auth/.well-known/jwks.json",
//		Scopes:   []string{"deploy"},
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	http.Handle("/", h) // the MCP endpoint and /.well-known/oauth-protected-resource/mcp
//
// Tokens are verified locally (signature by kid, iss, aud, exp/nbf with a minute's leeway; the JWK
// Set cached for an hour and refetched for an unknown kid at most once a minute), DPoP-bound tokens
// need a proof for the request, and the handler reads the claims with [Claims]. Refusals follow
// RFC 9728 and the MCP authorization profile: 401 WWW-Authenticate: Bearer resource_metadata="...",
// 401 error="invalid_token", 403 error="insufficient_scope" scope="<missing>". In the process that
// runs Polaris, pass Graph instead of Issuer and JWKSURL.
//
// Serve Polaris itself as an MCP server with the plugin: POST /mcp (the 2026-07-28 stateless
// profile, guarded as above with the graph's keys) and [ServeStdio] for local coding agents. Every
// route the caller may call is a tool named after it (polaris.auth.me, polaris.orgs.members.list),
// with its input schema folded from the manifest's OpenAPI operation; a call runs in-process
// through the same pipeline, so it answers {status, body} exactly as the route would, under the
// same authorization. A plugin adds tools by implementing wiring.ToolProvider (the agents plugin:
// one per capability). Resources: polaris://manifest, polaris://schema (when Config.Schema is set),
// polaris://problems/{plugin}/{name}.
//
//	p, err := polaris.New(polaris.Config{…, Plugins: []polaris.Plugin{
//		oauth.New(oauth.Config{BaseURL: base, Audiences: []string{base + "/mcp"}}),
//		mcp.New(mcp.Config{BaseURL: base}),
//	}})
package mcp
