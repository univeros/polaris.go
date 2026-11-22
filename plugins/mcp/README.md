# plugins/mcp

Polaris and the Model Context Protocol, two halves sharing token verification. The plugin serves
Polaris itself as an MCP server: `POST /mcp` (the 2026-07-28 stateless profile) for remote agents and
`mcp.ServeStdio` for local coding agents. Every route the caller may call is a tool named after it
(`polaris.auth.me`, `polaris.orgs.members.list`), run in-process through the same pipeline and
authorization; `plugins/agents` adds one tool per capability. `mcp.Protect` guards your own Go MCP
server with Polaris-issued tokens, in-process or against a remote issuer, without the plugin.
Register `plugins/oauth` with `Audiences: []string{BaseURL + "/mcp"}` so its tokens
reach `/mcp`.

## Install

```go
import (
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/oauth"
)

base := "https://app.example.com/auth" // where Polaris is mounted, prefix included
cfg, err := polaris.FromEnv(db,
	oauth.New(oauth.Config{BaseURL: base, Audiences: []string{base + "/mcp"}}),
	mcp.New(mcp.Config{BaseURL: base}))
p, err := polaris.New(cfg)
http.Handle("/auth/", p.Handler()) // POST /auth/mcp is the MCP server

// a local coding agent over stdio (or the CLI: polaris mcp --token=…)
err = mcp.ServeStdio(ctx, p, mcp.StdioOptions{Credential: os.Getenv(mcp.StdioEnv)}) // POLARIS_MCP_TOKEN
```

Protect your own MCP server (any `http.Handler`, e.g. the official go-sdk's):

```go
h, err := mcp.Protect(mcpHandler, mcp.ProtectConfig{
	Resource: "https://tools.example.com/mcp",
	Issuer:   "https://auth.example.com",
	JWKSURL:  "https://auth.example.com/auth/.well-known/jwks.json", // or Keys, or Graph in-process
	Scopes:   []string{"deploy"},
})
http.Handle("/", h) // the MCP endpoint and /.well-known/oauth-protected-resource/mcp
// in a tool: claims := mcp.Claims(ctx) // sub, scope, client_id, act, …
```

`Protect` checks the token locally, so a scope is all it knows. A Polaris permission name in
`Scopes` is an authorization check as of the token's issue (the oauth plugin grants a permission
scope only to a subject that holds it). A scope that is not a permission, like `deploy` above
(`oauth.Config.Scopes`), says only that the client was allowed to ask for it, which with dynamic
client registration is anyone: decide what the caller may do from a permission scope, or from `sub`
and `client_id` in `mcp.Claims`.

## Config

| Field | Default | Purpose |
| --- | --- | --- |
| `BaseURL` | required | where Polaris is mounted; the MCP resource (token `aud`) is `BaseURL + "/mcp"` |
| `Scopes` | none | scopes a token must hold to reach `/mcp` at all; each tool call is then checked by its route |
| `ServerName` | `Polaris` | server name and the metadata's `resource_name` |
| `Schema` | nil | DDL for `polaris://schema`; nil leaves the resource out (no SQL drivers linked) |

`mcp.ProtectConfig`: `Resource` (required) and exactly one key source — `JWKSURL` (https, cached
`DefaultJWKSTTL`, refetched for an unknown kid at most once a minute), `Keys`, or `Graph`. Optional:
`Issuer` (default with `Graph`: its issuer), `Audiences`, `Scopes`, `ScopesSupported`, `AllowLegacy`
(serve the 2025 session protocol too), `MetadataURL`, `ResourceName`, `HTTPClient`, `JWKSTTL`,
`Cache` (DPoP replay; share one across replicas), `Clock`, `Logger`.

Accepted tokens: an `at+jwt` (RFC 9068, the oauth plugin's access tokens), or a Polaris session
access token (`typ` JWT or none, with its `roles` list). Everything else the issuer signs is
refused, OpenID ID tokens included, even when their `aud` equals the resource. Tokens from another
issuer must be `at+jwt`.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/mcp` | one stateless JSON-RPC message: `server/discover`, `tools/list`, `tools/call`, `resources/read`, … |
| GET | `/.well-known/oauth-protected-resource/mcp` | RFC 9728 metadata of `/mcp` |

Resources: `mcp.ResourceManifest` (`polaris://manifest`, OpenAPI 3.1 of every route),
`mcp.ResourceSchema` (`polaris://schema`, when `Config.Schema` is set), `mcp.ResourceProblems`
(`polaris://problems/{plugin}/{name}`).

## Events and permissions

Emits no events and contributes no permissions. A tool call is the route itself: same permissions,
same events, same rate limits (the caller's IP is kept). Tools are listed by the delegate rule the
pipeline enforces, so a delegated token sees only what it may call.

## Problems

`https://polaris.univeros.io/problems/mcp/unauthorized` (401, with
`WWW-Authenticate: Bearer resource_metadata="…"`), `…/mcp/insufficient_scope` (403, `scope` names
the missing ones), `…/mcp/legacy_protocol` (400, a 2025 session request without `AllowLegacy`). A
route's own refusal comes back as a tool error result carrying its problem.

## Host integration

- Tool arguments are not schema-checked by the MCP layer: the route's own 422 is the answer.
- Bodies over `polaris.Config.MaxBodyBytes` (default 1 MiB) get 413.
- DPoP-bound tokens need a proof; its `htu` is checked against the configured resource, not `Host`,
  so it works behind a proxy.
- `StdioOptions.Credential` may be a session token, an API key, an OAuth access token or an operator
  key; empty serves the public tools only. `StdioOptions.Tools` adds stdio-only tools.
- `serverInfo` names `ServerName` (default "Polaris") and the running Polaris release.
- `tools/list` is paginated, on both transports: a result carries at most `mcp.ToolsPageSize` (100)
  tools and, when more follow, a `nextCursor` the client sends back as `params.cursor`. The cursor is
  opaque; one that does not name a tool of the caller's own list is `-32602` (invalid params). A
  list of 100 tools or fewer is one page with no `nextCursor`, as before.

## Example

`ExampleNew` and `ExampleProtect` in [`example_test.go`](example_test.go) —
`go doc github.com/univeros/polaris.go/plugins/mcp`.
