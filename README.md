<p align="center">
  <img src="docs/assets/polaris.svg" alt="Polaris" width="96">
</p>

<h1 align="center">Polaris for Go</h1>

<p align="center">
  <strong>Authentication and authorization for Go services, for users and for AI agents.</strong><br>
  Everything an auth system needs, self-hosted in your database, on <code>net/http</code>, with one import.
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/univeros/polaris.go"><img src="https://pkg.go.dev/badge/github.com/univeros/polaris.go.svg" alt="Go Reference"></a>
  <a href="https://github.com/univeros/polaris.go/actions/workflows/ci.yml"><img src="https://github.com/univeros/polaris.go/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/univeros/polaris.go/tags"><img src="https://img.shields.io/github/v/tag/univeros/polaris.go?sort=semver&label=release" alt="Release"></a>
  <img src="https://img.shields.io/github/go-mod/go-version/univeros/polaris.go" alt="Go version">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="llms.txt">llms.txt</a> ·
  <a href="#plugins">Plugins</a> ·
  <a href="#ai-agents">AI agents</a> ·
  <a href="https://polaris.univeros.io/docs/go/">Documentation</a>
</p>

---

## Why Polaris

- **Complete.** Accounts, MFA, sessions, organizations and roles, passwordless, passkeys, social
  sign-in, API keys, an OAuth 2.1 / OpenID Connect provider, SSO, SCIM, audit and risk scoring: the
  whole auth system, not a toolkit to assemble one.
- **Yours.** Users live in your PostgreSQL, MySQL or SQLite database, next to your own tables. No
  hosted service, no per-user pricing, no data leaving your infrastructure.
- **Agents are first-class principals.** An AI agent signs in with its own key, asks for grants a
  person approves, spends a budget, and leaves a signed, hash-chained receipt for every action. MCP
  servers take Polaris tokens.
- **Plain Go.** An `http.Handler` for the auth routes, middleware for yours, `context.Context`
  everywhere, errors you match with `errors.Is`. `polaristest` gives your tests a server in one line.
- **Built to be integrated by coding agents.** [`llms.txt`](llms.txt) is the whole integration on one
  page; every snippet in it is compiled by the test suite. Startup errors say how to fix them.
- **Careful where it matters.** Argon2id, constant-time comparisons, rotating refresh tokens with
  reuse detection, fuzzed parsers, contract tests replaying every route, and a stable API checked on
  every pull request.

## Quick start

```sh
go get github.com/univeros/polaris.go
go install github.com/univeros/polaris.go/cmd/polaris@latest
polaris init                      # writes .env: APP_KEY, an RS256 key pair, AUTH_ISSUER
set -a && . ./.env && set +a      # FromEnv reads the process environment
```

```go
db, err := sqlstore.Open(ctx, store.Postgres, os.Getenv("DATABASE_URL")) // or store.MySQL, store.SQLite
cfg, err := polaris.FromEnv(db /*, plugins... */)                        // reads the env vars below
p, err := polaris.New(cfg)                                               // validates everything; errors say how to fix
_, err = p.Migrate(ctx)                                                  // creates missing tables, seeds permissions; idempotent

mux := http.NewServeMux()
mux.Handle("/", p.Handler()) // every Polaris route: /auth/register, /auth/login, /auth/token/refresh, /orgs, ...
mux.Handle("GET /api/invoices", p.Protect(invoicesHandler, "org.read")) // your route, Polaris principals
```

Inside your handler, the caller is one call away:

```go
func invoices(w http.ResponseWriter, r *http.Request) {
	who, _ := polaris.PrincipalFrom(r.Context())
	fmt.Fprintf(w, "user %s in organization %s (%s)\n", who.UserID, who.OrganizationID, who.Kind)
}
```

`p.Protect` answers 401 without a principal and 403 without the permission. The principal can be a
user, an API key, an OAuth client or an agent; the same check covers all of them. A complete program is
in [`examples/minimal`](examples/minimal/main.go).

## What you get

| | |
|---|---|
| **Accounts** | Registration, email verification, password sign-in and reset (Argon2id, breached-password check), account disable, erase |
| **MFA** | TOTP, SMS and email codes, recovery codes, step-up for sensitive routes |
| **Sessions** | Short-lived JWTs (RS256 or EdDSA, JWKS published), rotating refresh tokens with reuse detection, cookie or body delivery, sign out everywhere |
| **Organizations** | Multi-tenant organizations, members, invitations, roles and permissions resolved per request, your own permissions in the catalog |
| **Your data** | Hooks in the account's transaction, your own JWT claims, a Go API (`p.Users()`, `p.Orgs()`, `p.Sessions()`, `p.Can()`) with the same rules as the routes |
| **Operations** | OpenTelemetry traces and metrics, a CLI (`init`, `migrate`, `doctor`, `schema:*`, `keys:generate`), PostgreSQL, MySQL, SQLite |

## Plugins

Add what your service needs; each plugin brings its own tables, routes, permissions and events.

```go
cfg, err := polaris.FromEnv(db,
	audit.New(audit.Config{}),
	admin.New(admin.Config{}),
	apikeys.New(apikeys.Config{}),
	passkey.New(passkey.Config{RPID: "example.com", Origins: []string{"https://example.com"}}),
)
```

| Sign-in | |
|---|---|
| [`passwordless`](plugins/passwordless) | Magic links, email and phone codes, one-time hand-off tokens |
| [`passkey`](plugins/passkey) | WebAuthn sign-in; a passkey is also an MFA factor |
| [`social`](plugins/social) | 19 OAuth / OIDC providers and a generic one, account linking, Google One Tap |
| [`username`](plugins/username) | Case-insensitive usernames; sign in with username or email |
| [`anonymous`](plugins/anonymous) | Guest sessions converted on sign-up |
| [`multisession`](plugins/multisession) | Several accounts per device, switch without signing in again |

| Machines and agents | |
|---|---|
| [`apikeys`](plugins/apikeys) | User and organization API keys, scoped to a subset of permissions, rate-limited, rotatable |
| [`oauth`](plugins/oauth) | OAuth 2.1 / OIDC provider: PKCE, client credentials, device, CIBA, token exchange, DPoP, dynamic registration |
| [`agents`](plugins/agents) | Agents as principals: grants, constraints, budgets, approvals, signed receipts, kill switch |
| [`mcp`](plugins/mcp) | Polaris as an MCP server, and `mcp.Protect` for your own MCP servers |

| Enterprise and operations | |
|---|---|
| [`sso`](plugins/sso) | SAML 2.0 and OIDC per organization, verified domains, single logout |
| [`scim`](plugins/scim) | SCIM 2.0 provisioning per organization |
| [`admin`](plugins/admin) | Operator API for users, sessions, MFA, organizations and audit |
| [`audit`](plugins/audit) | Append-only audit log, sinks and drains, optional hash chain |
| [`sentinel`](plugins/sentinel) | Risk engine: captcha, breached passwords, disposable domains, velocity, geo |
| [`messaging`](plugins/messaging) | Email and SMS delivery with templates, translations and send caps |

## AI agents

Declare what agents may do in your service; Polaris checks the grant, its constraints and budget
before your handler runs, and signs a receipt after.

```go
ag := agents.New(agents.Config{Capabilities: []agents.Capability{
	{Name: "invoices.list", Description: "List invoices", Permission: "org.read", Risk: agents.RiskLow,
		Handler: func(ctx context.Context, call agents.Call) (any, error) { return listInvoices(ctx, call.Agent) }},
	{Name: "refund", Description: "Refund an invoice", Permission: "billing.refund", Risk: agents.RiskHigh,
		Location: "https://app.example.com/api/refunds",
		Input: map[string]any{"type": "object", "required": []string{"invoice_id"},
			"properties": map[string]any{"invoice_id": map[string]any{"type": "string"}}}},
}})
```

The agent side is a Go SDK too:

```go
key, _ := agent.GenerateKey(agent.EdDSA)                 // persist key.Export(); reload with agent.ImportKey
a, _ := agent.New(ctx, "https://app.example.com", agent.WithKey(key))
bot, _, err := a.Enroll(ctx, enrollmentToken, agent.Registration{Name: "Worker", Mode: agent.Delegated})
asked, _ := bot.RequestGrants(ctx, agent.GrantRequest{Capabilities: []agent.CapabilityRequest{{Name: "refund"}}})
if asked.Approval != nil { _, err = bot.WaitForApproval(ctx, *asked.Approval) } // a person approves
res, err := bot.Execute(ctx, "invoices.list", nil)       // signed request JWT per call; res.Receipt
```

## Testing your app

```go
srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}))) // SQLite in a temp dir, test keys, recorders
```

`srv.Handler()` serves every route; `srv.Mailer.Sent()` holds the verification and reset emails;
`srv.Users()` and `srv.Sessions()` set up state without HTTP.

## Documentation

| | |
|---|---|
| [`llms.txt`](llms.txt) | The whole integration on one page: configuration, hooks, plugins, agents, MCP, testing, CLI, errors |
| [Website docs](https://polaris.univeros.io/docs/go/) | The same guides, rendered |
| [`plugins/<id>/README.md`](plugins) | Per plugin: configuration, routes, events, permissions, problems |
| [pkg.go.dev](https://pkg.go.dev/github.com/univeros/polaris.go) | Every exported identifier, with runnable examples |
| [`API.md`](API.md) | What is stable: the host surface, the plugin SDK |
| [`docs/decisions.md`](docs/decisions.md) | Every design decision, with the reason |

## Stability

Polaris is pre-1.0. The host surface and the plugin SDK listed in [`API.md`](API.md) only change with
a recorded decision and a release note, and CI checks every pull request for incompatible changes to
them. Stored data (password hashes, encrypted secrets, issued tokens, the schema) stays readable
across releases.

## Contributing and security

Contributions go through pull requests with CI green; [`AGENT.md`](AGENT.md) has the rules (tests
first, `make qa`). Report a vulnerability privately through
[GitHub security advisories](https://github.com/univeros/polaris.go/security/advisories/new), not in
an issue.

## License

[MIT](LICENSE)
