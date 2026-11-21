# Polaris for Go

Authentication and authorization for Go services, for users and for AI agents: everything an auth
system needs, self-hosted in your database, mounted on `net/http` with one import.

- **Users:** registration, email verification, password sign-in and reset (Argon2id, breached-password
  check), MFA (TOTP, SMS, email, recovery codes, step-up), sessions with rotating refresh tokens and
  reuse detection, cookie or bearer delivery.
- **Organizations and access:** multi-tenant organizations, members and invitations, roles and
  permissions resolved per request, `p.Protect(handler, "invoices.read")`.
- **Sign-in methods:** passwordless (magic links, email and phone codes), passkeys (WebAuthn),
  social (19 OAuth / OIDC providers and a generic one), usernames, guests, several accounts per device.
- **Machines and agents:** API keys, an OAuth 2.1 / OpenID Connect provider (PKCE, device, CIBA, token
  exchange, DPoP, dynamic registration), agents as first-class principals (grants with budgets and
  constraints, human approval, signed hash-chained receipts, a kill switch), MCP servers protected by
  Polaris tokens, and a Go agent SDK.
- **Enterprise and operations:** SSO (SAML 2.0, OIDC) with verified domains, SCIM 2.0 provisioning, an
  operator API, an append-only audit log, a risk engine, email and SMS delivery, OpenTelemetry.
- **Runs on** PostgreSQL, MySQL or SQLite; `polaristest` gives your own tests a server in one line.

```go
db, err := sqlstore.Open(ctx, store.Postgres, os.Getenv("DATABASE_URL"))
cfg, err := polaris.FromEnv(db /*, plugins... */)
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx)

mux.Handle("/", p.Handler())                                            // every Polaris route
mux.Handle("GET /api/invoices", p.Protect(invoicesHandler, "org.read")) // your routes
```

Start with [`llms.txt`](llms.txt): the whole integration on one page, written for coding agents and
people alike. Then [`examples/`](examples), each plugin's `README.md`, and
[`API.md`](API.md) for what is stable. Design decisions: [`docs/decisions.md`](docs/decisions.md).
Working on Polaris itself: [`AGENT.md`](AGENT.md).

MIT licensed.
