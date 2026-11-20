# Polaris for Go — the port of `polaris-core`

Status: **open** (2026-11-20). Upstream pinned at `univeros/polaris-core` **0.12.0** (`da72f79`).
Decisions taken while porting go to [`decisions.md`](decisions.md), append only.

---

## 0. Why this exists

Every project we build now needs agents to sign in: agents as OAuth clients, agents acting for a user
through token exchange, signed request JWTs, capability grants with budgets, approvals, receipts, a
kill switch, MCP servers protected by the same tokens. `polaris-core` (PHP) already does all of it.
The Go services need the same thing natively, as a library they embed, not a PHP sidecar.

This repository is that library: **the whole of `polaris-core`, ported to Go, minus the framework
adapters**. Its first users are internal Go projects; the agent stack (§8, WP4–WP5) is therefore
ported right after core, before the remaining sign-in methods and the infrastructure plugins.

**This repository is public** (MIT), like every Polaris repository. See §7.

---

## 1. Goals and non-goals

### Goals

| # | Goal | Proven by |
|---|---|---|
| G1 | **Same HTTP contract.** Every route of core and of every plugin answers the same status, headers and body as PHP. | The upstream contract fixtures replayed against the Go handler (§6.2). |
| G2 | **Same data.** Same tables, columns, types and indexes as PHP's `Schema`. A Go instance and a PHP instance can share one database. | `schema:export` output diffed against PHP's per dialect; cross-language vectors (§6.3). |
| G3 | **Same secrets and tokens.** Password hashes, peppered hashes, encrypted payloads and JWTs made by one side are accepted by the other with the same `APP_KEY` and signing keys. | Cross-language vectors (§6.3). |
| G4 | **Same manifest.** The endpoint YAML files are not rewritten: they are mirrored from upstream and embedded; the Go router, validator, OpenAPI export and MCP tool list are built from them. | `upstream/` is byte-identical to the pinned ref (§2). |
| G5 | **Same events and problem types.** Event names (`user.logged_in`, `agent.executed`, …), payload fields, RFC 9457 problem `type` URLs. | Listener tests; fixtures. |
| G6 | **Go first, not PHP translated.** Only what is observable is frozen (G1–G5). Everything inside — package boundaries, types, concurrency, error handling, configuration, extension points — is designed the way the best Go library would do it, even where that departs from the PHP structure. A PHP class is a description of behaviour, not a design to copy. | Review; `decisions.md` records each notable departure. |
| G7 | **Agents first.** Core, then api-keys, oauth-provider, agents, mcp and the Go agent SDK. | §8 order. |
| G8 | **Trivial for a coding agent to integrate.** An agent dropped into any Go project adds Polaris correctly without reading the source: one import, a few lines, one CLI command to check it. | §4.6; the integration test in each WP's acceptance. |

Consequence of G1+G4: `@polaris-auth/client` and `@polaris-auth/agent` (npm) work unchanged against a
Go server. They are not ported.

### Non-goals

- **Framework adapters**: `polaris/laravel`, `polaris/symfony`, `polaris/yii`. The Go equivalent of
  `polaris/psr15` is a plain `http.Handler`; any Go router (stdlib mux, chi, echo, gin) mounts it.
- **The TypeScript packages** (`client-ts`, `agent-ts`): reused as they are (see above).
- **The PHP agent SDK** `polaris/agent`: replaced by a Go agent SDK (WP5) with the same behaviour.
- **Skills / Claude Code plugin** (upstream program 4 WP5): out of scope until 1.0 (§9).
- **New features.** The port adds nothing upstream does not have. A feature request goes upstream
  first, then is ported. A Go-only *API* convenience (an option, a helper) is fine; a Go-only
  *behaviour* on the wire or in the database is not.

---

## 2. Upstream is the source of truth

- PHP `polaris-core` is the reference implementation. When the Go code and the PHP code disagree, the
  PHP code is right unless `decisions.md` says otherwise.
- `upstream/` mirrors, byte for byte, from the pinned ref:
  - `upstream/api/<package>/…` — every package's `api/` directory (the endpoint manifest, plus core's
    `schema.json`, the JSON Schema of a manifest file).
  - `upstream/fixtures/<package>/…` — every package's `tests/Contract/fixtures/*.json`.
  - `upstream/REF` — the upstream commit and tag.
- `scripts/sync-upstream.sh [<git-ref>]` refreshes the mirror from `../polaris-core` (or
  `$POLARIS_CORE`). Nobody edits `upstream/` by hand.
- Bumping the pin is its own change: sync, read upstream's `CHANGELOG.md` between the two refs, port
  the differences, record the bump in `decisions.md`.
- The Go package `upstream` embeds `upstream/api` (`embed.FS`), so the manifest ships inside the
  binary.

Upstream counts at the pin: 226 routes (core 52; admin 29; oauth 26; agents 23; scim 22; sso 20;
passwordless 13; social 9; api-keys 7; passkey 7; sentinel 5; multi-session 4; audit 3; anonymous 2;
mcp 2; username 2), 239 fixtures (core 184), 35 core events.

---

## 3. Compatibility contract

### 3.1 HTTP

- Core routes keep core's plain envelope: `{"data": …}` on success, `{"error": "<code>", "message": "…"}`
  on failure (`docs/auth/api-reference.md` upstream).
- Plugin routes answer RFC 9457 problems: `application/problem+json`, `type`
  (`https://polaris.univeros.io/problems/<plugin>/<name>`), `title`, `status`, `detail`, plus `error`
  and `message`.
- Validation messages, rate-limit headers (`X-RateLimit-Limit|Remaining|Reset`, `Retry-After`),
  anti-enumeration responses and timing parity on unknown accounts are part of the contract.
- Cookie token delivery (`auth.flows.token_delivery: cookie`): same cookie names, attributes, CSRF guard
  and plaintext refusal as upstream `docs/cookie-mode/spec.md`.
- Routes are relative; the handler takes a path prefix.

### 3.2 Data

- Table and column names, types, nullability, defaults, indexes and foreign keys equal PHP's
  `Polaris\Schema` definitions for every dialect: PostgreSQL, MySQL, SQLite.
- IDs are UUIDv7 strings, timestamps are stored as PHP stores them (format pinned by vectors in WP1).
- The Go `schema` package is the schema as data, as in PHP: DDL, `schema:diff` and the stores all read it.

### 3.3 Secrets and tokens (security-critical, ported literally)

| Primitive | Upstream | Go |
|---|---|---|
| Password hash | `password_hash(PASSWORD_ARGON2ID)`, m=65536, t=4, p=1, PHC string `$argon2id$v=19$m=…,t=…,p=…$salt$hash` | `golang.org/x/crypto/argon2.IDKey`, same PHC encoding (unpadded standard base64), `needsRehash` on parameter mismatch |
| Pepper | HKDF-SHA256(APP_KEY, 32, info `polaris:pepper:<context>`, salt ""), then HMAC-SHA256, lowercase hex; APP_KEY ≥ 32 bytes | `crypto/hkdf` + `crypto/hmac`; compare with `hmac.Equal` |
| Encrypter | key = HKDF-SHA256(APP_KEY, 32, info `polaris:encrypter:mfa`); XChaCha20-Poly1305-IETF, AD = version byte `0x01`; payload = base64(`0x01` ‖ nonce(24) ‖ ciphertext‖tag) | `golang.org/x/crypto/chacha20poly1305.NewX`, same layout |
| Access token | JWT, RS256 or EdDSA, `kid` header, managed `iss aud iat nbf exp`, `sub`, `jti`, Polaris claims (active org, roles, `amr`, `delegated`, `act`, `cnf.jkt`, …) | `github.com/go-jose/go-jose/v4` |
| JWKS | `/auth/jwks`, RFC 7517, `kid` rotation | same library |
| Refresh token | opaque, keyed-hashed, rotating, reuse revokes the family | ported literally |
| TOTP | RFC 6238 (otphp defaults: SHA1, 6 digits, 30 s) | `github.com/pquerna/otp` |
| Random tokens | `random_bytes` → base64url | `crypto/rand` → `base64.RawURLEncoding` |

Comparisons are constant-time. Sensitive values never reach a log (`slog.LogValuer` redaction on
secret types).

### 3.4 Allowed to differ (everything not in §3.1–3.3)

- The whole internal design. Go idioms win over PHP structure: small consumer-side interfaces instead
  of PHP's contract classes, values and plain structs instead of entity objects with a unit of work,
  `context.Context` for cancellation and request scope, errors as values (`errors.Is/As`), goroutine
  safety where a service is shared, generics where they remove duplication, stdlib before libraries.
  PHP services that exist only because of PHP constraints (reflection wiring, PSR adapters, identity
  maps) are not ported.
- The Go API: names, options, constructors (`polaris.New(polaris.Config{…})`), interfaces.
- Configuration loading: a Go struct plus `config.FromEnv()` reading the same env names
  (`APP_KEY`, `AUTH_JWT_*`, …).
- The QR image bytes (encoder differs); fixtures mask it already.
- Error strings inside Go `error` values (not on the wire).

---

## 4. Architecture

### 4.1 Mapping

| PHP | Go | Notes |
|---|---|---|
| `Polaris::create(new Config(...))` | `polaris.New(polaris.Config{…}) (*polaris.Polaris, error)` | Explicit graph, no container. |
| `Polaris\Wiring\Graph` | `polaris.Graph` | Lazily built services, one instance per graph; plugins look services up by typed accessor or `graph.Service(key)`. |
| `Polaris\Contract\*` ports | interfaces in the package that consumes them | `store.Adapter`, `mail.OTPMailer`, `sms.Sender`, `ratelimit.Store`, … Go idiom: small interfaces, defined at the consumer. |
| `Polaris\Psr15\Pipeline` + middleware | `pipeline` package: `func (p *Polaris) Handler() http.Handler` and `Middleware() []func(http.Handler) http.Handler` | Order in §4.3. |
| `Http\Endpoint(Input): Result` | `type Endpoint interface { Handle(ctx, Input) Result }` | Registered by the manifest's `domain.class`, mapped to a Go constructor in a registry (§4.4). |
| PSR-14 dispatcher + events | `event.Dispatcher` interface (`Dispatch(ctx, Event)`), typed event structs with `Name()` | Default: synchronous in-process; host may pass its own. |
| PSR-3 logger | `*slog.Logger` | |
| PSR-16 cache / clock | `cache.Cache`, `clock.Clock` | In-memory and system defaults. |
| `DatabaseAdapter` | `store.Adapter` (`FindOne`, `FindMany`, `Insert`, `Update`, `Delete`, `Count`, `Tx`, `Dialect`), all taking `context.Context` | Transaction carried in the context. |
| `polaris/pdo` | `store/sqlstore` over `database/sql` | Postgres (`pgx/v5/stdlib`), MySQL (`go-sql-driver/mysql`), SQLite (`modernc.org/sqlite`, no cgo). |
| `polaris/testing` | `store/memstore` | In-memory, passes the same conformance suite. |
| `polaris/cli` | `cmd/polaris` | `schema:export|create|drop|diff`, `manifest`, `doctor`, `mcp`; stdlib `flag`. `--bootstrap` is replaced by building the CLI in the host (`cli.Run(p *Polaris, args)`), so a host's plugins are seen. |
| `Polaris\Contract\Plugin` | `polaris.Plugin` interface (§4.5) | |
| PHP exceptions | sentinel errors + typed errors (`errors.Is/As`) | Endpoints map them to the envelope exactly as PHP does. |

### 4.2 Layout

One Go module, `github.com/univeros/polaris.go`. Packages are added when their work package starts,
not before.

```
polaris.go, setup.go, …   the host surface: New, FromEnv, Migrate, Prune, Handler, Protect,
                          PrincipalFrom, Users/Orgs/Sessions/Can, Hooks, errors (§4.7)
wiring/ endpoint/ manifest/ event/ token/   the plugin SDK (read-only Graph accessors)
schema/  store/ store/sqlstore store/memstore store/storetest
config/  security/  cache/  clock/  ratelimit/  notify/  metrics/
model/  repository/  identity/  session/  mfa/  authz/  orgs/  pipeline/   implementation
plugins/<id>/             audit, admin, apikeys, oauth, agents, mcp, passwordless, username,
                          anonymous, multisession, social, passkey, messaging, sentinel, sso, scim
agent/                    the Go agent SDK
telemetry/otel/           OpenTelemetry middleware, store wrapper, auth metrics
cli/  cmd/polaris/        the CLI (cli.Run for host binaries)
polaristest/              a full test server for hosts' tests
internal/                 upstream mirror and embed, contracttest, httpapi (core endpoints),
                          observe, maintenance, netguard, e2e
examples/  llms.txt  API.md
```

Dependency direction: domain packages ← `wiring` ← `httpapi`, `pipeline`, plugins ← root `polaris`.
Plugins import `wiring` and `endpoint`, never the root; nothing imports a plugin except the host.
`internal/` is used for helpers no host or plugin should touch.

### 4.3 Request pipeline (order is contractual)

1. Route match (404/405 in the core envelope)
2. Client context (IP, user agent)
3. Per-IP auth rate limit
4. Refresh cookie (cookie delivery only)
5. MFA ticket authentication
6. Bearer authentication: plugin **bearer resolvers** first (api-keys, oauth, agents), then core JWT parse
7. Plugin middleware (in plugin registration order)
8. Step-up
9. Denylist
10. Per-principal rate limit
11. Authorization (manifest `requires_permissions` + `Gate`, delegated authority intersection)
12. Endpoint

Principal, route and token travel in the request `context.Context` through typed keys.

### 4.4 Endpoints from the manifest

The YAML stays byte-identical, but Go does not key anything on the PHP class names it contains
(`domain.class` is ignored). Endpoints register by **route name**, derived from the spec file path as
upstream does (`polaris.auth.login`, `polaris.agents.execute`): a `map[string]Endpoint` per package.
At `New()`, every route in the manifest must have a registered endpoint, or `New` fails (no silent
501s). Until a work package lands, its routes are simply not mounted: the manifest
is filtered by the packages enabled.

Input rules (`required`, `email`, `max:N`, `list<string>`, …) are a port of PHP's validator with the
same messages; no third-party validator.

### 4.5 Plugins

```go
type Plugin interface {
    ID() string
    Schema() []schema.Model
    Manifest() fs.FS                      // the plugin's api/<id>/ tree; nil if none
    Endpoints() map[string]EndpointFactory
    Services(g *Graph) error              // register services on the graph
    Listeners(g *Graph) []event.Listener
    Permissions() map[string]string
    Middleware(g *Graph) []func(http.Handler) http.Handler
}
```

Plus the core seams upstream added for program 4, as optional interfaces a plugin may implement:
`BearerResolver` (WP3 #2), `MfaFactorType` (WP2), and the delegated-authority claim honoured by the
gate (WP3 #3). A `polaris.BasePlugin` gives empty defaults. Rejections match PHP: a plugin redefining a
core table or redeclaring a route fails `New`.

### 4.6 Integration surface (built for coding agents)

The primary integrator of this library is a coding agent working in someone else's Go project. Every
rule below exists so it gets the integration right the first time.

1. **The whole integration fits on one screen.**
   ```go
   p, err := polaris.New(polaris.FromEnv(db),            // APP_KEY, AUTH_JWT_*, issuer, audience
       polaris.WithPlugins(apikeys.New(), oauth.New(), agents.New(agents.Config{…})))
   if err != nil { log.Fatal(err) }
   mux.Handle("/auth/", p.Handler())                      // every Polaris route
   mux.Handle("/api/", p.Protect(apiHandler, "invoices.read")) // your routes, Polaris principals
   ```
   `polaris.PrincipalFrom(ctx)` gives the user / agent / API key / OAuth client on any protected
   request (§4.7). Functional
   options for everything optional; every port has a working default (in-memory cache, log mailer,
   system clock), so the zero-config path runs.
2. **Fail at startup, with the fix in the message.** `New` validates config, keys, schema presence
   and manifest coverage; every error names the env var, file or command that fixes it
   (`APP_KEY is 12 bytes, need ≥ 32: run "polaris keys:generate"`). Nothing fails lazily on the first
   request.
3. **One CLI, machine-readable.** `polaris init` (writes `.env` keys, generates RS256/EdDSA keys,
   prints the snippet above for the plugins chosen), `polaris schema:create|diff`, `polaris doctor`.
   Every command is idempotent, takes `--json`, and exits non-zero with a remedy on failure.
4. **Docs an agent reads first.** `llms.txt` at the repo root (what Polaris is, the snippet, the
   plugin list with one line each, where the examples are); a `doc.go` per package with a runnable
   `Example…` test for its main use, so `go doc` answers and examples cannot rot.
5. **Copyable examples.** `examples/<scenario>/main.go`, each a complete compiling program checked by
   `go build ./...`: `minimal` (core only), `api-keys`, `agent-delegated`, `agent-autonomous`,
   `mcp-server` (an MCP server protected by Polaris).
6. **Small public API.** Exported identifiers are the stable surface; everything else lives in
   `internal/`. Breaking an exported name before 1.0 is allowed only with a decision entry.
7. **Errors are typed and stable.** Wire errors carry the upstream problem `type`; Go errors expose
   `errors.Is` sentinels so an agent can branch without string matching.
8. **Polaris explains itself over MCP** (WP5): the `polaris mcp` stdio server exposes the manifest,
   schema and problem catalog as resources, so an agent with MCP can query routes and permissions
   instead of guessing.

Each WP's acceptance includes: its `examples/` program builds and its scenario runs end to end in a
test, and `llms.txt` lists what it added.

### 4.7 The Go developer surface (WP9)

Goal: the obvious choice for a Go service that wants embedded auth. A host touches only package
`polaris` (plus plugin constructors, `store/sqlstore`, `polaristest`, `agent`, `mcp.Protect`);
`wiring`, `endpoint`, `manifest`, `event`, `token` are the **plugin SDK**; everything else is
implementation, behind `internal/` where nothing outside the module needs it.

1. **Principal as a value.** `polaris.PrincipalFrom(ctx) (polaris.Principal, bool)` with
   `Principal{UserID, OrganizationID, Roles, Permissions, Kind, Delegated, ClientID, AgentID,
   KeyID, Claims}`; `Kind` is `KindUser | KindAPIKey | KindOAuthClient | KindAgent`.
   `*token.Token` stays reachable for plugin authors only.
2. **The app keeps its own user data.** `polaris.Hooks` in `Config`: `OnUserCreated(ctx, User)
   error` and `OnUserDeleted(ctx, userID) error` run inside Polaris's transaction (an error aborts
   it), so an app's profile row is created atomically with the account; `Claims(ctx, ClaimsInput)
   (map[string]any, error)` adds namespaced claims to access tokens (reserved names refused at
   startup and at mint time).
3. **Transactions.** `sqlstore.WithTx(ctx, *sql.Tx) context.Context`: every Polaris write made
   with that ctx joins the host's transaction (the host commits or rolls back); nested Polaris
   transactions become savepoints.
4. **Programmatic API.** Everything the HTTP routes do for an app, as Go calls on `*Polaris`:
   `p.Users()` (Get, ByEmail, Create, SetPassword, Disable, Enable, Delete), `p.Orgs()`
   (Create, Get, ListFor, AddMember, SetRoles, RemoveMember), `p.Sessions()` (Issue for a custom
   sign-in, Refresh, Revoke, RevokeAll), `p.Can(ctx, principal, perms...) bool`. Same checks,
   events and audit as the routes.
5. **Read-only graph.** `wiring.Graph` exposes services through accessor methods, not mutable
   fields; documented as the plugin SDK.
6. **Observability.** `polaris.Config.Middleware` (host middleware wrapped outermost) and package
   `telemetry/otel`: OpenTelemetry spans and metrics for the pipeline (`Middleware`) and the store
   (`Store(adapter)`), importing OpenTelemetry only when that package is imported.
7. **Quality bar.** `staticcheck`, `govulncheck`, `golangci-lint` (a checked-in config) clean in
   CI (GitHub Actions); benchmarks for login, token verification, Protect and agent
   execution; `API.md` states what is stable in v0.x and what may change.

---

## 5. Dependencies

Stdlib first. Allowed, each for a reason; adding one outside this list is a decision.

| Need | Module |
|---|---|
| Argon2id, XChaCha20-Poly1305, HKDF fallback | `golang.org/x/crypto` |
| JWS/JWT/JWK/JWKS, RFC 7638 thumbprints, DPoP | `github.com/go-jose/go-jose/v4` |
| YAML manifest | `go.yaml.in/yaml/v3` |
| UUIDv7 | `github.com/google/uuid` |
| TOTP | `github.com/pquerna/otp` |
| QR PNG | `github.com/skip2/go-qrcode` |
| SQL drivers | `github.com/jackc/pgx/v5`, `github.com/go-sql-driver/mysql`, `modernc.org/sqlite` |
| WebAuthn (passkey) | `github.com/go-webauthn/webauthn` |
| OIDC/OAuth2 client (social, sso) | `github.com/coreos/go-oidc/v3`, `golang.org/x/oauth2` |
| SAML (sso) | `github.com/crewjam/saml` |
| MCP server/transports | `github.com/modelcontextprotocol/go-sdk` |

Not used: web frameworks, DI containers, ORMs, `fosite`/`go-oauth2` (same reason upstream rejected
`league/oauth2-server`: their storage model fights the schema-as-data contract and duplicates users).

---

## 6. Testing

TDD; coverage ≥ 80% per package; `go test -race ./...` green before any commit. `make qa` runs gofmt
check, `go vet`, tests with race and coverage.

### 6.1 Unit and integration

Each Go package has tests for its own behaviour, ported from the matching PHP test where one exists.
`store/storetest` is the adapter conformance suite (port of `tests/AdapterConformance`); it runs on
`memstore` and SQLite always, on PostgreSQL and MySQL when `POLARIS_TEST_PG_DSN` /
`POLARIS_TEST_MYSQL_DSN` are set.

### 6.2 Contract replay (the oracle)

Upstream fixtures record each functional test's request/response steps. They are compare-only: the
test issues requests (taking tokens from earlier responses and from captured mail/SMS), and each
response is compared, normalized, with the recorded step.

- `contracttest` ports `Fixture`, `Normalizer` and `KnownChanges` from `packages/core/tests/Contract`
  (volatile headers dropped, tokens/UUIDs/timestamps masked, query hand-off codes masked).
- Each upstream functional test is ported 1:1 as a Go test with the **same name**, so it finds its
  fixture: `Polaris.Tests.Functional.LoginEndpointTest.testLoginReturnsTokens` ↔ Go
  `TestLoginEndpoint/testLoginReturnsTokens` resolving `upstream/fixtures/core/<that name>.json`.
- Same frozen clock, same seeded keys and config as the PHP harness (`FunctionalTestCase::setUp`).
- A work package is done when **all** fixtures of its packages pass. A coverage test (port of
  `ContractCoverageTest`) fails if a fixture file has no Go test.

### 6.3 Cross-language vectors

`scripts/vectors.php` (run against `../polaris-core/vendor`) writes `testdata/vectors/*.json`: Argon2id
hashes, pepper hashes, encrypted payloads, signed JWTs, refresh-token hashes, TOTP codes at fixed
times, the DDL per dialect. Go tests verify each one and produce their own for PHP to verify
(`scripts/verify-vectors.php`). This proves G2 and G3.

---

## 7. Visibility and disclosure

- Polaris is public at every level: this repository (`univeros/polaris.go`) is MIT and public, and
  its documentation joins the Polaris website next to the PHP version.
- Exception, temporary: the repository stays private until polaris-core ships the fixes for the
  upstream vulnerabilities this port found and documents (decisions #38, #39, #43), so their
  exploits are never public before a patch. Then it is flipped public and `scripts/protect-main.sh`
  protects `main` (pull requests only, the three CI checks green, linear history, no force pushes).
- Security issues found later follow the same rule: fix upstream (or here) first, publish details
  after.
---

## 8. Work packages

Branch `port/wpN`. Each WP: read its scope, write tests first (ported PHP tests + fixtures), make them
pass, log decisions, open a PR listing each acceptance criterion with how it was verified.

### WP0 — setup (this change)

Module, docs, privacy guard, upstream mirror, `make qa`.
**Accept:** `go build ./... && go vet ./...` green; `upstream/REF` = `da72f79` (the pre-push guard of
this WP was retired by decision #49).

### WP1 — foundation

`schema` (+ core definitions), `store` + `memstore` + `sqlstore` (SQLite, Postgres, MySQL) + conformance
suite, `security` (§3.3), `clock`, `cache`, `ratelimit`, `event`, `manifest` (loader against
`schema.json`, input rules, OpenAPI export), `pipeline` skeleton (router, envelope, problem writer),
`contracttest` harness, `scripts/vectors.php`.
**Accept:** conformance suite green on memstore + SQLite (+ PG/MySQL in CI); vectors both ways;
`polaris manifest --format=openapi` equals PHP's output for core; DDL equals PHP's per dialect.

### WP2 — identity and tokens

Register, email verification, login (lockout, timing parity), `/auth/me`, logout, logout-all, refresh
rotation with reuse detection, sessions, password forgot/reset/change, JWKS, switch-org token
re-scoping, denylist, cookie delivery, notifications via mailer/SMS ports, prune service.
**Accept:** fixtures of `Registration`, `Login`, `Session`, `Password`, `Jwks`, `AuthMiddleware`,
`Denylist`, `CookieMode` tests pass.

### WP3 — MFA, organizations, RBAC, users; core complete

TOTP/SMS/email factors, recovery codes, login MFA gate, step-up, `MfaFactorType` seam; organizations,
memberships, roles, invitations, permission catalog + seeder, `Gate`, escalation guard, last-owner
rule; user admin; audit-log listener, metrics listener; `cmd/polaris` (`schema:*`, `manifest`, `doctor`);
plugin runtime (§4.5) with `BearerResolver` and delegated authority.
Integration surface for core (§4.6 items 1–7): `FromEnv`, options, `Handler`, `Protect`,
`Principal`, startup validation with remedies, `polaris init`, `llms.txt`, `examples/minimal`.
**Accept:** all 184 core fixtures pass; a test plugin proves every plugin part; a fresh Go module
integrates core from `llms.txt` alone (scripted check: copy the snippet, build, register, log in);
core release `v0.1.0`.

### WP4 — agent sign-in, part 1: api-keys, oauth-provider, audit, admin

`plugins/audit` (receipts and agent actions need the store), `plugins/admin` (agents and mcp use its
operator principals and `/admin` routes), `plugins/apikeys`, `plugins/oauth`
(authorization code + PKCE, refresh, client credentials, device, CIBA, token exchange with `act`,
DPoP, DCR off by default, CIMD, discovery, introspection, revocation, userinfo).
**Accept:** their fixtures pass; a Go service can protect its routes with Polaris-issued API keys and
OAuth tokens; `v0.2.0`.

### WP5 — agent sign-in, part 2: agents, mcp, Go agent SDK

`plugins/agents` (registration, host enrolment, delegated/autonomous, signed request JWTs,
capabilities, grants, constraints, budgets, approvals by device code / CIBA / in-app, receipts and
hash chain, kill switch, `/.well-known/agent-configuration`), `plugins/mcp` (`McpProtectedResource`
middleware for any Go MCP server; Polaris as an MCP server over `POST /mcp` and `polaris mcp` stdio),
`agent/` SDK (discover, register/enroll, request grant, poll approval, sign request JWTs, call,
verify receipts).
**Accept:** their fixtures pass; the Go SDK and `@polaris-auth/agent` both complete the
register → grant → approve → execute → verify-receipt walkthrough against a Go server; `v0.3.0`.
**This is the release internal projects adopt.**

### WP6 — sign-in methods

`passwordless`, `username`, `anonymous`, `multisession`, `social`, `passkey`.
**Accept:** their fixtures pass; `v0.4.0`.

### WP7 — infrastructure plugins

`messaging`, `sentinel`, `sso`, `scim` (`admin` moved to WP4).
**Accept:** their fixtures pass; `v0.5.0`.

### WP8 — 1.0

Re-sync with upstream head, port the delta, security review of `security`, `token`, `oauth`, `agents`,
`mcp`, `passkey`, `social`, `sso`; fuzz tests on manifest input, token parsing and SCIM filter;
README per plugin; `v1.0.0`.

---

## 9. Decisions taken by default, and what is left open

Taken (log them in `decisions.md` if revisited):

1. One Go module, plugins as subpackages: one repository, one version, no `go.work`.
2. Database- and token-compatible with PHP (G2, G3), so PHP and Go apps can share an identity store.
3. Manifest YAML reused verbatim, endpoints keyed by PHP class name (§4.4).
4. Agents-first ordering (§8).
5. No Go agent skills / Claude Code plugin until 1.0; `llms.txt`, examples and the MCP resources
   (§4.6) carry the integration knowledge until then.
6. The public API is designed for a coding agent as integrator (§4.6): a single snippet, defaults
   for every port, startup errors with remedies.

Open:

- Whether to keep tracking upstream after 1.0, or let the two diverge.
- Router 405 behaviour and trailing-slash handling: decided by what the fixtures show in WP1.
