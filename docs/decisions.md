# Port decisions

Append only. Each entry: date, decision, why. The spec is [`spec.md`](spec.md).

## 1. 2026-11-20 — Upstream pinned at polaris-core 0.12.0 (`da72f79`)

The port starts from the last release. `upstream/` mirrors its manifests and fixtures; bumping the pin
is a separate change (spec §2).

## 2. 2026-11-20 — Agents first, integration by agents

The library exists so internal Go projects get agent sign-in (API keys, OAuth provider, agents, MCP).
After core (WP1–WP3), those plugins come first (WP4–WP5); the integration surface is designed for a
coding agent as the integrator (spec §4.6, G8).

## 3. 2026-11-20 — Private repository

Private repository `univeros/polaris.go`, no public remote, `GOPRIVATE` for the module path,
pre-push hook refusing non-private remotes (spec §7). License MIT, as upstream: visibility is
controlled by the repository, and MIT keeps a later open-sourcing a visibility switch.

## 4. 2026-11-20 — Fixture bodies compare structurally

PHP `assertSame` on decoded arrays is key-order sensitive; Go decodes JSON objects into maps. The Go
harness compares decoded bodies structurally (key order ignored), everything else exactly. No client
depends on key order. Endpoints must still emit `[]` where PHP emits an empty array (never `null`).

## 5. 2026-11-20 — Packages: `wiring` holds the graph, the root is a façade

Endpoints and plugins need the graph, and the root must import the core endpoints and the pipeline,
so the graph lives in `wiring` (as PHP's `Polaris\Wiring\Graph`) and the root package only re-exports
it (spec §4.2). Persistence maps rows explicitly per model instead of PHP's reflection-driven unit of
work; the writes and their transactions are the same.

## 6. 2026-11-20 — Go first: only observable behaviour is frozen

The owner's rule: doing something a certain way in PHP does not make it right in Go. Upstream fixes
what clients and a shared database observe (responses, tables, secret and token formats, event
names); the internal design is Go's own (spec G6, §3.4). Consequence: endpoints register by route
name, not by the PHP class named in `domain.class` (spec §4.4).

## 7. 2026-11-20 — Contract harness is stricter than PHP's

`contracttest.For` fails when a fixture file is missing (PHP skipped silently) unless
`POLARIS_RECORD_FIXTURES=1`; `Uncovered` errors on a missing directory; a failed test never records;
a mismatch names the first differing JSON path. Empty `{}` and `[]` compare equal (PHP cannot tell
them apart), integers and floats do not. The PHP harness freezes only the rate limiter's clock and
generates RSA keys per process; the Go harness mirrors that, so timestamps and tokens rely on the
normalizer's masks. Every response header except `Date`, `X-RateLimit-Reset`,
`X-RateLimit-Remaining` and `Retry-After` is compared, so the server must not add headers PHP does
not send (e.g. `Content-Length` is stripped by the harness transport, not by the server). The route
coverage check moves to the pipeline package (it needs the router).

## 8. 2026-11-20 — Manifest loader is stricter than PHP's

Go rejects duplicate route names (not only duplicate method + path) and duplicate YAML keys; `regex:`
rules compile to Go regexps at load (PHP's `$` semantics kept; a pattern RE2 cannot compile, such as
lookbehind, fails at load instead of at request time); errors carry file and field. No process
cache: `Load` is called once per graph. `domain.class` is read only for the exports. Open: the
OpenAPI `info.title` still says "Polaris for PHP" to match the goldens; switch to "Polaris for Go"
(and mask it in the golden test) when the Go server first publishes its document.

## 9. 2026-11-20 — Config and support packages

- Durations are `time.Duration` (whole seconds); start from `config.Defaults()` — a zero `Auth` is
  invalid. Config errors list every problem at once with the env var / key and the fix.
- Cache is `Get/Set/Delete` on bytes (nothing upstream uses more of PSR-16).
- Rate-limit cache keys hash with FNV-128a instead of xxh128: PHP and Go instances do not share
  rate-limit buckets in a shared cache (the database is unaffected). `CacheStore` locks per key so a
  burst cannot overspend in one process.
- TOTP `Verify` folds into `Match(step, ok, err)`; an issuer containing `:` fails at startup.
- QR codes are SVG (`qr_svg`), drawn from go-qrcode's bitmap; bytes differ from PHP, masked by fixtures.
- `ValidE164` rejects a trailing newline (PHP's `$` accepted it); email masking keeps the first
  character, not byte, so non-ASCII addresses stay valid UTF-8.

## 10. 2026-11-20 — Store adapters

- DDL is byte-identical to PHP's `schema:export` (create and drop, three dialects; goldens in
  `testdata/ddl`); conformance suite verified on SQLite, Postgres 17, MySQL 8.4.
- Offset without limit: Postgres `OFFSET n`, MySQL `LIMIT 18446744073709551615` (PHP's `LIMIT -1`
  only worked on SQLite).
- memstore enforces primary keys and unique indexes (`store.ErrDuplicate`) and compares times as UTC
  seconds, like SQL, so it passes the same suite.
- `schema.Merge` also rejects two plugins defining the same table. Criteria keys are sorted, so one
  query always produces the same SQL. Identifiers are quote-escaped.
- `CreateSchema` does not seed the permission catalog; `authz` seeds right after it.

## 11. 2026-11-20 — Security and token primitives

- PHP's generator / parser / validator / factory classes are one `token.Codec` (`Issue`, `Parse`,
  `Verify`); key PEMs are parsed and checked once in `token.New`. The adapter-only paths
  (`fromCredentials`, `PolarisTokenValidator`) are not ported.
- Signing uses stdlib crypto, not go-jose: go-jose reorders JOSE header fields, and minted tokens must
  be byte-identical to PHP's for the same key, clock and claims (proven by vectors both ways).
- Stricter than PHP: libsodium's Ed25519 small-order / canonical checks are applied; inputs that crash
  PHP (TypeError, SodiumException → 500) return `ErrInvalidToken`; out-of-range dates are rejected;
  argon2 v=16 and bcrypt `$2x$` hashes never verify.
- As upstream: verification uses the active key only (the previous key only appears in JWKS); JWKS is
  RSA only. The JWKS endpoint must encode with PHP's JSON flags.
- `testdata/vectors/keys.json` holds test-only keys (not secrets); secret scanners may flag it.

## 12. 2026-11-20 — Route parameters win over body and query

Upstream merges route params first, so a body or query `id` overrides the path's `{id}`
(`array_replace`). Go applies route params last: an endpoint reading `id` always gets the path
value. No fixture sends a conflicting key; this only closes a confusion vector. Body, cookie and
query precedence is otherwise upstream's.

## 13. 2026-11-20 — Sessions and authorization

- One `session.Service` replaces `TokenService` + `SessionService`.
- **Refresh rotation is one transaction** (claim + new token insert); the losing request's family
  revocation commits separately. Upstream has a window where a losing concurrent refresh revokes the
  family before the winner's new token exists, leaving that token live. **Report upstream.**
- `RevokeFamily` is one conditional `UPDATE … WHERE family_id = ? AND revoked_at IS NULL` (already
  revoked rows keep their reason, a concurrent rotation cannot be overwritten).
- The gate takes `authz.Caller` (user, org, delegated + permissions) set by the bearer resolver, never
  read from token claims on the wire.
- Plugin permission contributions are maps: keys sorted per contribution; core order unchanged.
- Denylist watermark: decimal Unix seconds under upstream's key prefix. Resolver lists are `[]`,
  never nil. Upstream has 34 core events (the 35th file is the null dispatcher).
- Callers must `Auth.Validate()` before building the session service (the graph does).

## 14. 2026-11-20 — Pipeline

- A failing service (store, gate, denylist, factor lookup) answers 500 `{"error":"server_error"}` and
  is logged; upstream let the exception escape to the host.
- Cookie mode treats a request as HTTPS only when `r.TLS` is set (a client can fake `r.URL.Scheme`);
  behind a TLS-terminating proxy the host must set `r.TLS` (or wrap the handler to do so).
- Step-up checks `auth_time` before the factor lookup (same outcome, one query fewer); the
  terminal 405 carries `Allow`. Upstream's `bodyDelivery` switch waits for the MCP port.
- Bearer resolvers return `token.NewPrincipal(claims)`; delegation is attached in-process with
  `(*token.Token).Delegate(perms)` and is never read from JWT claims (upstream honoured a
  `delegated` claim on any verified token).

## 15. 2026-11-20 — Identity

- One `identity.Service` replaces registration, verification, login, password reset and user admin
  services; `RepositoryIdentityProvider` is not ported (its only consumer was dropped in #11).
- Login returns the `login_mfa` ticket plus the confirmed factor rows; the endpoint renders the
  masked factor views.
- Reset tokens are consumed with a conditional UPDATE (single use under concurrency; upstream raced).
  Multi-row writes (register, verify, resend, forgot, reset, login + session insert, anonymize) are one
  transaction each.
- Failed-login counting is atomic (upstream's read-modify-write lets concurrent wrong passwords
  undercount and slip under the lockout). A concurrent duplicate registration takes the
  anti-enumeration path instead of a 500.
- `ErrInvalidCredentials` maps to 401 on login, 403 on password change (as upstream).

## 16. 2026-11-20 — MFA

- One `mfa.Service` replaces ~10 PHP classes, including upstream's `Identity\MfaLoginService` and
  `StepUpService` (they are MFA in Go).
- Plugin factor types are validated in `mfa.New` (core name, duplicate, nil, empty name fail at
  startup; upstream failed on first verification).
- Single-use checks always go through the database's conditional updates (upstream had an unchecked
  in-memory shortcut); the TOTP time step is claimed with a conditional update too, so one code cannot
  pass twice concurrently (upstream: read-then-write race).
- OTP send budgets are JSON in the cache under a per-process lock: PHP and Go do not share budgets in
  a shared cache. TOTP enrolment builds the URI and QR before writing, so a bad label leaves no row.
  OTP length and max attempts must be ≥ 1.

## 17. 2026-11-20 — Organizations

- One `orgs.Service` for organizations, members, invitations and roles; refusals are
  `*orgs.Error{Kind}` (+ `authz.Forbidden`) carrying upstream's wire message.
- Each write runs in one transaction with its checks; slug clashes are conflicts, duplicate role ids /
  permission keys are de-duplicated (upstream: 500 on a PK violation).
- `DeleteOrganization` revokes every member's sessions and dispatches `org.deleted` even if one
  revocation fails (errors joined); upstream stopped at the first and never sent the event.
- Invitation acceptance is a conditional single-use claim, and owner-changing writes serialize per
  organization, so concurrency can neither accept an invite twice nor leave an org with no owner
  (both raced upstream).
- The metrics listener counts core events only (upstream: the `Polaris\Event\` namespace).

## 18. 2026-11-20 — Plugins are optional interfaces; the graph is built eagerly

A plugin implements `ID()` plus only the hooks it has (`SchemaProvider`, `PermissionProvider`,
`ManifestProvider`, `Initializer`, `EndpointProvider`, `ListenerProvider`, `MiddlewareProvider`,
`BearerResolverProvider`, `MFAFactorTypeProvider`) — the `io.WriterTo` pattern, no base type.
Services are built once in `wiring.New` (a Go process is long-lived; upstream built lazily per PHP
request). A plugin builds its own services in `Init(g)` and reaches another plugin with
`g.Plugin(id)`. Factor types are collected before the MFA service exists, so the hook takes no graph.
The default event dispatcher has core's and plugins' listeners already subscribed.
`polaristest` boots a full server on SQLite for applications' own tests (upstream's
`polaris/testing` was only the in-memory adapter).

## 19. 2026-11-20 — Delegation is never a wire claim; Protect runs plugin middleware

The pipeline's "delegated credentials may not self-serve or step up" rule and the gate both read
`(*token.Token).Delegation()`, set only by a plugin's bearer resolver. No JWT claim named `delegated`
is honoured anywhere (upstream read it from any verified token). `Polaris.Protect` runs the plugins'
middleware after authentication, so an API key's own rate limit and headers apply on host routes too.

## 20. 2026-11-20 — Core endpoints validate inline, as upstream

Core's PHP endpoints check their input themselves with route-specific messages ("An email and
password are required.") that the fixtures record; the manifest's generic rule messages would not
match. Core endpoints therefore validate inline; plugin endpoints use `route.Validate`. Input reads
follow PHP's `(string)` cast and `trim()` (a JSON number becomes its text, `true` becomes "1").
`polaristest.WithSecrets` lets a test add a previous key for rotation.

## 21. 2026-11-20 — Audit and API keys

- `apikeys` works without `audit` (events still fire, nothing is recorded); upstream refused to boot.
  Keeps the one-line setup (spec §4.6).
- Audit hash chain: hashed JSON uses sorted keys with PHP escaping, so verification survives
  Postgres/MySQL re-ordering JSON (upstream could report false tampering there); PHP-written rows
  verify through their stored text. Chain writes are serialized per process. **Open:** writers in
  separate processes can still fork the chain (as upstream); closing it needs a database lock without
  changing the schema. **Check:** PHP verifying a chain Go wrote.
- Key rotation is a conditional update (two racing rotations cannot both create a successor).
- Audit queries with `from` and `to` push the upper bound to the database (upstream returned short
  pages). Dates are ISO 8601 only (PHP also took "yesterday").
- `audit:prune` / `audit:verify` are `Prune` / `Verify` methods until `cmd/polaris` exists.

## 22. 2026-11-20 — Core HTTP API complete; test speed

All 52 core routes are served and all 184 core fixtures replay (`TestEveryCoreFixtureHasAGoTest`,
`TestNoPendingRoutes` guard it). `DELETE /orgs/{id}` answers 200 once the soft delete committed even
if a member's session revocation then fails (logged). `wiring.Config.Hasher` is optional (default
`security.Argon2id{}`, PHP's parameters); `polaristest` uses `Argon2id{Memory: 1024, Time: 1}` so the
race suite runs in ~40 s instead of ~4 min — same PHC format, verifiable by any parameters.

## 23. 2026-11-20 — OAuth provider

- Operator checks on the `/admin/oauth` routes go through `oauth.Config.Operators`; until wired to
  `plugins/admin`, holders of core's superadmin role act as instance owners. **To do:** switch to the
  admin plugin's operator check once it lands.
- Outbound fetches (CIMD, `jwks_uri`) refuse non-public addresses at connect time and never follow
  redirects, even with a host-supplied client (upstream checked the resolved host only).
- Refresh rotation (claim + new tokens) and client deletion are one transaction each; DPoP and client
  assertion `jti` replay checks are serialized per process (multi-replica replay protection relies on
  the cache, as upstream).
- Only compact JWS is accepted; RFC 7638 thumbprints hash the raw members as upstream; go-jose parses
  keys and verifies signatures, core's codec mints (byte-compatible access and ID tokens).
- `PollInterval < 0` disables the device-flow throttle; `DisableClientIDMetadata` turns CIMD off;
  `BaseURL` defaults to issuer + path prefix; config errors are returned from `Init` naming the field.
- Admin routes use the admin plugin's `AuthorizeOperator` ("read" to list, "own" to create/delete);
  core superadmin applies only without an admin plugin. `oauth.Event` implements `audit.Auditable` and
  the plugin adds its names to the audit catalog.
- **Data departure (to fix):** a client created by an operator API key stores `created_by` null;
  upstream stores the key id. Needs admin to expose the operator principal id to non-importers.

## 24. 2026-11-20 — MCP tools hook in wiring; embedded JSON compared decoded

- `wiring.ToolProvider` / `Tool` / `ToolResult` let any plugin (agents' capabilities) add MCP tools
  without importing `plugins/mcp`: no plugin imports another for types.
- `pipeline.DeniesDelegate` is exported so the MCP server lists tools by the same delegate rule as the
  pipeline enforces.
- The fixture normalizer compares a string that is exactly one JSON value decoded (MCP tool results
  carry the route's JSON as pretty-printed text; key order is not contractual, #4).
- Polaris's MCP server speaks JSON-RPC directly: the official go-sdk drops `isError:false`, rewords
  "Tool not found", sorts tools and adds headers, all of which the fixture freezes. go-sdk is used for
  the `mcp.Protect` example around a host's own MCP server.

## 25. 2026-11-20 — Admin

- Other plugins reach operators without importing admin: `AuthorizeOperator(ctx, capability, orgID)`
  and `IsOperator(ctx, credential)` on `*admin.Plugin`, found by type-asserting `g.Plugin("admin")`.
  A plugin's own route tagged `[admin, …]` gets the operator resolved by admin's middleware.
- `admin.New` without the audit plugin fails with the fix in the message (registration order free).
- Stricter than upstream: an operator's access token is checked against the denylist when enabled;
  member-role changes lock the organization row first (as core, #17); MFA reset is one transaction;
  `filter` must be a JSON list; allowlist bit counts must be integers; dates ISO 8601 only.
- `ip_allowlist` is stored with escaped slashes, byte-identical to PHP.
- **Open:** two concurrent first operator grants for one user can both insert on Postgres/MySQL
  (upstream's schema has no unique index on `user_id`). `admin:key` / `admin:grant` are the
  `Keys()` / `Grants()` services until `cmd/polaris` exists.

## 26. 2026-11-20 — Go agent SDK

- `agent.New(ctx, url, opts...)` discovers; keys (ES256, EdDSA) import/export in the PHP SDK's stored
  form both ways. PHP's server verifier accepts Go-signed request JWTs and client assertions
  (`agent/testdata/interop.php`); Go verifies PHP-signed receipt chains; the hash vector shared by the
  PHP and TS SDKs matches.
- Go-first: network failures are wrapped Go errors (no `transport_failed` code); waiting is cancelled
  through the context (no callback, no `maxAttempts`); typed responses (zero interval/expiry read as
  upstream's defaults 5 s / 600 s); receipts require a `kid` (as PHP; TS tries every key); `Do(req)`
  signs any request (Go-only). No stream client, no route generator.
- **To do:** the end-to-end walkthrough against the Go server once `plugins/agents` lands.

## 27. 2026-11-20 — MCP

- `mcp.Protect(next, mcp.ProtectConfig{…})` protects any Go MCP server, standalone (remote issuer:
  JWKS over https, cached 1 h, refetched for an unknown kid at most once a minute) or in-process;
  serves RFC 9728 metadata; `mcp.Claims(ctx)` reads the verified token.
- Polaris's own `/mcp` serves the 2026-07 profile only; `ProtectConfig.AllowLegacy` lets the 2025
  session protocol through to an external server.
- Tool arguments are not schema-checked by the MCP layer; the route's own 422 comes back as an error
  result (one validator, the route's).
- Inner tool calls keep the caller's IP (upstream used "unknown": every MCP caller shared one per-IP
  rate-limit bucket). DPoP `htu` is checked against the configured resource origin, not `Host`, so it
  works behind a proxy.
- `polaris://schema` exists only when `Config.Schema` is set (keeps SQL drivers out of services that
  only use `Protect`). `serverInfo` still reads "Polaris for PHP" 0.10.0 because the fixture freezes it.
- `mcp.ServeStdio` takes `*polaris.Polaris`, so this plugin imports the root package for hosting; the
  root never imports plugins, so there is no cycle.
- **Open:** the body-mode pipeline for `/mcp` is built from a shallow copy of the graph (a pipeline
  option for token delivery would be cleaner); `tools/list` has no pagination; DPoP/assertion `jti`
  replay is cache get-then-set, racy across processes as upstream — add an atomic add-if-absent to
  `cache.Cache` in the security pass.

## 28. 2026-11-20 — Agents

- Host integration: `agents.New(agents.Config{Capabilities: …})`; a capability is a Go func
  (`Handler`) or a host route (`Location`) guarded by `ag.Protect(name, h)` / `ag.Guard(mux)`, checked
  before the handler runs; the handler reads `agents.CallFrom(ctx)`; responses carry
  `X-Polaris-Receipt`. `ag.DiscoveryHandler()` serves `/.well-known/agent-configuration` at the root.
  Capabilities are MCP tools through `wiring.ToolProvider`.
- Every upstream check is kept (request JWT exact `aud`, single-use `jti`, ≤ 300 s, `htm`/`htu`/
  `body_hash`, no key headers, alg matches the key; confused-deputy subject check; constraints and
  budgets; approval strengths and owner permissions; kill switch in one transaction; receipts signed
  with `Codec.Sign` and hash-chained).
- Races closed beyond upstream: executing a budget-less grant re-claims it conditionally (a revoke
  cannot race it); a decision is conditional on the approval not having expired; a receipt sequence
  collision answers 409.
- No JSON Schema dependency: a validator for the keyword subset upstream's capabilities use, with
  opis's messages; an unsupported keyword fails `New`; `format` is not checked; `pattern` is RE2
  (PCRE-only syntax refused).
- Audit optional; admin auto-detected (`AuthorizeOperator`), without it `/admin/agents` answers 401.
  Constraint violations sorted by field. A departing member's agents go through the full kill switch
  (also emitting `agent.receipt.sealed`). Guarded responses are buffered until the receipt commits.
  The called URL is read from `RequestURI`, so it survives `http.StripPrefix`. An agent token is
  honoured only on principals a bearer resolver delegated.
- The Go SDK walkthrough runs against this server in-process (`TestTheGoAgentSDKWalksThrough`).

## 29. 2026-11-20 — Integration surface (spec §4.6)

`polaris.FromEnv(db, plugins...)` builds a Config from the environment; `(*Polaris).Migrate(ctx)`
creates missing tables (never altering existing ones) and seeds the catalog, idempotent at every boot;
`Config.Permissions` declares the host's own permissions (joined to the catalog like a plugin's);
`llms.txt` is the one-page integration guide, every identifier in it checked against the code;
`TestQuickstart` runs the copy-paste path end to end.

## 30. 2026-11-20 — Agent sign-in proven end to end (WP5 acceptance)

Both agent SDKs complete the walkthrough against a Go server: the Go SDK in-process
(`TestTheGoAgentSDKWalksThrough`), and upstream's unmodified `@polaris-auth/agent` e2e
(`e2e/walkthrough.e2e.ts`: register and verify the owner, organization, host, enrolment, grants,
execution, receipts) against `internal/e2e/agentserver` — passed on the first run, no server change
needed. Rerun: `scripts/e2e-agent-ts.sh`. Closes the to-do of #26.

## 31. 2026-11-20 — Security pass 1: replay, body limits, approval cap

- `cache.Cache.Add(ctx, key, value, ttl) (added bool, err error)` — atomic add-if-absent (Redis
  `SET NX PX`, Memcached `add`; host caches must make it atomic across replicas). Every `jti` /
  DPoP / client-assertion replay check uses it, so a proof is accepted once across all replicas
  (closes the opens in #23 and #27; upstream was get-then-set). Per-process locks removed.
- Routed request bodies are read up to `Config.MaxBodyBytes` (default 1 MiB, negative = unlimited);
  above it 413 (core envelope on core routes, problem on plugin routes), chunked bodies included.
  `agents.Config.MaxBodyBytes` (default 1 MiB) bounds `Protect`/`Guard`. **Behaviour change:**
  `/mcp` messages over 1 MiB (upstream allowed 4 MiB) get 413 unless the host raises the limit.
- Grant requests lock the agent row first: the pending-approval cap holds under concurrency and the
  same grant cannot be created twice.
- Clients created by an operator API key store the key id in `created_by` (admin `OperatorID(ctx)`),
  as upstream (closes the data departure in #23).
- `Graph.Pipeline(endpoints, wiring.WithBodyDelivery())` replaces the graph copy behind `/mcp` (#27).

## 32. 2026-11-20 — Plugins may serve core ports

`wiring.PortsProvider` (`Ports() Ports{Mailer, SMS, Breaches}`) lets a plugin (messaging, sentinel)
serve core's mail, SMS and breach-check ports when `Config` leaves them nil — upstream's plugin "port
rule". Precedence: `Config`, then the first plugin in registration order, then the defaults (log
drivers; HIBP when `Auth.Password.BreachCheck`, else none). `polaristest.WithoutRecorders()` leaves
the ports to plugins.

## 33. 2026-11-20 — Passwordless, username, anonymous, multi-session

- All four ported; every upstream fixture replays. Zero values mean upstream's defaults
  (`DisableSignUp`, `SkipMFAGate` invert upstream's flags); `BaseURL` defaults to issuer + prefix.
- Races closed beyond upstream: hand-off code taken once via `cache.Add`; a resend is one transaction
  (one live code); verification / dropped password conditional (event once); concurrent sign-ups
  re-read the account; reset updates the password and revokes sessions in one transaction; a
  unique-index clash answers `phone_taken` / `taken`, not 500; concurrent conversions run `OnConvert`
  once; a multi-session switch claims the old session conditionally (one of N wins).
- A failed delivery of a link or code is logged and still answers 202 (known and unknown addresses
  look the same). `data` columns are written with PHP's JSON escaping (byte-identical). Usernames use
  a Go regexp and `strings.ToLower` (not `mb_strtolower`: differs only on non-ASCII case folding).
- `OnConvert` errors answer 500. Multi-session records devices only on routes that open or refresh a
  session; a failed device write is logged and the sign-in still answers, without the device header
  (upstream answered 500).
- **Open (as upstream):** if ending a guest fails after `OnConvert` ran, its sessions stay live and a
  retry answers `not_a_guest`; erasing a user leaves its username / phone rows; a passwordless
  sign-in and an MFA factor on the same channel satisfy the gate with one channel; mail scanners can
  spend magic links. Anonymous pruning is `Prune(ctx)` until the CLI wires it.

## 34. 2026-11-20 — CLI

`cli.Run(ctx, p, args, stdout, stderr)` runs the commands over a host's own instance (replaces
upstream's `--bootstrap`); `cmd/polaris` is the standalone binary (env + `.env`, `--dsn` /
`DATABASE_URL`, `--plugins` / `POLARIS_PLUGINS`). Every command is idempotent with `--json` and a
remedy on failure. `schema:export` and `manifest` match upstream byte for byte. Departures:
`schema:create` = `migrate` (creates only missing tables; upstream failed when tables existed);
`admin:key` refuses an existing name (a retry cannot mint a second live key); `init` writes
`AUTH_ISSUER` (default `http://localhost:8080`) when missing; `--bootstrap` / `--dir` dropped; `mcp`
also exposes `schema:export`, `schema:diff`, `manifest`, `doctor` as tools, as upstream.
**Open:** `keys:generate --alg=EdDSA` prints raw base64 keys, but `config.FromEnv` only reads RS256
PEMs — EdDSA through the environment needs the upstream env format checked and wired.

## 35. 2026-11-20 — Social and passkey

- Every upstream fixture replays (social 4/4, passkey 1/1). Configuration errors (missing client id,
  unknown provider, bad Apple key, bad origins) fail at `polaris.New`. Social works without audit.
- **WebAuthn is implemented directly** (a small CBOR decoder + ES256/RS256 verification), not with
  go-webauthn (its dependency tree was not in go.sum when ported). Stricter than upstream: cross-origin
  ceremonies refused, the BE flag may not change, RSA keys ≥ 2048 bits, conditional sign-count update.
  **WP8: fuzz the CBOR decoder and attestation/assertion parsing, and review against go-webauthn's
  checks (or switch to it).**
- ID tokens are verified with go-jose reproducing firebase/php-jwt (kid required, key alg must match,
  60 s leeway, one key-set refetch on an unknown kid); go-oidc / x/oauth2 not used (no leeway control,
  no Microsoft issuer pattern, different token request handling) — drop them from go.mod at tidy.
- Social state, hand-off outcomes (they hold session tokens) and passkey challenges are single-use
  via `cache.Add` and encrypted with core's encrypter. The proxy callback no longer copies cookies into
  the forwarded URL. Multi-row writes are one transaction; unique clashes answer 409
  `account_linked` / 422 `credential_invalid`. Cache keys hash with SHA-256 (upstream xxh128).
- Config zero values: `DisableSignUp`, `SkipMFA`, `NoMFAFactor`, `NoPKCE`, `BasicAuth`;
  `TrustedProviders` nil means google and apple.
- **Open (as upstream, WP8 review):** unlinking the last credential is not transactional; a link
  started in one browser can be completed in another.

## 36. 2026-11-20 — Messaging and sentinel

- Messaging serves core's Mailer and SMS through `PortsProvider` (#32); channels SMTP (net/smtp,
  replaces Symfony Mailer / PHPMailer; audit `channel` value `smtp`), Twilio, Vonage, generic HTTP
  SMS, log, memory. Works without audit. Quiet mode matches recipients case-insensitively (upstream
  compared raw addresses, so mixed case escaped it).
- Sentinel imports `plugins/admin` (its routes are admin routes; upstream depends on admin too) — the
  one plugin-to-plugin import. The attempt travels in the request context. Velocity counters use a
  `CounterStore` on the cache (the rate store cannot reset or report reasons); not exact across
  replicas, as upstream — a host can plug Redis `INCR`. A missing `DisposableListFile` fails `New`
  (upstream used an empty list); `RefreshDomainList` needs a target file (the bundled list is
  embedded). Failing to record a decision answers 500; a failing signal is skipped (fails open, as
  upstream). IP rules are read per guarded request. The guard reads form bodies too and sets the device
  cookie when the response starts.
- No MaxMind dependency: `GeoResolver` is an interface (`NoGeo` default).

## 37. 2026-11-20 — SCIM

SCIM 2.0 server per organization ported; all 3 upstream fixtures replay (coverage test guards them),
filter parser fuzzed (`FuzzFilter`). Audit and admin optional (without admin the `/admin/scim` routes
answer 401). Filters accept the subset directories send (`attr eq|co|sw "value"` joined by `and`),
anything else `invalidFilter`, as upstream. Built-in owner/admin/member roles take members but are
never renamed or deleted. (The porting agent was stopped at the pause before reporting; departures
beyond these to be confirmed in the WP8 review.)

## 38. 2026-11-20 — SECURITY: SCIM connections were global account takeover (fixed; report upstream)

**Severity high, present in upstream `polaris/scim`** (`Users.php` create / rename / setActive). A
SCIM bearer for organization A could: join any existing account (even the owner of org B) to A by
`POST /Users {userName: victim}` and overwrite its name; `PATCH userName` to change the victim's
**global** email, then reset the password to take over the account and every org it holds;
`active:false` disabled the user globally. Go behaviour (deliberate departure):
1. Global profile/status writes only for users this connection created that belong to no other org;
   otherwise SCIM acts on the membership in A only.
2. An existing account is linked (membership only) only when its email domain is a verified domain of
   A (`plugins/sso`); otherwise 409 `uniqueness`.
3. `active:false` suspends the membership in A (revoking A's sessions), never a global disable;
   delete-deprovisioning anonymises only rule-1 users, else removes the membership.
4. Group writes on the built-in owner role go through the last-owner guard (#17).
**Action for the owner:** report to polaris-core (same fix applies).
**Severity raised to critical (#38):** any registered user can create an organization and, as its
owner, a SCIM connection (`POST /orgs/{id}/scim/connections`), so before the fix anyone could take
over any account. "Created by this connection" needs no schema change: the connection's provenance
row and the user row are written in one transaction with one timestamp, and a user counts as created
by the connection when both exist with equal `created_at`. The sso plugin answers
`DomainVerified(ctx, organizationID, domain)` for rule 2.

## 39. 2026-11-20 — SECURITY: social login/link CSRF; cookies out of endpoint input

- **Medium, present upstream:** social state lived only in the cache, unbound to the browser that
  started the flow, so an attacker could have a victim complete the attacker's sign-in (session
  fixation) or link the victim's provider identity to the attacker's account (later "Sign in with
  Google" by the victim opens the attacker's account). Go binds the flow to the browser with a
  `__Host-` (on HTTPS) HttpOnly SameSite=Lax cookie holding a nonce stored in the state entry,
  compared in constant time at the callback; otherwise `state_invalid`. The added `Set-Cookie` and
  the callback's cookie requirement are recorded as known changes against upstream's social fixtures.
  **Report upstream.**
- `endpoint.NewInput` no longer merges cookies into input (upstream: body < cookies < query), so a
  cookie tossed from a sibling subdomain cannot override body fields; endpoints that need a cookie
  read it explicitly. (Refines #12.)
- `social.Config.TrustedProviders` documents that a provider treating any returned email as verified
  must never be trusted for linking by email (defaults google, apple are safe).

## 40. 2026-11-20 — EdDSA keys; dependency and doc corrections

- EdDSA keys via the environment are the raw libsodium bytes as upstream reads them, or their base64
  (Go-only; an environment variable cannot hold a NUL byte and PHP's `trim` can cut edge bytes);
  `keys:generate --alg=EdDSA` prints base64. The signer stays code configuration
  (`cfg.Auth.AccessToken.Signer = config.SignerEdDSA`), as upstream. Upstream's JWKS route fails
  under EdDSA (RSA-only renderer); Go publishes Ed25519 keys as RFC 8037 OKP JWKs and every JWKS
  consumer in the repo accepts them (closes #34's open item).
- Corrections to earlier entries: the CLI now exists, so the commands #21 (`audit:prune` /
  `audit:verify`), #25 (`admin:key` / `admin:grant`) and #33 (`anonymous:prune`) say are missing are
  served by `polaris`; #35's `x/oauth2` stays (the MCP go-sdk needs it); go-oidc and go-webauthn are
  dropped by `go mod tidy`.
- Dependencies added outside spec §5's list: `github.com/beevik/etree` and
  `github.com/russellhaering/goxmldsig` (XML canonicalization and signature verification for SAML,
  `plugins/sso`); `github.com/modelcontextprotocol/go-sdk` (spec §5 listed it; used by the
  `mcp.Protect` example).
- `llms_test.go` keeps every `llms.txt` snippet compiling; per-plugin READMEs are checked against
  `go doc`.

## 41. 2026-11-20 — MySQL: passkey credential ids are ASCII (upstream bug)

Upstream's passkey schema (`credential_id VARCHAR(1024)` with a unique index) cannot be installed on
MySQL 8.4 under utf8mb4 (4096-byte key > 3072-byte limit: error 1071) — the passkey plugin never
worked on MySQL upstream. Credential ids are base64url, so on MySQL only the column is declared
`CHARACTER SET ascii COLLATE ascii_bin` (1024-byte key; case-sensitive uniqueness as base64url
requires). Type, length and data are unchanged, so PHP reads and writes the same rows; PostgreSQL and
SQLite DDL stay byte-identical. Report upstream. The matrix run also found and fixed a Go bug on
MySQL (`clientFoundRows`: affected-row counts for unchanged rows broke conditional updates).

## 42. 2026-11-20 — Security review (WP8) results

- Fixed with regression tests: the SCIM takeover (#38; ownership = provenance row with the user's
  `created_at`, linking only on an sso-verified domain via `DomainVerified`, membership suspension,
  owner guard `orgs.KeepOwner`; `plugins/scim/takeover_test.go`); social login/link CSRF (#39) — the
  binding cookie is `__Host-`, HttpOnly, Secure, **SameSite=None** on HTTPS because Apple's
  `form_post` callback is a cross-site POST that would drop a Lax cookie (the cookie only proves the
  browser holds the nonce), Lax over plain http; 11 social fixture steps record the added
  `Set-Cookie` in `contracttest.knownHeaders`; `mcp.Protect` refuses tokens with a `purpose` claim
  and any `typ` other than `at+jwt` / `JWT` / none (a password-only login-MFA ticket was accepted
  where the issuer was also a configured audience); passkey RSA keys checked by modulus bit length
  (≥ 2048) and odd exponent ≥ 3; social `TrustedProviders` warns against facebook, x, notion, kick.
- Checked clean: constant-time / hashed-lookup secret compares; single-use refresh, codes and
  challenges; exact OAuth `redirect_uri`, S256-only PKCE, codes bound to client and redirect;
  delegated permissions intersected at use; impersonation tokens never operators; client IP from
  `RemoteAddr` only; bounded outbound reads; dummy hash for unknown users; passkey type, origin,
  crossOrigin, rpIdHash, UP/UV, BE/BS, AT flag, credential-id length, counter, alg allow-list,
  "none"-only attestation.
- Fuzz targets (≥ 60 s each, no crashes): token `FuzzParseRaw`, `FuzzSignedClaims`; passkey
  `FuzzCBOR`, `FuzzAuthData`, `FuzzCOSEVerify`, `FuzzCredential`, `FuzzAssertion`; `FuzzDPoPProof`
  (oauth, mcp); agents `FuzzRequestJWT`; endpoint `FuzzInput`; pipeline `FuzzCookieCSRF`; scim
  `FuzzPatch`, `FuzzFilter`.

## 43. 2026-11-20 — SSO (and a second upstream takeover)

- `plugins/sso` ported; all 3 upstream fixtures replay; SAML via crewjam/saml + goxmldsig (every
  php-saml check plus stricter ones: exactly one assertion per response; AudienceRestriction,
  Destination and matching InResponseTo required; response IssueInstant within 90 s; 180 s skew on
  conditions; only signed LogoutRequests); assertion ids single-use via `cache.Add`; OIDC with PKCE
  S256, state, nonce, ID token verified against the provider's JWKS (60 s leeway, one refetch on an
  unknown kid); outbound HTTP to public addresses only, no redirects. Fuzzed: `FuzzSAMLResponse`,
  `FuzzMetadata`, `FuzzLogoutRequest`.
- **SECURITY, present upstream:** an organization's IdP could sign in to **any existing account**
  (same class as #38: any user can create an org and configure an IdP), and an IdP LogoutRequest could
  end any account's sessions. Go signs in an existing account only if it is already a member of that
  organization or its email domain is verified for it, and IdP logout ends members' sessions only.
  **Report upstream with #38.**
- A PATCH without `config` no longer re-encrypts the stored client secret (upstream bug). OIDC works
  without extra configuration; audit optional; stored `attributes` keys sorted. As upstream, an
  expired IdP certificate still verifies (IdPs rotate late; trust is the configured certificate).
- `DomainVerified(ctx, orgID, domain)` serves SCIM's linking rule (#38).

## 44. 2026-11-20 — Shared SSRF guard; CLI plugin list; EdDSA JWKS done

- `internal/netguard` (`PublicAddr`, `Control`, `Client`, `NoRedirects`) replaces the copies in
  `plugins/oauth` and `plugins/sso`: every tenant- or client-supplied URL is fetched only from public
  unicast addresses, decided after DNS resolution, never following redirects.
- `cmd/polaris --plugins` knows every plugin that works with zero configuration: audit, admin,
  apikeys, oauth, agents, mcp, anonymous, username, multisession, passwordless, messaging, sentinel,
  sso, scim (social and passkey need provider / relying-party settings: build your own binary with
  `cli.Run`). Smoke-tested: `init` → `migrate` (210 routes; idempotent) → `doctor` "Polaris is ready".
- Ed25519 keys are published as RFC 8037 OKP JWKs; `mcp.Protect` in-process reads the graph's JWKS;
  the Go agent SDK walkthrough runs on RS256 and EdDSA (#40).
- Sentinel's flaky test: velocity buckets are `now / 600 s` on the system clock, so a run crossing a
  boundary split its counts; the test freezes the counters. Production buckets behave as upstream.

## 45. 2026-11-20 — Database matrix (WP8)

memstore, SQLite, PostgreSQL 17 and MySQL 8.4 all run the suite via `scripts/test-db-matrix.sh`
(`store/storetest.Backends()`; `polaristest` picks `POLARIS_TEST_DB` / `WithDialect`). The race fixes
of #13, #15–#17, #28, #31, #33, #35 hold on all four. Found and fixed on MySQL: `UPDATE` reported
*changed* rows, so a conditional update rewriting identical values returned 0 (an agent execution in
the same second as the previous one silently did nothing) — `sqlstore.Open` forces
`clientFoundRows=true`; host pools passed to `sqlstore.New` are checked. `schema.Field.ASCII`
(`AsASCII()`) emits `CHARACTER SET ascii COLLATE ascii_bin` on MySQL only (#41), also applied to
case-sensitive external identifiers (social `provider_account_id`, …) that MySQL's default collation
would match case- and accent-insensitively. PG/MySQL return JSON columns normalized; tests compare
JSON decoded.
**#45 addendum:** case-sensitive external identifiers use `AsCaseSensitive()` (MySQL `utf8mb4_bin`):
social `provider_account_id`, every oauth `client_id` column (tests fail without it on MySQL). A
host pool given to `sqlstore.New` on MySQL is probed once per store on its first top-level write;
without `clientFoundRows=true` writes fail with `sqlstore.ErrMySQLFoundRows` naming the fix (if the
probe cannot run, e.g. no `CREATE TEMPORARY TABLES` grant, it retries on later writes). PostgreSQL:
the whole race suite passes; MySQL: every package that compiled passed — final rerun after WP9.

## 46. 2026-11-20 — WP9: the Go developer surface

Hosts import only package `polaris` (+ plugin constructors, `store/sqlstore`, `polaristest`,
`agent`, `mcp.Protect`, `telemetry/otel`). `PrincipalFrom(ctx)` returns a `Principal` value; its
kind comes from `token.KindOf`, reading resolver claims only on in-process delegated principals.
`Protect` always resolves the caller's authority (one query per request). Every account is created
through `identity.InsertUser`, which runs `Hooks.OnUserCreated` in a savepoint of the creating
transaction (`TestEveryAccountIsCreatedThroughInsertUser` guards new paths; anonymous guests count
as accounts, conversion creates none); `OnUserDeleted` runs on erase, admin delete, SCIM delete,
guest prune and `Users().Delete`. `Hooks.Claims` refuses JWT/OAuth/OIDC names, every core and
plugin claim, `polaris*` names and names already present, at mint time. `sqlstore.WithTx` joins the
host's transaction (Polaris's own become savepoints; events fire before the host commits). The
programmatic API (`Users`, `Orgs`, `Sessions`, `Can`) acts as the trusted actor `system` with the
routes' checks, events and audit. `Graph` is read-only through accessors. `contracttest`, `httpapi`,
`upstream` (with its data, `internal/upstream`), `observe`, `maintenance`, `netguard` are internal;
`Polaris.Prune(ctx)` exposes the expired-row job. `Config.Middleware` wraps `Handler`/`Protect`
outermost; `Config.Listeners` joins the default bus. API.md states what is stable in v0.x.
Breaking (pre-1.0): `polaris.Principal`/`Authority` removed; Graph fields → methods;
`session.Service.Mint(ctx, …)`; an account created already verified sends no verification mail.

## 47. 2026-11-20 — Observability and quality bar (WP9 §4.7 items 6–7)

- `telemetry/otel` (otel v1.47, otelhttp v0.72) is the only importer of OpenTelemetry (`go list
  -deps` checked): `Middleware` (spans named by Polaris route; duration histogram by route and
  principal kind), `Store` (a span per adapter call, no values; passes `CreateMissing` through,
  `Unwrap()`), `Listener()` (`polaris.auth.outcomes`). It records no tokens, emails, values or error
  messages; the user id only as an HMAC with `WithUserIDHash(key)`. `endpoint.Observed` lets
  outermost middleware see the route and principal.
- golangci-lint v2.15 (`.golangci.yml`, every exclusion and `//nolint` with a reason), `make lint`
  in `make qa`; govulncheck via `scripts/govulncheck.sh` with one reviewed ignore: GO-2026-6909
  (crewjam/saml; the record covers all versions but describes v0.5.1 — `TestSAMLGO20266909` signs
  responses exercising both conditions and the plugin refuses them; re-review on every upgrade).
  `toolchain go1.26.11` pins a standard library with the 18 reported fixes.
- CI (`.github/workflows/ci.yml`): `make qa` + coverage artifact, `make vuln`, and the database
  matrix on postgres:17 and mysql:8.4 services. Benchmarks in `docs/benchmarks.md`.

## 48. 2026-11-20 — Lazy authority in Protect

`Protect` without permissions no longer queries the database: it stores a once-per-request resolver
(`endpoint.WithLazyAuthority` / `endpoint.ResolveAuthority`), and `PrincipalFrom` resolves roles and
permissions on first use. `Protect` with permissions and the route authorization step resolve
eagerly and seed the same cache, so a request resolves at most once
(`TestProtectResolvesTheAuthorityLazilyOnce`). If a lazy resolution fails it is logged and
`PrincipalFrom` returns `ok=false`. `BenchmarkProtect`: JWT 376 → 124 allocs, API key 597 → 345.
Supersedes the "one query per request" note of #46.

## 49. 2026-11-20 — Public, renamed `univeros/polaris.go`; disclosure first

The owner's rule: Polaris is public at every level, and its website will document the Go version
next to the PHP one. Replaces #3: the repository is `univeros/polaris.go` (module
`github.com/univeros/polaris.go`, package `polaris`), MIT, public. It stays private only until
polaris-core ships the fixes for #38 (SCIM takeover), #39 (social CSRF) and #43 (SSO takeover), so
no exploit is public before its patch; then it flips public and `scripts/protect-main.sh` protects
`main` (branch protection needs a public repository on the org's plan). The pre-push "private
only" hook is removed; `GOPRIVATE` is needed only during the private window. `v0.1.0` was tagged
under the old module path before the rename; releases start at `v0.1.1`.

## 50. 2026-11-20 — Upstream patched (polaris-core 0.12.1); disclosed; re-synced

- polaris-core 0.12.1 (`39ce83a`, tag `v0.12.1`; Packagist, npm `@polaris-auth/client` 0.12.1)
  ships the fixes for #38 (SCIM takeover), #43 (SSO takeover) and #39 (social login/link CSRF).
  Advisories on `univeros/polaris-core`: GHSA-vr39-7fjx-jx56 (scim), GHSA-m3cr-x84p-2jq6 (sso),
  GHSA-pf6x-vg8c-q5fq (social); CVEs requested. Every polaris.go tag from `v0.1.0` contains the
  fixes. The private window of #49 ends: the repository is public and the exploit details in #38,
  #39 and #43 may be public.
- `internal/upstream` re-synced to `v0.12.1`. Only social fixtures changed: the start and link
  steps record the binding `Set-Cookie`, so the known-header override of #39 is gone and the replay
  compares the recorded header. New fixture `testAFlowCompletesOnlyInTheBrowserThatStartedIt`
  replays (`contracttest.Client.ForgetCookies` is the PHP harness's `$this->cookies = []`).
- Fix, found by the re-sync: the binding cookie's `__Host-` prefix, `Secure` and `SameSite=None`
  followed the connection (`r.TLS`); upstream follows the scheme of `baseUrl`. Behind a
  TLS-terminating proxy Go set a `SameSite=Lax` cookie, which Apple's cross-site `form_post`
  callback does not carry, so Apple sign-in failed with `state_invalid`. Go now follows
  `Config.BaseURL` (`TestTheBindingCookieFollowsTheBaseURLNotTheConnection`).
- CI no longer sets `GOPRIVATE`.

## 51. 2026-11-20 — API stability: narrow Graph services, stable host interfaces, apidiff guard

- **Breaking (pre-1.0):** `wiring.Graph`'s `Identity`, `Sessions`, `MFA`, `Orgs`, `Denylist`,
  `Catalog`, `Resolver`, `Gate`, `Principals` and `Pepper` return narrow interfaces declared in
  `wiring`, holding only the methods the plugins call (inventoried with `go/types` over `plugins/`,
  `agent/`, `cli/`; `mfa.Service.HasConfirmedFactor`, passed into an agents interface, was found by
  the compiler). `Escalation` and `Tickets` leave the SDK: no plugin used them. The concrete method
  sets are then free to change. Core (package `polaris`, `internal/httpapi`, `polaristest`) reaches
  the concrete services through `internal/services.Of(g)`, bound by `wiring`'s `init`.
  `TestGraphAccessorsReturnOnlyStableTypes` keeps every accessor on a stable type.
- Declared stable, unchanged: the host-implemented interfaces (`security.PasswordHasher`,
  `security.BreachedPasswordCheck`, `notify.Mailer`, `notify.SMSSender`, `clock.Clock`,
  `cache.Cache`, `ratelimit.Store` with `ratelimit.Result`, `metrics.Metrics`); packages `model`
  (rows, frozen with the database anyway) and `schema` (the table DSL a `SchemaProvider` needs);
  `telemetry/otel` (host surface, #47); and the types the stable signatures name, computed as the
  closure of the stable packages' exported API. `Graph.Repos` stays `*repository.Repos`; the
  repositories and `repository.Table` are stable as they are. `scripts/api-stable.txt` is the
  machine-readable list; API.md the prose.
- No package moved to `internal/`: every remaining public package is named by a stable signature,
  except `store/memstore` and `store/storetest`, kept public for hosts' tests and adapter authors.
- New tool `golang.org/x/exp/cmd/apidiff` (pinned pseudo-version in the Makefile, fetched with
  `go run`, never in `go.mod`). `make apicheck BASE=<ref>` and the CI job "API compatibility" on
  pull requests fail on an incompatible change to a listed name unless `decisions.md` gains a line
  containing "Breaking". Chosen over `gorelease`, which reports every package, the unstable ones
  included.

## 52. 2026-11-21 — MCP output schemas admit null (follows polaris-core)

polaris-core 0.12.2 moved `polaris/mcp` to `mcp/sdk` `^0.10` (0.8 is blocked by Packagist for
GHSA-f4rf-6ghj-mhr6). That SDK validates a tool result against its `outputSchema`, and the schema
is typed from each route's example, which cannot show which fields may be null (`GET /auth/me`
answers `display_name: null` against `"type": "string"`). Upstream's `ToolSchema::nullable()` lets
every inferred scalar also be null; `plugins/mcp` does the same (`nullable` in `tools.go`), so
`tools/list` publishes the same schemas and the re-recorded MCP contract fixture replays. The Go
server never failed the call (go-sdk does not reject it), but an MCP client validating the result
would have.

## 53. 2026-11-21 — Polaris for Go is its own product

The owner's direction: Polaris for Go is an auth system for Go (users and AI agents, everything an
auth system needs), not a port that tracks the PHP version. It no longer follows `polaris-core`,
and the two may differ; the PHP code is neither a reference nor a constraint.

- AGENT.md rules rewritten: Go first; the route specs are Go's own (edited with their endpoints);
  behaviour changes are deliberate (contract fixtures edited or re-recorded in the same PR, with a
  decision); stored data stays readable across releases; security-critical code stays careful;
  releases are milestones. Rules "upstream decides observable behaviour", "the wire, the database
  and the secrets are frozen [to PHP]" and "no feature work beyond upstream" are gone.
- `internal/upstream` becomes `internal/apispec` (package `apispec`): the embedded route specs and
  the contract fixtures, kept as Go-owned regression tests (`contracttest.Fixtures`). The fixture
  file names keep the test names they were recorded under. `scripts/sync-upstream.sh`, `make sync`
  and the `REF` pin are removed.
- Removed with the PHP cross-checks: `scripts/vectors.php`, `scripts/verify-vectors.php` and the
  `go-*.json` vectors written for them (the recorded vectors stay as known-answer tests),
  `agent/interop_test.go` with `testdata/interop.php`, and `scripts/e2e-agent-ts.sh` with
  `internal/e2e/agentserver` (the TypeScript agent SDK of the PHP project).
- Compatibility with the PHP version is no longer promised. What exists today still is compatible
  (same routes, tables and formats); it changes whenever a Go design is better, under rules 4 and 5.
- The port plan moves to `docs/history/port-spec.md`; this log moves to `docs/decisions.md`. Entries
  #1–#52 keep their wording: they record why things are as they are.

## 54. 2026-11-21 — Polaris for Go identifies as itself

What a client reads from the server said "Polaris for PHP" (#53 follow-up). Breaking, deliberately:

- MCP `serverInfo`: version is the running Polaris release, description "Polaris for Go: …" (was
  "0.10.0", "Polaris for PHP: …").
- The OpenAPI document (`polaris manifest --format=openapi`, the MCP schema resource): title "Polaris
  for Go", description "Authentication and authorization for users and AI agents.", version the running
  release (was "Polaris for PHP" 0.12.0).
- `/.well-known/agent-configuration` `agent_sdk_versions` names the Go agent SDK,
  `{"github.com/univeros/polaris.go/agent": <release>}` (was the PHP and TypeScript SDKs at 0.10.0).
- **Breaking:** `manifest.UpstreamVersion` is removed; the running release comes from
  `internal/version.Module()`, read from the build information (`runtime/debug.ReadBuildInfo`): the
  version of `github.com/univeros/polaris.go` the host requires, or "devel" when none is recorded
  (tests, a `replace`). Nothing to bump at release time.
- The MCP and agents contract fixtures and the OpenAPI goldens are edited to match.

## 55. 2026-11-22 — Host middleware, optional authentication, and `verify` for other services

Two things a Go service needs were missing from the host surface: middleware in the shape routers
chain, with optional authentication, and a way for another service, without the auth database, to
accept Polaris tokens.

- `p.Require(permissions...)` is `func(http.Handler) http.Handler`, exactly `Protect(next,
  permissions...)`. `p.Authenticate(next)` is Protect without permissions for a route open to
  everyone: no credential passes anonymous (`PrincipalFrom` reports false); a credential that does
  not verify, a resolver's refusal, a denylisted token, or a Bearer/DPoP header no resolver took is
  401, never downgraded to anonymous. Another scheme (a proxy's Basic credentials) is not a Polaris
  credential and passes anonymous. `Protect` is unchanged.
- A guard behind another guard that found a principal checks only its permissions
  (`pipeline.Protect`/`Authenticate` mark the request): `r.Use(p.Authenticate)` plus
  `r.With(p.Require("x"))` resolves the bearer and runs plugin middleware once per request, where
  nested Protects used to repeat them (an API key's rate limit was counted twice). Config.Middleware
  still wraps each guard.
- `polaris.RequireKind(kinds...)` and `polaris.RequireOrganization` read only what the principal
  already carries (no query): 401 without a principal, 403 otherwise. A step-up requirement was
  left out: it needs the pipeline's step-up check plumbed to host routes; no policy language.
- New package `verify` (stable, API.md §1): `New(Config)`, `Verifier.Verify(ctx, raw)`,
  `Verifier.Require(scopes...)`, `ClaimsFrom`, `Claims`, `ErrInvalidToken`, `ErrUnavailable`. It
  accepts session JWTs (typ JWT) and the oauth plugin's at+jwt tokens, RS256 or EdDSA only, and
  answers like the host (401 / 403 with the RFC 6750 challenge) plus 503 when the issuer's keys
  cannot be read, so an outage does not look like a bad token. With no `Audiences` it accepts only
  tokens without an aud (session tokens while AUTH_AUDIENCE is unset), the rule `token.Codec.Parse`
  applies; OAuth tokens need the service's resource in `Audiences`. A missing typ is refused (Polaris
  always writes one).
- Its documented limit: no revocation, denylist, disabled users, suspended memberships, agent kill
  switch or permission changes until the token expires; `Claims.Scopes` are the permissions at
  issue. The access token lifetime (AUTH_ACCESS_TOKEN_TTL, 15 min by default) bounds it; actions
  that must see a revocation at once go through the host's `Protect`.
- The verifier is shared, not duplicated: `plugins/mcp`'s token verifier and JWK Set cache moved to
  `internal/jwtverify` unchanged but for three settings: the algorithm allow-list, a typ-required
  switch, and the no-audience rule above (mcp keeps its list, accepts an absent typ, and always has
  its Resource as an audience; its refusal messages are the same). `mcp.Protect`'s tests and fixtures pass
  unchanged; `mcp.MinJWKSRefetch` and `mcp.DefaultJWKSTTL` are the shared constants.
- `verify` fetches the JWK Set with `netguard.NoRedirects(cfg.HTTPClient)`, as `oauth` and `sso`
  do: by default public addresses only, never a redirect; a host with an issuer on a private
  network passes its own client. `mcp.Protect` keeps its own default client (its behaviour is
  unchanged).

Security review (rule 6): no check is weakened. `verify` adds checks over the moved verifier (an
RS256/EdDSA allow-list before any key lookup, typ required, aud refused when none is configured,
cnf-bound tokens refused because accepting them without the proof would make a DPoP token a bearer
one). Keys come only from the configured https URL, are bounded to 64 KiB, cached for a TTL and
never used past it; an unknown kid refetches at most once a minute, so a forged kid is no fetch
amplifier. alg none, HS256 keyed with the public key, ES256 under an RSA kid and an RS256 token
naming the Ed25519 kid are tested refusals; `FuzzVerify` covers arbitrary headers and claims signed
with the issuer's key. Optional authentication shares Protect's chain (resolvers, plugin middleware,
denylist), so the only new branch is "no credential at all", which carries no principal. An OpenID
ID token is typ JWT, signed by the same key, with aud its client_id, so `verify` accepts a typ JWT
token only when it carries the `roles` list every session access token carries (empty when the
user has no role) and an ID token never does: a positive session marker, not a deny-list of ID
token claims an ID token may lack. `mcp.Protect` keeps accepting typ JWT without that marker for
now (its behaviour is not changed here), so a resource whose audience equals a client_id accepts
that client's ID tokens there.

## 56. 2026-11-22 — Import users with their password hashes

Adopting Polaris should not mean a password reset for every existing user. A host can now bring
accounts with the hash another system stored, and the first sign-in upgrades each one.

- `p.Users().Import(ctx, polaris.ImportedUser{...})`, a method of its own rather than a
  `PasswordHash` field on `NewUser`: `Create` keeps one meaning (Polaris hashes a password under the
  policy, verification email out), and an import has different rules (no policy, no hashing, no
  email; `CreatedAt` and `Disabled` kept). It goes through `identity.InsertUser`, so
  `Hooks.OnUserCreated` runs in the account's transaction and `user.registered` is dispatched
  (without a verification token, so the mailer sends nothing); it joins the host's
  `sqlstore.WithTx`, so a migration is all or nothing. No HTTP route: it is for a trusted caller in
  process. The contract fixtures are unchanged.
- The hash must pass `security.HashChecker.CheckHash`, a new optional interface of the
  `PasswordHasher` port (`security.Argon2id` implements it). A configured hasher without it refuses
  imports with an error naming the fix, rather than storing a hash nobody could sign in with. A
  refused hash is `polaris.ErrInvalidInput` and `security.ErrUnsupportedHash`; the message lists
  `security.SupportedHashFormats`.
- `security.Argon2id.Verify` also verifies Django `pbkdf2_sha256$` and `scrypt$`, passlib
  `$pbkdf2-sha256$`, `$pbkdf2-sha512$` and `$scrypt$` (standard or passlib base64), and Firebase's
  modified scrypt as `$firebase-scrypt$ln=,r=,sep=,key=$salt$hash` (the project's hash parameters
  and the exported values, so each row describes itself). PBKDF2 uses stdlib `crypto/pbkdf2`,
  scrypt `golang.org/x/crypto/scrypt` (already required); no new dependency. Bcrypt, Argon2id and
  Argon2i verify exactly as before. Known-answer vectors from Django's and passlib's test suites,
  RFC 7914 §11–12 and the `firebase/scrypt` README are in `testdata/vectors/imported-hashes.json`.
  Not supported: Django `pbkdf2_sha1$` and `argon2$`, passlib `$pbkdf2$` (SHA-1), PHC-style
  `i=,l=` PBKDF2 parameters, scrypt `$7$`; Cognito exports no hashes at all. A host keeps an exotic
  scheme by wrapping `Argon2id` as `Config.Hasher` (its own `Verify` and `CheckHash` for the
  prefix); `ExampleHashChecker` shows it.

Security review (rule 6):

- Verify only. Polaris never creates these formats; `NeedsRehash` is true for every one of them,
  so `Login` stores an Argon2id hash under the configured parameters on the first correct
  password, and the legacy string is gone.
- A hash string is data from the database, so its costs are bounded before any work: PBKDF2
  iterations 1,000 (RFC 8018 §4.2) to 5,000,000; scrypt memory 128·r·N from 1 MiB to 256 MiB,
  p ≤ 16 and 128·r·N·p ≤ 1 GiB; salts 4 to 256 bytes (4 is RFC 7914's own "NaCl"; refusing
  shorter catches truncated rows); stored hashes 16 to 64 bytes; strings at most 1,024
  characters. Out of bounds never verifies (and never runs the KDF); the parsers take strict
  decimals (no sign, no leading zero) and reject trailing fields. `FuzzCheckHash` covers them.
- Imports are stricter than `Verify` for the formats `Verify` already read: bcrypt cost at most 16,
  Argon2 memory at most 1 GiB and memory × passes at most 4 GiB. `Verify` itself keeps reading every
  bcrypt and Argon2 hash it read before (rule 5), so an existing row with an absurd cost still costs
  what it did; bounding that is a separate change.
- Comparisons are `crypto/subtle.ConstantTimeCompare` of the derived bytes (bcrypt compares inside
  `x/crypto/bcrypt`, as before). The Firebase scheme compares the signer key encrypted under the
  derived key, as Firebase does.
- Timing: `Login` still runs exactly one verify per attempt, but a not-yet-upgraded user's verify
  runs at the imported hash's cost, not the configured Argon2id's, so the response time can tell an
  imported account from an unknown email until that user signs in once. This is the same exposure
  an Argon2id hash with older parameters already had.
- The Firebase signer key sits in each Firebase row's hash string. A database reader can then test
  guesses against those rows offline, as with any stored hash; without the key the rows could not
  be verified at all. The rows disappear as their users sign in; a host that does not accept this
  imports Firebase users without a hash and has them reset.

## 58. 2026-11-22 — The code reads as Go, not as a port

Outside `plugins/`, comments, private identifiers, test names and test-data file names no longer
describe the code by reference to the PHP project (#53). Each comment now states the format or rule
in its own terms and, where a format is unusual, why: stored data, issued tokens and recorded
vectors from earlier releases must keep reading (rule 5). References to documents that do not exist
here (`docs/auth/*`, `docs/cookie-mode`, "spec §N") are removed or described inline.

- Renamed (all unexported or test names; no stable API changed): `internal/observe/phpjson.go` is
  `metadatajson.go` (`phpJSON` is `metadataJSON`), `agent/testdata/php-receipts.json` is
  `receipt-chains.json`, and the `php*`/`*PHP*`/`*Upstream*`/`*Otphp*`/`*Lcobucci*` helpers and tests
  in `token`, `security`, `identity`, `orgs`, `manifest`, `cli`, `internal/contracttest` and
  `internal/httpapi` take names that describe the behaviour (`encodeOrderedObject`, `asList`,
  `decodeBase64Lenient`, `leadingInt`, `trimSet`, …).
- No behaviour changed: no byte the server emits, stores or accepts, no fixture, no golden, no vector.
- Kept on purpose: the `domain.class` values (`Polaris\Http\…`) in the route specs and the exported
  manifest goldens, which clients read; the recorded test names (`Polaris\Tests\Functional\…`) that
  key the contract fixtures; the `"generator": "php"` field of the known-answer vectors, which the
  vector tests check; the `cache.ErrInvalidKey` error text naming PSR-16, which hosts may match; the
  501 text "This endpoint is not ported yet."; and the history sentence in `AGENT.md`.

## 57. 2026-11-22 — plugins/ui: server-rendered sign-in pages

Polaris was a JSON API only: a Go team wrote every screen before a user could sign in, and
`plugins/oauth` needed a host-written login and consent page before it worked at all. `plugins/ui`
(id `ui`) serves the pages a browser without JavaScript needs: sign in, the MFA step, sign up, "check
your email" and verification, forgot and reset password, sign out, the OAuth consent and device
pages. `html/template`, embedded templates and one stylesheet (about 10 KB), no dependency.

- **Mounting.** The pages are not manifest routes: the route specs model JSON input and output and
  feed the OpenAPI export, and describing HTML forms there would make both worse. A new optional
  interface, `wiring.HandlerProvider` (`Handler(g) (prefix, http.Handler)`), gives a plugin every
  request at or under one prefix (`/auth/ui`), inside `Config.Middleware`, ahead of the pipeline;
  `polaris.New` refuses a prefix that overlaps a manifest route or another plugin's. Requests
  elsewhere reach the pipeline unchanged.
- **Same entry points.** A page runs the JSON route in process (`POST /auth/login`,
  `/auth/register`, `/auth/mfa/verify`, `/oauth2/authorize/decision`, …) through a second pipeline
  over the same graph, built the way `plugins/mcp` builds its tool dispatcher (body token delivery,
  every endpoint, the plugins' middleware). It shares the rate-limit store, so the per-IP buckets are
  the route's (`TestRateLimitsAreTheRoutes`: a JSON attempt and page attempts spend one budget);
  sentinel's middleware judges it (`TestSentinelJudgesThePages`); lockout, timing parity, the MFA
  gate, events and audit are core's because the endpoint is core's. Calling the services directly
  would have skipped the pipeline, where rate limits and sentinel live.
- **Session transport.** Core's session is used as is (the refresh-token family, rotation, reuse
  detection, denylist). Core's cookie delivery cannot carry it for a browser without JavaScript: it
  needs the `X-Polaris-CSRF` header and scopes the refresh cookie to `/auth/token/refresh`, and the
  access token stays in the JSON body. So the pages keep the pair in their own HttpOnly, Secure
  cookies: `__Host-polaris_session` (access token, `SameSite=Lax`, its TTL) and
  `__Secure-polaris_ui_refresh` (refresh token, `Path=/auth/ui`, only the pages read it). The plugin's
  bearer resolver reads the session cookie, so `p.Protect` and the bearer routes accept a browser;
  an `Authorization` or `X-Api-Key` header wins. `RequireSignIn(h)` turns a GET's 401 into a redirect
  to `/auth/ui/refresh`, which rotates the refresh token through `POST /auth/token/refresh` or asks
  for a sign-in.
- **One configured origin.** The pages' origin is `ui.Config.BaseURL`'s (default the issuer +
  `PathPrefix`), never one derived from the request: the Host header and `r.TLS` are not read and
  `X-Forwarded-*` is not trusted. It is what a browser's `Origin` must equal (form posts, and the
  session cookie on non-GET requests), the origin a `return_to` URL may name, and the session rule:
  an https origin issues sessions whatever the connection, a loopback http origin too
  (development), any other http origin refuses every form and warns at startup. So the pages work
  behind a TLS-terminating proxy with an internal Host, as `plugins/social`'s binding cookie learnt
  to follow `BaseURL` (#50), and a forged Host cannot make a cross-site Origin look same-origin.
  The pages are served on that origin only: under another name they render but refuse every post
  with a link to the configured origin (`__Host-` cookies belong to one host); hosts redirect other
  names at the proxy. A `BaseURL` that is not an absolute http(s) URL fails `polaris.New`.
- **OAuth.** `plugins/oauth` gains `oauth.PageProvider`: a plugin implementing it fills the
  `ConsentURL` and `DeviceURL` the host left empty (an explicit URL still wins). With `ui`
  installed, a filled `DeviceURL` turns the device flow on.

Security review (rule 6):

- **CSRF.** Core's cookie-mode guard needs a custom header a form cannot send, so the pages use a
  signed double-submit token: a random nonce in `__Host-polaris_csrf` (HttpOnly, Secure, Path=/,
  SameSite=Strict; the `__Host-` prefix stops a sibling subdomain from planting it) and, in every
  form, its HMAC from core's pepper (`Pepper.Hash("ui.csrf", nonce)`, keyed from `APP_KEY`), checked
  with `Pepper.Matches` in constant time. A post whose `Origin` (or `Sec-Fetch-Site`) is not the
  configured origin is refused before the token is looked at. The session cookie adds no CSRF surface to other
  routes: the resolver uses it for GET, HEAD and OPTIONS, and for any other method only when `Origin`
  or `Sec-Fetch-Site` says same-origin (no header: no credential), which covers the host's own
  routes behind `p.Protect`.
- **Redirects.** `return_to`, `AfterSignIn` and `AfterSignOut` are a same-origin path (not `//`, no
  backslash, no control character) or an http(s) URL on the configured origin or
  `Config.RedirectOrigins`; anything else ends on `AfterSignIn` and is not echoed into the form. The
  configured targets are checked at startup. The consent and device pages redirect only to what
  the provider answers (the client's registered redirect URI); that origin joins the consent page's
  `form-action`, nothing else.
- **Headers.** Every response: `Cache-Control: no-store`; `Content-Security-Policy: default-src
  'none'; style-src 'self'; img-src 'self' [logo origin]; form-action 'self' [RedirectOrigins]
  [client]; frame-ancestors 'none'; base-uri 'none'` (no script at all, no inline style; the
  colours are generated into the stylesheet, validated as hex); `X-Frame-Options: DENY`;
  `Referrer-Policy: no-referrer` (reset tokens ride in URLs); `X-Content-Type-Options: nosniff`.
  Every value reaches HTML through `html/template`'s contextual escaping.
- **Enumeration.** The pages show what the routes answer and no more: sign-up always continues to
  "check your email", forgot and resend always show the same notice, a wrong password, an unknown
  account and a locked account read "Incorrect email or password". Only what the JSON route already
  tells (an unverified email under `RequireVerifiedEmail`, a disabled account) is shown.
- **Tokens.** The email verification link verifies on GET (verification is idempotent and signs
  nobody in); a reset link only fills the form, and the reset is a POST. The MFA ticket rides in a
  short-lived HttpOnly cookie scoped to the pages, never in the HTML.
- **Ceiling.** Two tabs refreshing the same session at once present one refresh token twice, and
  reuse detection ends the session (as for any cookie client); the user signs in again.

Not in v1: passkeys (the WebAuthn ceremony needs JavaScript), social and magic-link buttons (each needs
a landing page registered among that plugin's redirect URIs), account settings and organization
screens. `cli` knows the plugin (`--plugins=ui`).

## 59. 2026-11-22 — A provider's email_verified fails closed; mcp.Protect refuses ID tokens

Two token and claim checks found loose during the v0.4.0 review, both tightened.

- **social: email_verified.** The GitHub, Discord, Zoom and Dropbox profiles read the provider's
  `email_verified` / `verified` with a lenient truthiness: any non-empty string other than "0",
  the string "false" included, and any non-empty list or object read as verified. A verified email
  decides whether a new account starts verified and, for a trusted provider, whether `linkTrusted`
  may claim an existing unverified account with that address and unlink its other providers.
  Now one function, `verifiedFlag`, reads every provider's flag and `OIDCProfile`'s: true only for
  JSON true, the strings "true" (any case) and "1", and the number 1; everything else is
  unverified. `OIDCProfile` now also accepts "TRUE" and a float 1, which it used to refuse.
  These providers send JSON booleans today, so no known exchange was misread.
- **mcp.Protect: OpenID ID tokens.** The oauth plugin's ID tokens are signed by the access-token
  key with typ JWT, and their aud is a client_id, which can be an https URL (client ID metadata
  documents) equal to a protected resource. `mcp.Protect` now applies `verify`'s rule (#55): a
  typ JWT token, or one without typ, must carry a session access token's `roles` list; at+jwt
  tokens are unaffected. A non-Polaris issuer's tokens must be at+jwt. Client-visible: such a
  token without `roles` is now 401 where it was accepted.

Security review: both changes only refuse more. Tests: `TestEmailVerifiedIsTrueOnlyWhenTheProviderSaysSo`
(every provider mapping and `OIDCProfile`, "false" and container values),
`TestAnIDTokenIsNotAnAccessToken`, and `TestOnlyAccessTokensAreAccepted` extended with the refused
shapes. The `mcp` contract fixtures replay unchanged.

## 60. 2026-11-22 — Audit chain across processes, one operator grant per user, paginated tools/list

Three items decisions 21, 25 and 27 left open (docs/v1.md 4.3), closed.

- **Audit: the hash chain no longer forks across processes (#21).** A chained write read the
  newest row and inserted after it under a per-process mutex, with its id minted before the
  transaction: two replicas (or two `Store`s on one database) could link two rows to one
  predecessor, or commit a row whose id sorts before its predecessor's, and `Verify` then
  reported breaks in an untampered table (a test with 2 handles x 8 writers x 15 writes forked it
  on memstore, SQLite, PostgreSQL and MySQL; on SQLite writes also failed with SQLITE_BUSY: 96 of
  240 in one run). Now every chained write runs in one transaction whose first statement updates the
  single row of a new table, `polaris_audit_chain` (id, last_id, last_hash, locked_by). That row
  is the chain's lock and holds its tip. The lock: a row lock held to commit on PostgreSQL and
  MySQL; on SQLite the database write lock, taken by the transaction's first statement, so the busy
  timeout waits for it instead of failing a reader that tries to upgrade. The tip: after its lock
  UPDATE the write reads last_id / last_hash from that same row, links to them, inserts the event
  and moves the tip to it in the same transaction. Reading the tip from the events table instead
  depended on snapshot timing: audit events are recorded with the caller's ctx, and a host's
  transaction (`sqlstore.WithTx`, events dispatched before the host commits) nests the write as a
  savepoint; on MySQL's REPEATABLE READ a transaction that had already read keeps a snapshot from
  before the lock, so the newest row it saw was stale and the chain forked again (239 breaks in
  240 rows in the test below). A row the transaction just updated is read as its own version, built
  on the latest commit (InnoDB's UPDATE is a current read), on every dialect. When the freshly
  minted UUID v7 does not sort after last_id (another replica's clock ahead, the same
  millisecond), the write takes the next UUID after it (random tail + 1, version and variant kept),
  so id order stays chain order. An id the caller set is kept as before. With the tip on the lock
  row, pruning the newest event leaves the next row linked to the pruned one; the `audit.pruned`
  checkpoint names that hash, so `Verify` accepts it. Alternatives rejected: a unique
  index on `prev_hash` (the first row's prev_hash is NULL, so two first rows still fork; a chain
  re-started after the chain was off would collide with the first one; it also needed the index
  added to existing tables); advisory locks (different per dialect, none on SQLite).
  **Upgrade:** `Migrate` creates the table (a missing table, nothing altered); the first chained
  write inserts the lock row (the insert first, then the seed: the newest event's id and hash, in
  a savepoint so a duplicate from another replica neither fails nor aborts a host's PostgreSQL
  transaction). No chained write appends before the row exists, so the seed is the tip whatever
  snapshot reads it. Rows, hashes and `Verify` are unchanged: existing chains keep verifying and
  the next write links to their newest row. A host that upgrades without running `Migrate`
  gets chained writes failing with an error naming the table and `Migrate` (logged by the recorder,
  the operation itself is not failed), not a silently forkable chain.
  Security review: tamper evidence only gains; no hash input changed (`hashOf` untouched, the
  canonical-form test still pins it). The lock serializes chained writes across the deployment:
  throughput is one chained write at a time per database, as it was per process, and an event
  recorded inside a host's transaction holds the lock until the host commits. Tests:
  `TestTheChainStaysLinearWithWritersInSeparateProcesses` (memory, SQLite with two pools on one
  file, PostgreSQL and MySQL with two stores), `TestTheChainStaysLinearWhenWritersAppendInsideATransactionThatAlreadyRead`
  (each write inside an outer transaction that read `polaris_audit_event` first; memory,
  PostgreSQL, MySQL: SQLite cannot upgrade such a transaction to a writer while another writes, so
  the host's transaction fails with SQLITE_BUSY and nothing forks),
  `TestAChainFromBeforeTheLockTableKeepsVerifyingAfterMigrate`,
  `TestPruningTheNewestEventKeepsTheChainVerifying`,
  `TestAChainedWriteWithoutTheLockTableNamesTheFix`, `TestAfterSortsRightAfterAUUID`.
- **Admin: one grant per user under concurrent first grants (#25).** `polaris_admin_grant.user_id`
  is unique (`polaris_admin_grant_user_unique`, replacing the plain `polaris_admin_grant_user_index`).
  `Grants.Grant` is an upsert; when its insert loses to a concurrent first grant of the same user
  (`store.ErrDuplicate`) it runs again, now as the update of the row there, which is what the same
  two grants answer when they arrive one after the other (the route's 200 with the grant, its id
  kept). Up to three attempts. On SQLite writers are serialized, so the duplicate could not happen.
  **Upgrade:** `Migrate` adds the unique index to existing tables and then drops the old one
  (decision 63: `.Unique(…, "polaris_admin_grant_user_unique").DropIndex("polaris_admin_grant_user_index")`).
  A database that already holds two grants for one user (only this race made them) is refused, not
  repaired: `Migrate` fails with "if polaris_admin_grant holds duplicate (user_id) values, remove
  the duplicate rows and migrate again", deletes nothing and keeps the old index. Keeping "the strongest" was rejected: grants carry a scope (the instance or one
  organization), so there is no strongest across scopes, and choosing which operator power survives
  is the operator's call. The remedy (query and revoke) is in the admin README and the changelog.
  Security review: removes a way to hold two operator grants with `For` answering either one; no
  check is weakened; the retry only re-runs the same authorized upsert. Tests:
  `TestConcurrentFirstGrantsOfOneUserKeepOneRow` (memory, PostgreSQL, MySQL: 20 rounds of 8
  concurrent first grants over two stores; before the fix PostgreSQL kept 2 rows and MySQL 5),
  `TestAnUpgradeWithDuplicateGrantsIsRefusedWithTheRemedy` (SQLite, PostgreSQL, MySQL: refused
  with the old index kept, then, once the extra grant is revoked, the index replaced and `Diff`
  empty). `TestMigrateUpgradesEveryReleasedSchema` (decision 63) reaches the fresh schema from
  v0.4.1 with exactly three changes: `polaris_audit_chain` created, the admin index created and the
  old one dropped; the `admin` and `audit` DDL goldens are regenerated.
- **MCP: `tools/list` is paginated (#27).** The 2026-07-28 profile and the 2025 stdio revisions
  page list results with `params.cursor` / `nextCursor`. A result now carries at most
  `mcp.ToolsPageSize` (100) tools; when more follow, `nextCursor` is the base64url of the last
  listed tool's name, and the next request starts after that tool. The cursor is checked against
  the caller's own list, recomputed under the caller's permissions on every request: one that does
  not decode or does not name one of the caller's tools is `-32602` invalid params (the
  specification's code for an invalid cursor). It is not signed because it grants nothing: it
  only says where to resume in a list the caller may already see, so a forged one can only skip
  ahead in that list. A name cursor rather than an offset keeps a page stable when tools are added
  before it between requests. Client-visible: a caller with more than 100 tools (an instance
  operator with every plugin: about 230 routes) gets several pages; a list of 100 or fewer is one
  page with no `nextCursor`, byte-identical to before, so the `mcp` contract fixtures (34 tools)
  replay unchanged. Security review: the list is filtered per caller exactly as before; the cursor
  is input validated before use and leaks nothing about other callers' tools (any name outside the
  caller's list, existing or not, is the same error). Test: `TestToolsListIsPaginated` (287 tools
  in three pages, no tool twice, the short list unchanged, invalid cursors refused).

## 63. 2026-11-22 — Schema evolution: additive, declared in the schema DSL

1.x will change tables that exist in deployed databases (a unique index on a plugin table, a column
for SCIM name parts), and `Migrate` only created missing tables (`CreateMissing`). The mechanism:

- **The schema DSL stays the single source.** A table is declared as the latest release wants it.
  `sqlstore.Store.Migrate(ctx, models)` inspects each table and creates it when missing (the table,
  then its indexes) or, on an existing table, adds every declared column it lacks
  (`ALTER TABLE … ADD COLUMN`) and every declared index it lacks (matched by columns and
  uniqueness, as `Diff` matches), then drops the indexes a model retires with
  `Model.DropIndex(name)` (a new `DroppedIndexes` field). A fresh install never sees a retired name.
  `Polaris.Migrate` calls it, finding it through `Unwrap` (telemetry/otel's wrapper) and falling
  back to `CreateMissing` for an adapter without one.
- **Safe by default.** It never drops a table or a column and never changes a type, nullability
  or default: `schema:diff` reports those and they stay manual. It plans every table before the
  first statement and refuses, changing nothing, a column added to an existing table that is NOT
  NULL without a default (SQLite cannot add one, PostgreSQL fails on a table with rows) or part of
  the primary key, and an index both declared and dropped (Migrate would drop and recreate it on
  every boot). A unique index that meets duplicate rows fails with the remedy (remove the
  duplicates, migrate again); it never deletes rows. A foreign key on an existing table is not
  added (SQLite cannot); a new relation goes on a new table.
- **Idempotent on every replica.** Each step is checked against the live table before it runs;
  when its statement fails and a fresh inspection shows the change in place (another replica got
  there first: none of the three dialects has `ADD COLUMN IF NOT EXISTS` and MySQL has no `CREATE
  INDEX IF NOT EXISTS`), the step counts as done. A second run changes nothing.
- **What it returns.** `Polaris.Migrate` returned the tables it created; it now returns what it
  changed: each created table by name (as before), then `"<table>: added column <c>"`,
  `"<table>: created index <i>"`, `"<table>: dropped index <i>"`. On a database that only lacked
  tables the result is unchanged. `polaris migrate` prints "Applied N change(s)"; its JSON keeps
  the `created` key, holding the same list.

How a plugin declares a change: add the field to its `schema.Table(…)` (`.AsNullable()` or
`.WithDefault(v)`); add an index with `.Index`/`.Unique` under a new name; to turn an index into a
unique one, declare the unique index under a new name and `.DropIndex("<old name>")`. Then
regenerate the plugin's DDL golden (`go test ./cli -run TestPluginDDLGoldens -update`); the
upgrade test checks `Migrate` reaches the new schema from the released one.

Why not versioned migration steps (a table of applied step ids, SQL per dialect): every additive
change would need three hand-written dialect variants and a step id, for what the DSL already
says; a diff-driven step cannot drift from the fresh-install DDL. A change the DSL cannot express
(a rename, a type change, a backfill) is when a versioned step is worth adding; none is needed
yet.

Guards, all in `make qa` (SQLite) and the database matrix (PostgreSQL 17, MySQL 8.4):
`TestMigrateAddsColumnsAndIndexesAndKeepsRows`, `TestMigrateIsSafeOnConcurrentReplicas`,
`TestMigrateRefusesWhatItCannotApplySafely`, `TestMigrateNamesTheFixWhenAUniqueIndexMeetsDuplicates`
(`store/sqlstore`); `TestMigrateUpgradesEveryReleasedSchema` (`cli`: applies the schema
`polaris schema:export --plugins=<all>` printed at v0.4.1, `testdata/upgrade/v0.4.1.*.sql`, runs
`Migrate`, and compares every table with a fresh install, index names included; a release that
changes the schema adds its predecessor's export there); `TestPluginDDLGoldens` (one golden per
plugin per dialect in `testdata/ddl`, like core's). Lint: revive's `exported` rule now fails on an
exported name without a doc comment (its "X …" wording check is not enforced: the event types
read "UserLoggedIn: …"). Security review: no security-critical package changes; `Migrate` runs
DDL built from the compiled-in schema only, quoting every identifier, never from input.

## 62. 2026-11-22 — Six fixes found while writing the examples

Writing `examples/` against the public surface turned up six defects; each is fixed with a test
that failed first.

- **A host's permissions are grantable: `Config.RolePermissions`.** `cfg.Permissions` put the
  host's keys in the catalog, but no system role held one, and `POST /orgs/{id}/roles` (like
  invitations, API keys and agent approvals) refuses to grant what the actor does not hold, so only
  a superadmin could ever grant them; llms.txt documented a flow that answered 403, and three
  examples wrote role grants through `Graph().Repos()`. Now the host says which system roles hold
  which of its permissions: `cfg.RolePermissions = map[string][]string{"owner": {"invoices.read"}}`
  (slugs `owner`, `admin`, `member`). `authz.Catalog.WithRoleGrants` adds them to the role
  templates; a new organization's copies start with them (`orgs.Config.Catalog`); `Seed` (run by
  `Migrate`) gives a grant new to a template to every existing organization's copy, once: the
  template's own grants record what was given, so a later `Migrate` leaves a tenant's removal from
  its editable admin or member role alone. `New` refuses another slug (superadmin already holds
  everything; a custom role belongs to its organization), a key the catalog lacks and a core key
  (the system roles' core permissions stay fixed; `users.*` stays platform-only). Removing a key
  from the map revokes nothing. "You cannot grant what you do not hold" is unchanged for everyone.
  Rejected: the owner role holding every host permission automatically (a host permission can be
  platform-scoped, as `users.manage` is, and an implicit grant to every tenant's owner is an
  escalation the host did not ask for); a `p.Orgs()` role-management call for a trusted caller
  (every host would write per-organization code at creation and a backfill for existing
  organizations, which is what the examples' workaround was, and the HTTP flow would still fail).
- **An exhausted budget is `budget_exhausted`.** The execution that spends a grant's last unit
  marks it exhausted, and the next call found no active grant and answered
  `capability_not_granted`, so an agent following llms.txt (`errors.Is(err,
  agent.ErrBudgetExhausted)`) never saw its budget run out. Without a live grant, the refusal now
  looks at the agent's latest grant for the capability: exhausted answers 403 `budget_exhausted`
  ("The grant's budget cannot cover this execution (0 left)."), anything else
  `capability_not_granted` as before. Client-visible; the `agents` fixture step that pinned the old
  answer is edited.
- **429 has a body.** The per-IP, per-user and per-API-key limiters answered 429 with no body,
  where every other refusal is JSON. `endpoint.TooManyRequests(route)` answers core's
  `{"error":"too_many_requests","message":…}` on core routes and host routes, and an RFC 9457
  problem (`…/problems/too_many_requests`) on plugin routes; `Retry-After` and `X-RateLimit-*` are
  unchanged. Client-visible (Content-Type and body); three core and api-keys fixture steps edited.
- **Audit rows of core events record the client.** Core's events carry no client fields (only
  sign-in, failed sign-in, lock, reuse and revoke-all name an IP), and the audit recorder mapped
  them without the request, so `org.created`, `org.member_invited` and the rest had null `ip` and
  `user_agent` where plugin events (`api_keys.*`) filled them from the request. The recorder now
  fills both from `endpoint.Client(ctx)` when the event does not name its own; outside a request
  (a `p.Orgs()` call) they stay null. `request_id` is null for every event, plugin ones included:
  Polaris has no request id; carrying a host's is a separate decision. A minimal change in
  `plugins/audit` (`Recorder.Listen`).
- **SCIM keeps name parts.** The user row holds only a display name, so a User created with
  `name.givenName`/`familyName` came back with `name.formatted` alone and a directory comparing
  resources saw a difference. A new plugin table, `polaris_scim_user_name` (connection, user,
  given and family name), keeps what each connection sent for accounts it manages (created, or
  owned under the existing ownership rule), and the User resource answers them (RFC 7643 §4.1.1).
  PUT replaces both (absent means cleared); a PATCH of one part keeps the other and recomputes the
  display name from both (before, a PATCH of `givenName` alone set the display name to the given
  name only). Deleting the user from the directory, its leaving, and deleting the connection drop
  the rows. A new table rather than columns on `polaris_scim_resource`: that row exists only while
  the directory sent an `externalId` and is counted as the connection's managed users. Existing
  databases get the table on `Migrate` (`TestMigrateUpgradesEveryReleasedSchema`); a user without
  a row reads as before.
- **Whole-second NumericDates.** Access tokens and OAuth/OIDC tokens carried fractional
  `iat`/`nbf`/`exp` (`1795333957.332773`): RFC 7519 allows it, but many verifiers decode into an
  integer and refuse them; and an OAuth token's `exp` fell microseconds short of `iat` + TTL
  because the plugin read the clock a moment before the codec. `Codec.Issue` writes `iat = nbf`
  = now in whole seconds and `exp = iat + TTL`; `Codec.Mint` writes `exp = iat +` the lifetime
  (`expiresAt − now`) rounded to whole seconds. Decoding is unchanged, so tokens already issued
  with fractions keep verifying (rule 5): the four recorded vectors minted at fractional instants
  keep their tokens and checks and no longer pin minted bytes; the whole-second vectors still mint
  byte for byte. `Codec.Sign` (receipts) is unchanged. The denylist already compares whole
  seconds.

Security review: `RolePermissions` is host configuration read at `New`, validated, and grants only
contributed (non-core) permissions to the roles the host names; the escalation guard is untouched.
The agents change only reports a refusal under another code, after the same checks. The
token change is encoding only; the verification checks and leeways are unchanged. Tests:
`TestHostPermissionsReachRolesThroughRolePermissions`, `TestUndeclaredHostPermissionsStayUngrantable`,
`TestMigrateGivesExistingOrganizationsNewRolePermissions`, `TestRolePermissionsAreCheckedAtNew`;
`TestASpentCountBudgetIsBudgetExhausted` (Go agent SDK) and the lifecycle and token-middleware
expectations; `TestA429OnAPluginRouteIsAProblem` and `TestRateLimiterAnswers429WithTheHeadersOf10`;
`TestEventsRecordTheRequestsClient`; `TestTheDirectoryReadsBackTheNamePartsItSent`,
`TestADirectoryDoesNotStoreNamePartsOfAnAccountItDoesNotOwn`;
`TestDateClaimsAreMintedAsWholeSeconds`, `TestIssueEncodesDatesAsWholeSeconds`,
`TestMintAccessTokenLayout`, the vectors.

## 61. 2026-11-22 — Account lifecycle: guest conversion, erasure, one-channel MFA, magic links

Closes the account-lifecycle items decisions 33 and 35 left open (docs/v1.md §4.3).

- **anonymous: conversion is one transaction.** `Guests.Convert` used to claim the guest row, run
  `OnConvert`, then end the guest in a second transaction: when ending failed the conversion stayed
  recorded, the guest's sessions stayed live and a retry answered `not_a_guest`. Now claiming the
  row, `OnConvert`, disabling the guest and revoking its sessions are one transaction; any failure
  rolls all of it back (500, the guest keeps its session and can retry). `OnConvert` runs with the
  transaction in its ctx, as `Hooks.OnUserCreated` does: a host that writes through ctx moves its
  data atomically with the conversion; a write outside it is not undone by a later failure, and
  the retry runs the hook again (documented: keep such a hook idempotent). The session revocation
  runs last because its denylist watermark is in the cache, which a rollback cannot undo.
  Security review: a guest is never reported converted while it can still refresh; concurrent
  conversions still run the hook once (the claim is the transaction's first write, so a second
  conversion waits on it and then finds the row claimed). Tests:
  `TestAConversionWhoseEndingFailsConvertsNothingAndCanBeRetried` (failed before: the conversion
  stayed recorded with the guest live), `TestConcurrentConversionsConvertOnce`.
- **The converted guest's access token on `/auth/me`.** Diagnosed as the stateless access-token
  window, not a missing check: conversion revokes the guest's refresh tokens and watermarks the
  denylist, so with `AUTH_ACCESS_TOKEN_DENYLIST` on the token answers 401 at once; with it off,
  every access token (a logged-out session's, a disabled or erased user's) answers until it
  expires, by design, while a disabled user resolves no permission. `/auth/me` answering
  `"status":"disabled"` is that window. Nothing in core changes; the anonymous README and package
  doc said "ends the guest's sessions" without the window and now state it, and
  `config.AccessToken.Denylist` documents it. Test:
  `TestAConvertedGuestsAccessTokenEndsWithTheDenylist`
  (both settings; passed before, it pins the diagnosis).
- **Erasure removes every plugin row keyed to the user.** Through the existing mechanism (each
  plugin's `event.UserDeleted` listener; a new `internal/maintenance.EraseOnUserDeleted` deletes a
  plugin's listed rows and logs a failure, as the other plugins' erasures do). Newly deleted on
  erasure: usernames, verified phones and pending passwordless secrets, multi-session and sentinel
  device records, operator grants, OAuth authorization codes, device codes and CIBA requests (the
  consents and tokens already went), SCIM membership provenance and user mappings, the guest row,
  and the audit activity row. Kept, as attribution to the anonymized tombstone id (the audit trail
  keeps it too): `created_by` / `granted_by` / `decided_by` on configuration and approvals, the
  audit events' subject and actor, and a guest row's `converted_user_id`. Client-visible: after an
  erasure `GET /admin/users/{id}` answers `last_active_at: null` (the admin users fixture is
  edited at that one step). Guard: `TestErasureRemovesEveryPluginRowOfTheUser` boots every
  plugin, seeds a row naming the user in every plugin table with a user column (`*user_id`,
  `*_by`, `owner_id`, `subject_id`, `actor_id`, `local_id`), erases the user and fails on any row
  left that is not in its retained list; a new table with a user column fails it until covered or
  listed with a reason (failed before: 13 plugin tables kept the erased user's rows). Security
  review: deletes only rows naming the erased id; the listeners run after the erasure commits, so
  a failure is logged and leaves rows behind (as for the plugins that already erased this way),
  never a half-erased account.
- **MFA: one channel is one factor.** A passwordless sign-in by email code or magic link proves the
  mailbox; an email MFA factor on the same address (an SMS factor on the phone a phone sign-in
  used) proves nothing more, yet it satisfied the gate. Now the passwordless gate offers only the
  factors that do not deliver where the sign-in's code went (addresses compared case-insensitively),
  and answers 403 `passwordless/mfa_same_channel` when none is left (the user signs in with the
  password, or adds another factor). Offering fewer factors is not enough, since the ticket let the
  client name any factor of the user: `mfa.Service.BeginLogin` now binds the `login_mfa` ticket to
  the factors it lists (claim `mfa_factors`, added to the reserved claim names), and
  `/auth/mfa/challenge` and `/auth/mfa/verify` answer 404 (as for an unknown factor) for another
  one; recovery codes still complete it. Core's password login issues an unrestricted ticket as
  before, and a ticket without the claim (issued before the upgrade) stays unrestricted. The
  passkey sign-in, which already left its own passkey out of the list, gets the enforcement it
  lacked. Plumbing, all additive: `session.MFATickets.IssueFor` / `AuthenticateFactors`,
  `pipeline.MFATicketFactors` (an optional interface the pipeline checks on its `MFATickets`),
  `endpoint.WithMFATicketFactors` / `MFATicketAllows`; `mfa.Tickets` (not stable) now has
  `IssueFor` instead of `Issue`. Security review: the restriction is inside the signed ticket, so a
  client cannot widen it; an unparsable claim fails the ticket. Tests:
  `AFactorOnTheSignInsChannelIsNotASecondFactor` (email code, magic link, phone; failed before:
  the same-address factor was offered), `TestTheMFATicketTakesOnlyTheFactorsItOffered` (HTTP:
  challenge and verify refuse the left-out factor; failed before), `TestMFATickets`,
  `TestBeginLoginMintsATicketAndMasksFactorViews`,
  `TestMFATicketAllowsOnlyTheFactorsItWasRestrictedTo`.
- **Magic links: opening one spends nothing.** Email security scanners follow links with GET and
  spent the one-time token before the user clicked. `GET /magic-link/verify` now checks the token
  without spending it and answers a static HTML page (no JavaScript; `Cache-Control: no-store`,
  `Referrer-Policy: no-referrer`, a CSP of `default-src 'none'; frame-ancestors 'none'` and
  `form-action 'self'` plus the redirect URIs' origins, since browsers apply form-action to the
  POST's redirect) whose one button posts back to the same URL; the new `POST /magic-link/verify`
  (`polaris.passwordless.magic-link-confirm`) spends it and answers the 302 the GET used to. An
  unknown, used or expired token still answers the 422 problem on both. The emailed link, the
  hand-off code and `/magic-link/exchange` are unchanged, so API clients that only send and
  exchange keep working; a client that fetched the link itself and expected the 302 must POST.
  **Client-visible:** the GET answers 200 HTML; the magic-link contract fixture is re-recorded and
  the manifest goldens regenerated (227 routes). `plugins/ui` is not involved: the page is the
  plugin's own, fixed bytes. Security review: the page carries no per-link value (the token stays
  in the URL the browser posts to), so it cannot leak it beyond what the link already does; a
  scanner that also submits forms would still spend the link (none known to do so by default).
  Tests: `testAMagicLinkSignsUpRedirectsWithACodeAndExchangesItOnce` (two GETs spend nothing, the
  POST signs in once; failed before: the first GET answered 302), `Example`,
  `examples/signin-methods`.
- **social: unlinking the last credential is one transaction.** `unlink` read the user and its
  accounts and then deleted, so two concurrent unlinks of an account's two providers (no password)
  both passed the check and left no way to sign in. Now the check and the delete are one
  transaction that first locks the user's row with a no-op update (the pattern of
  `orgs.KeepOwner`): row locks on PostgreSQL and MySQL, the write lock on SQLite. A password
  dropped meanwhile (passwordless pre-hijacking cleanup) updates the same row, so it serializes
  with an unlink too. Test: `TestConcurrentUnlinksNeverRemoveTheLastCredential` (ten rounds of two
  concurrent unlinks; failed before: both succeeded), run on SQLite, PostgreSQL and MySQL by the
  matrix.

Left open: `polaris_sentinel_decision` keeps the email address of past sign-in attempts after an
erasure. It is keyed by address, not user id, and `event.UserDeleted` does not carry the address
(the row is already a tombstone when it is dispatched); erasing it needs the address passed along
or a retention prune, a separate change.

## 66. 2026-11-22 — The host API before v1: org-scoped sessions, invitations, host transactions, dev secrets

Writing the six example programs turned up everyday host tasks the host surface (API.md §1) could
not do without the plugin SDK, `p.Graph()` or a copied workaround. v1.0.0 freezes that surface, so
they are closed now. Each change is additive; tests were written first.

- **`SignIn.OrganizationID`.** An in-process session could not be scoped to an organization
  without an HTTP `POST /auth/switch-org` (the agents example did that against its own server).
  `Sessions().Issue` with `OrganizationID` checks what the route checks (an active organization,
  else `ErrNotFound`; an active membership, else `ErrForbidden`) and runs the sign-in and the
  switch in one transaction, so a refusal opens nothing; the events are the route pair's
  (`user.logged_in`, `auth.org_switched`). It reuses `identity.SignIn` and
  `session.SwitchOrganization` unchanged. Rejected: a new `identity.SignIn` taking an
  organization (another agent is changing identity; the two calls already compose).
- **`Orgs().Invite(ctx, organizationID, inviterUserID, email, roles...) (Invitation, string,
  error)`.** Invitations reached a host only through `notify.Mailer` (the b2b test kept a mailer
  to fish tokens out). It calls `orgs.Service.Invite`, so the rules, the event and the audit are
  the route's; `orgs.Invitation` gained a `Token` field (the plaintext, set only on what `Invite`
  returns) so the token need not be scraped from the event. The caller is trusted (no
  `members.invite` check) but an inviter is required and the escalation guard stays: an
  invitation never grants more than its inviter holds, from Go as over HTTP. The token is a second
  return value, not a field of `polaris.Invitation`, so the struct can be logged and encoded
  without leaking it. The configured mailer still receives `member.invited`, as for the route.
  Rejected: a system-actor invitation without an inviter (it would bypass the escalation guard and
  needs a new path in `orgs`).
- **Package `event` joins §1.** `Config.Listeners` takes `event.Listener`, so §1's "a host needs
  no other package" was false. Aliasing `Event`, `Listener` and some 40 event types in `polaris`
  would give every event two names and a listener's type switch two spellings; `event` is small,
  already stable (§2) and named by `Config`, so it is listed instead. Rejected for now:
  `Hooks.OnOrgCreated`. `org.created` reaches listeners (after the commit, below), and a host that
  needs the organization's row in the same transaction creates it with `p.Orgs().Create` inside
  `db.Tx`; adding a hook field later is not a breaking change.
- **`sqlstore.Store.Conn(ctx) Conn`.** Hooks could reach the account's transaction only through
  `Store.Exec` / `FindOne` (not in §1; `Exec` returns no rows). `Conn` returns the transaction ctx
  carries (a `Store.Tx`, a savepoint of one, `WithTx`'s) or else the pool, as the interface `*sql.DB`
  and `*sql.Tx` share (`ExecContext`, `QueryContext`, `QueryRowContext`), so a hook writes the
  host's rows with plain `database/sql`. Statements go to the driver as written: `$1` on PostgreSQL,
  `?` on MySQL and SQLite (documented on `Conn`). This is the formerly unexported `conner`.
- **Events wait for the commit of a `Store.Tx`.** Under a host transaction, events (and so the
  verification and invitation mail the notify listener sends) were dispatched when Polaris's part
  was done, before the host committed: a rolled-back signup still mailed. Now the default
  dispatcher is wrapped (`wiring.deferUntilCommit`) so that an event raised inside a
  `sqlstore.Store.Tx` is queued on that transaction (`Store.AfterCommit`) and dispatched right
  after the outermost commit, in order, with the ctx it was raised with (which no longer joins the
  finished transaction, so a listener's writes use the pool); a rollback drops the queue, and a
  rolled-back savepoint drops what it queued. The wrapper finds `AfterCommit` through `Unwrap`, so
  `telemetry/otel.Store` keeps it; an adapter without it (memstore) dispatches at once, as before.
  `Store.Tx` is therefore the host's transaction (`db.Tx(ctx, fn)`, writes through
  `db.Conn(ctx)`), and the hooks example uses it. `sqlstore.WithTx` (a host's own `*sql.Tx`) is
  unchanged and documented: Polaris cannot see that commit, so its events go out before it.
  Polaris's own code dispatches after its transactions return, so outside a host transaction
  nothing changes for routes or Go calls; a listener that ran inside an enclosing transaction now
  runs after it, in its own. Rejected: a transactional outbox table (durable delivery is a
  separate feature; this only stops sending what never committed); wrapping `*sql.Tx` to see
  `Commit` (a host's ORM owns its transaction type). Delivery is still at-most-once: a crash
  between the commit and the dispatch loses the events, as a crash after any commit did before.
  Tests: `TestStoreTxDefersEventsUntilCommit` (no event or mail inside the transaction or after its
  rollback; both after the commit; failed before: `user.registered` and the mail inside),
  `TestAfterCommitWaitsForTheOutermostCommit`, `TestConnJoinsTheTransactionCarriedByCtx`,
  `ExampleStore_Tx`.
- **`ErrEmailNotVerified`.** `Sessions().Issue` refused an unverified account with a bare
  `ErrForbidden`. The new sentinel wraps `ErrForbidden`, so `errors.Is` matches both and existing
  checks keep working; `Issue` documents the rule (`Auth.Flows.RequireVerifiedEmail`, on by
  default) and the fix (`NewUser.EmailVerified`).
- **`DevEnv(issuer)` and `EnvDev`.** Five examples carried the same 30-line generator of `APP_KEY`
  and an RS256 pair. `polaris.DevEnv` sets what `FromEnv` reads and the environment lacks, logs a
  warning per generated value, and refuses (an error naming the fix, nothing set) unless
  `POLARIS_DEV=1` is in the environment: a binary that still calls it cannot boot in production on
  a throwaway `APP_KEY` (which would make encrypted MFA secrets unreadable after a restart) unless
  someone sets that variable there on purpose. The examples now run with `POLARIS_DEV=1 go run
  ./examples/<name>`. Rejected: defaulting to development when the variables are missing (the
  accident this prevents); detecting `go run` from the executable's path (clever, and wrong for
  `go build` in a dev loop); a `FromEnv` option (its variadic plugins leave no room).
- **`polaristest.Hasher()`.** A host whose tests call `polaris.New` themselves hashed with the
  production Argon2id (64 MiB): the examples' `-race` tests took 45–92 s each. `Hasher` is the
  hasher `polaristest.New` already used (Argon2id at 1 MiB, one pass; the same format), named so
  `cfg.Hasher = polaristest.Hasher()` reads as test-only; the examples' tests pass it through a
  `tune` argument of `newServer` and now take 2–8 s.
- **Small ones.** `Store.Close()` closes the pool. `p.Wrap(h)` applies `Config.Middleware` to a
  host route that `Protect`, `Require` and `Authenticate` do not wrap (the hooks example wrapped its
  public signup by hand). SSO offline needs no new affordance: `sso.Config.HTTPClient` (reaching a
  local IdP; the default reaches public addresses only) and `sso.Config.Domains` (a fake
  `DomainVerifier`) exist and are now documented in llms.txt as test and laptop settings; a
  `polaristest` switch that relaxed the SSRF guard or domain proof would be one setting away from
  production.

API.md §1 lists the new names (`DevEnv`, `EnvDev`, `Polaris.Wrap`, `Invitation`, `Orgs.Invite`,
`ErrEmailNotVerified`, `Store.Tx`/`Conn`/`AfterCommit`/`Close`, `Conn`, `polaristest.Hasher`, and
package `event` for listeners); `scripts/api-stable.txt` already covers them (whole packages).
Security review: `DevEnv` cannot set a secret without the explicit flag and never replaces one
already set; the invitation token is returned once, as the event carried it, and is not part of
the loggable struct; `SignIn.OrganizationID` applies the switch route's membership checks and the
escalation guard still bounds `Invite`. The event deferral changes when listeners run, not what
they see; the audit listener keeps writing every committed event.
