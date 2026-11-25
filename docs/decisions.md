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

## 68. 2026-11-22 — Account boundaries: what an organization's IdP may reach, the first proof of a mailbox, verification links

Three ways across an account's boundary, found by a security review with running tests, all
closed. Each is client-visible; the changelog lists what a host or client sees.

- **sso: an organization's IdP signs in only the accounts the organization owns (supersedes the
  rule of #43).** #43 let a provider sign in an existing account that was "already a member of that
  organization or its email domain is verified for it". Membership was the mistake: any user can
  create an organization, configure an IdP that asserts any email, and invite people; a person who
  accepted became an account that organization's IdP could open, with a session like any other.
  Now a provider signs in an existing account only when (`owns`) one of the organization's
  providers created it just in time (a new table, `polaris_sso_account`, written with the account),
  one of its SCIM directories created it (`scim.Plugin.Provisioned`: the provenance row carries the
  account's creation time, the test SCIM's own `owns` already used), or the account's email domain
  is verified for the organization. Anything else answers `sso/user_unknown`. An IdP LogoutRequest
  ends sessions under the same rule (it was "members"). An unverified account on a verified domain
  is proven by the sign-in (below). **Break, deliberate:** accounts a provider created before this
  release have no record; they sign in again once the organization verifies their domain, or the
  host records them (`sso.Plugin.MarkProvisioned`). No heuristic can tell them from a member who
  signed up alone, so none is tried. Run `Migrate` (one new table).
- **sso: the session an IdP opens is bound to its organization.** Even for an account the
  organization owns, whoever runs the IdP is not the account holder, and #43's session was a full
  one: fresh `auth_time`, no MFA gate, free to `switch-org` to any other organization of the user
  and to change the password, factors and keys. The binding is the session's `amr` holding `sso`
  (already stored on the refresh-token row and minted into every access token, so there is no
  schema change and sessions issued before the upgrade are bound too); `token.Token.OrganizationBound`
  reads it. Enforced in four places: `session.SwitchOrganization` refuses another organization
  (`ErrOrganizationBound`, 403); `session.StepUp` keeps `sso` in the amr (`sso,otp`), so proving a
  factor does not unbind it; the pipeline's authorization step refuses a bound session
  (`pipeline.DeniesBound`) on every route that needs no permission and writes, destroys or is a
  step-up route, which is the rule that already keeps delegated credentials off the account
  holder's routes (`pipeline.DeniesDelegate`), minus logging out of the session itself; and
  neither the token (`session.Mint`) nor `authz.Gate` (`Caller.OrganizationBound`) gives a bound
  session the superadmin override, while the provider refuses to sign a superadmin in at all.
  Routes with a permission stay open to it in its organization, step-up ones included: the IdP
  sign-in is the recent authentication there, and nowhere else, since it cannot leave. The rule is
  by route shape, not a list, so a new self-service route is closed to bound sessions by default.
  Hosts see `Principal.OrganizationBound`. Consequence accepted: a user whose only way in is the
  IdP cannot enroll a factor, mint an API key, approve an OAuth client or register an agent; they
  sign in to the account itself for that. Reads without a permission (`/auth/me`, the lists of the
  user's sessions, organizations, factors, keys) stay open.
- **One operation for the first proof of a mailbox: `identity.Service.ProveEmail`.** An account
  can exist before anyone proved its address (a registration never verified; a social sign-up
  whose provider did not vouch for the email). Whoever made it may not own the mailbox, and each
  path that later proved the mailbox cleaned up a different subset: the verification link and the
  password reset nothing (the reset did not even mark the account verified), a passwordless
  sign-in the password, a trusted social link the password, the sessions and the other provider
  links. So a provider account linked before the proof stayed a way into the account after its
  owner verified it or reset its password. Now every path calls `ProveEmail` (through
  `wiring.Identity`, decision 51) and nothing else writes `email_verified_at` on an existing
  account: core's verification link and reset, passwordless email codes, magic links and reset
  codes, the trusted social link, SSO. On the first proof of an account it marks it verified and,
  in one transaction, drops the password and lockout state, the MFA factors, recovery codes and
  pending challenges, what the plugins hold (a new optional interface, `wiring.AccessEraser`:
  social links, passkeys, API keys, OAuth consents, tokens and codes, agents and hosts, the
  passwordless phone and pending secrets; each reuses its erasure code, run inside the
  transaction rather than from an event), and every session; then dispatches
  `user.email_verified`. On a proven account it does nothing. A reset then sets the new password
  in the same transaction. One distinction is kept, as a parameter: a registration's own
  verification message (core's link, the passwordless `verify-email` code) confirms the
  registration, so when the account has a password it is marked verified and nothing is removed
  (removing would add nothing: whoever holds that password could put it all back, and dropping
  the password would break every registration); an account without a password has no
  registration to confirm and gets the full first proof.
- **social: no account and no link for an email the provider does not vouch for, when no session
  opens.** With `RequireVerifiedEmail` (the default) the sign-up committed the account and the link
  and then refused the session, leaving both waiting in the address's name. It now refuses first
  (`social/email_unverified`, same status; nothing written). With `RequireVerifiedEmail` off the
  account is created and signs in as before, and the first proof removes the link.
- **ui: opening the verification link verifies nothing.** `GET /auth/ui/verify?token=` verified at
  once (#57 reasoned that verification is idempotent and signs nobody in). Mail scanners follow
  links, so a registration made with someone else's address was confirmed by that person's mail
  system. The GET now renders the page with the token in a hidden field and one button; the
  CSRF-guarded POST verifies, as #61 did for magic links. Core has no GET verification route
  (`POST /auth/email/verify` only). A host template overriding `verify.html` keeps working (its
  field arrives filled).

Security review (rule 6), per item:

- *IdP ownership.* Only refuses more, except SCIM-created accounts, accepted on the record SCIM's
  own ownership check trusts. `MarkProvisioned` is in-process, for the host. Residual: an
  organization that verified a domain can sign in every account on it, by design (it controls
  those mailboxes). Tests: `TestAMembershipDoesNotLetTheOrganizationsIdPSignTheMemberIn` (failed
  before: the member was signed in), `TestTheAccountsAnOrganizationProvisionedAreItsIdPsToSignIn`,
  `TestAnOrganizationsIdPCannotClaimOutsideAccounts` (unchanged, passes).
- *Bound sessions.* The marker is inside the signed token and on the server-side session row; a
  client cannot remove it, refresh restores it from the row, step-up preserves it. Paths that mint
  a session or a credential from a session (multi-session switch, one-time tokens, OAuth consent,
  API keys, agents) are all permission-less writes and so refused. Residual: a service that
  resolves an actor's authority itself from the user id does not see the binding; with the
  sign-in refusal and the refusals above that leaves reads by an account made superadmin while its
  bound session lives. Tests: `TestAnSSOSessionStaysInItsOrganization` (HTTP; failed before:
  switch-org, password change, factor enrolment, account deletion all answered 200),
  `TestAnSSOSessionCarriesNoSuperadminOverride` (failed before),
  `TestAnIdentityProvidersSessionStaysBoundToItsOrganization`, `TestAuthorization` (bound cases),
  `TestAnOrganizationBoundCallerNeverHoldsTheSuperadminOverride`.
- *First proof.* One transaction: a failure in any plugin's removal rolls the proof back
  (`TestAFailedFirstProofChangesNothing`); concurrent proofs run the removal once (a conditional
  update claims it); sessions are revoked last because the denylist watermark is in the cache.
  Nothing is weakened: every path removes at least what it removed before. Residual, inherent to
  confirming a registration by link: a person who confirms a registration they did not make
  leaves its password holder in control; the page says so. Tests:
  `TestAnUnvouchedEmailLeavesNoAccountAndNoLink` and
  `TestTheFirstProofOfTheMailboxRemovesWhatCameBefore` (social, HTTP; both failed before: the
  account and link were created, and the link survived the owner's reset and signed in),
  `TestTheFirstProofOfAMailboxRemovesEveryWayIn` and
  `TestConfirmingARegistrationKeepsWhatItsPasswordHolderHas` (every plugin booted, a row in every
  access table), `TestAResetIsTheFirstProofOfAnUnprovenMailbox`,
  `TestTheVerificationLinkConfirmsARegistration`, passwordless
  `TheFirstProofOfTheMailboxRemovesWhatCameBefore`.
- *Verification page.* The token stays in the page the link already names; the POST needs the
  same-origin `Origin` and the signed double-submit token of #57. A scanner that also submits
  forms would still verify (none known to by default). Test:
  `TestOpeningTheVerificationLinkVerifiesNothing` (failed before: the GET verified).

Contract fixtures replay unchanged (no recorded exchange crossed these boundaries); the route
specs of the changed routes describe the new behaviour. Breaking for `make apicheck` only: the
narrow interface `wiring.Identity` gains `ProveEmail`, which API.md §2 allows without notice (only
Polaris implements those interfaces). Otherwise the API is additive (`wiring.Identity.ProveEmail`,
`wiring.AccessEraser`, `token.AMRSSO`, `Token.OrganizationBound`, `authz.Caller.OrganizationBound`,
`polaris.Principal.OrganizationBound`, `pipeline.DeniesBound`, `session.ErrOrganizationBound`,
`sso.Plugin.MarkProvisioned`, `sso.TableAccounts`, `scim.Plugin.Provisioned`,
`identity.Config.OnEmailProven`).

Left open: existing databases may hold provider links made before this release on unverified
accounts; they go at the account's first proof. On accounts already verified they cannot be told
from the owner's own links by Polaris; a host can list the `polaris_social_account` rows created
before their account's `email_verified_at`. Bound sessions keep the permission-less reads.

## 67. 2026-11-22 — Only the system role is the superadmin

The security review for v1 (docs/v1.md 4.2) found that the platform superadmin was recognised by
slug: `authz.Authority.IsSuperadmin` is `Roles` containing "superadmin", and the resolver filled
`Roles` with the slugs of the member's roles in the active organization. `orgs.CreateRole` accepted
the slug "superadmin" in any organization (the system superadmin role is not copied into
organizations, so the slug was free). An organization's owner could therefore create a role
slugged "superadmin", take it, and be treated as the platform superadmin by every check that reads
the authority or the token's `roles` claim: the cross-organization guard, the "you cannot grant
what you do not hold" rule, and the plugins' organization routes (sso, scim, oauth clients, audit).

- The resolver never puts "superadmin" into an organization's authority: only `isSuperadmin`
  (membership in the system role, `organization_id IS NULL`) yields `RoleSuperadmin`. An existing
  organization role with that slug becomes an ordinary role (its permissions, in its organization).
- `orgs.CreateRole` refuses the slug ("This role slug is reserved.", 422).
- `authz.Seed` never copies a superadmin template grant into organization roles of that slug.

Security review: the fix removes the only path from an organization role to the override; every
consumer reads the authority or the `roles` claim minted from it. An access token minted before the
upgrade keeps its claim until it expires (`AUTH_ACCESS_TOKEN_TTL`, 15 minutes by default); turning
on `AUTH_ACCESS_TOKEN_DENYLIST` and revoking sessions ends it sooner. Hosts should look for
organization roles slugged "superadmin" (`SELECT * FROM auth_roles WHERE slug = 'superadmin' AND
organization_id IS NOT NULL`) and review their audit log for what such members did. Tests:
`TestAnOrganizationRoleSluggedSuperadminIsNotTheSuperadmin` (authz, every backend) and the
reserved-slug refusal in `TestCreateRoleRefusals` (orgs).

## 69. 2026-11-22 — Authorization bounds: OAuth scopes, operator reach, second-factor attempts

Seven findings of a security review, each reproduced by a failing test before its fix. Released
as v0.5.1.

- **oauth: a permission scope is granted only to a subject that holds the permission.** A scope
  that is a permission name was granted to whoever asked: on consent, on the device and CIBA
  grants, on a token exchange and to `client_credentials`, limited only by the client's own
  `scopes` list (empty: every scope). The host was not affected, because its resolver intersects
  the token's scopes with the user's authority on every request (a client acting as itself
  resolves to nothing). A service that checks tokens without the database (`verify.Require`,
  `mcp.Protect`) had only the `scope` claim, and with a caller-chosen `resource` as `aud` it
  accepted a permission scope the subject never held. Now `tokens.issue`, which every grant goes
  through, keeps a permission scope in the access token only if the subject holds the permission
  at that moment: a user, by `authz.Resolver` in the token's organization; a client acting as
  itself, only when an operator registered it `trusted` with the permission in its `scopes`, or
  when a plugin that owns the client answers for it (`oauth.ClientAuthority`, new: `plugins/agents`
  answers the permissions of the agent's live grants that its owner holds). The refresh token
  keeps the consented scopes and each refresh and exchange is bounded again, so a lost permission
  leaves at the next token and a regained one returns. An organization's client route can no
  longer change the `scopes` of a trusted client (they are now that client's authority).
  Non-permission scopes (`openid`, `profile`, `email`, `offline_access`, `Config.Scopes`) are
  granted as before. **Client-visible:** a token response's `scope` (and the token's) may list
  fewer scopes than requested, which RFC 6749 §3.3 allows; `PATCH /orgs/{id}/oauth/clients/{id}`
  answers 400 `invalid_client_metadata` for a changed `scopes` on a trusted client. One agents
  fixture step is edited (a user without the permission exchanging for `members.read` now gets
  `"scope": ""`). `oauth.Plugin.IssueTokens` is bounded the same way. The `verify` package
  documentation said `Claims.Scopes` are the permissions the token was issued with; it now says
  what a permission scope proves and that any other scope proves only what the client asked for,
  and `mcp.Protect` says the same.
  Security review: the bound is in the one function that mints access tokens, so no grant skips
  it; it only removes scopes. A trusted client's listed scopes are set by an operator (`own`) or
  the Go API. Left as is, and documented: a non-permission scope of `Config.Scopes` is still
  granted to any client allowed to ask for it, a self-registered one included, so it is not proof
  of authority for a remote verifier. Tests: `TestAClientHoldsNoPermissionScopeOfItsOwn`,
  `TestAUsersPermissionScopesAreBoundedByTheirAuthority` (issue, refresh, exchange),
  `TestOnlyAnOperatorChangesATrustedClientsScopes`, `TestAnAgentsOwnTokenIsBoundedByItsOwnersAuthority`;
  the oauth fixtures replay unchanged.
- **admin: `Manage` on an account does not reach up.** Ban, unban, set password, remove a factor,
  reset MFA and delete checked only the caller's `Manage` capability, so an operator with the
  `admin` role could set the password or reset the MFA of an `owner` operator or a superadmin and
  sign in as them; impersonation already refused a superadmin. Now one helper, `manageUser`, used
  by those six routes: below `RoleOwner`, the target may not be a superadmin (whatever the
  account's status, so a disabled one cannot be unbanned from below) nor hold an operator grant of
  the caller's role or above. **Client-visible:** such a request answers 403 `admin/forbidden`.
  Session revocation (`Support`) and member-role changes are unchanged: they do not give the
  caller the target's credentials. Security review: only refuses more; an owner's reach is
  unchanged. Test: `TestOnlyAnOwnerManagesAnEqualOrHigherOperatorOrASuperadmin` (admin key and
  admin user against an owner, a peer admin and a disabled superadmin, six actions each; a support
  operator's account and an owner caller still pass). The admin fixtures replay unchanged.
- **mfa: second-factor attempts are limited per user.** Wrong codes at `/auth/mfa/verify` and
  step-up were limited per IP only (`mfa_confirm`); the password lockout counts password failures,
  and the `login_mfa` ticket is stateless, so whoever held the password could mint tickets and
  keep guessing TOTP or recovery codes from many addresses. Now `VerifyLogin` and `VerifyStepUp`
  count every attempt of the user before checking it (in the cache, as the OTP send budget is) and
  a code that clears resets the count: after `auth.lockout.max_attempts` attempts that did not
  clear, every code, a right one and a recovery code included, is refused as a wrong one
  (`ErrInvalidOTP`, the same 422) until `auth.lockout.lock_duration` has passed since the first.
  No new setting. **Client-visible:** a user who mistypes the second factor five times waits up to
  15 minutes (defaults) and sees the wrong-code answer meanwhile. Security review: the refusal
  discloses nothing a wrong code does not; the counter is atomic within a process and, like the
  send budget, not across replicas (the per-IP limit bounds the residual). Whoever holds the
  password can make the second step unavailable for the window, as with the password lockout.
  Test: `TestRepeatedWrongSecondFactorCodesCloseTheGateForAWhile`.
- **mfa: an OTP attempt is reserved before the compare.** `VerifyOTP` read the challenge, compared
  the code, and only then spent an attempt, so requests in flight together could each get a
  compare beyond `max_attempts`. Now the conditional UPDATE (`attempts < max_attempts`) runs first
  and the code is compared only if it applied, as `plugins/passwordless` does; a right code spends
  an attempt too. Test: `TestACorrectCodeIsRefusedWhenTheBudgetWasSpentAfterTheRead` (the budget
  is spent between this request's read and its compare; memory and SQLite).
- **ui: `/refresh` does not rotate for a navigation another site started.** `GET /auth/ui/refresh`
  rotates the refresh token and the cookie is `SameSite=Lax`, so another site could navigate the
  browser there; two such navigations carrying the same cookie read as a reused token and end the
  session family. Now a request whose `Sec-Fetch-Site` is neither `same-origin` nor `none` gets a
  page with one link to the same URL (messages `refresh_title`, `refresh_intro`), and following it
  renews the session. Chosen over a reuse grace period in core, which would weaken reuse
  detection for every client. **Client-visible:** a user who arrives from a link on another site
  with an expired access cookie sees that page once instead of being returned at once. A browser
  that sends no `Sec-Fetch-Site` is served as before. Security review: refuses more; the link is
  built from the validated `return_to`. Test: `TestANavigationFromAnotherSiteDoesNotRotateTheRefreshToken`.
- **agents: a request JWT's `aud` is compared with the configured origin.** On the plugin's own
  routes the expected `aud` was built from the request's `Host` header and `r.TLS`, so a JWT an
  agent signed for another server was accepted when that server forwarded it with its own `Host`.
  Now it is the called path on `Config.BaseURL`'s origin (default: the oauth plugin's base URL),
  as `plugins/ui` does; a TLS-terminating proxy no longer needs `r.TLS` set for these routes.
  Host routes behind `Protect` / `Guard` still compare with the URL as requested (a bound
  `Protect` may be mounted at any URL), which the README now states. Requiring `htm` was
  considered and left optional: `jti` is single-use and existing agents may omit it.
  **Client-visible:** an agent that reached Polaris under a host name other than the base URL's
  now gets `aud_mismatch`. Test: `TestARequestJWTForAnotherOriginIsRefusedWhateverTheHostHeader`.
- **verify, mcp.Protect: a failed JWK Set fetch is remembered for 5 seconds.** The fetch runs under
  a mutex, so while the issuer was down every request waited for the one before it to time out.
  Now a failure is kept for `jwtverify.FailureBackoff` and requests that need a fetch answer
  `ErrUnavailable` (503) at once; a fetch that failed because its own request was cancelled is
  not remembered. A cached set inside its TTL keeps verifying as before. Test:
  `TestAFailedJWKSFetchIsRememberedBriefly`.

## 65. 2026-11-22 — Plugins speak Go on the wire

The plugins still reproduced behaviours of the language they were ported from (#53, #58): offsets
written `+00:00`, numbers read from any numeric-looking string, `[]` standing in for `{}`, a
boolean cast to `"1"` or `""`, JSON with `\/` and `\uXXXX`, the error texts of PHP libraries.
After v1.0.0 changing any of them needs v2, so each is removed now, deliberately, under rules 4
and 5: what a client sends is read strictly, what it reads is conventional Go, and stored rows,
issued receipts and hash chains keep reading and verifying. Tests first in each plugin (the
`wire_test.go` files and the tests named below). Contract fixture contents are edited where a
client-visible text changed (file names unchanged); the normalizer already masks datetimes and
treats `{}` and `[]` alike, so timestamp-only changes needed no fixture edit (the SCIM fixtures
were brought up to date anyway).

### 1. Timestamps: RFC 3339 with `Z`

Every `dateAtom` layout (`2006-01-02T15:04:05-07:00`) is gone: admin, apikeys, agents, audit,
multisession, oauth, passkey, scim, sentinel, social and sso write `t.UTC().Format(time.RFC3339)`,
so UTC is `Z`. admin and passkey did not convert to UTC first: a key or grant created with
`expires_at: "2030-01-01T00:00:00+02:00"` echoed the offset and now answers
`2029-12-31T22:00:00Z`. Inputs keep accepting both forms (`time.RFC3339` parsing reads either), as
does sentinel's re-parse of its stored `created_at`.

Kept, because a hash covers the text:
- **Audit hash chain.** `hashOf` hashes the event's wire keys; it now formats `occurred_at` as
  `+00:00` inside the hash computation only (`hashedTimeLayout`), while `Event.Map` gives clients
  `Z`. `canonicalJSON` and the stored `data` text are byte-identical. A chain written by an
  earlier release keeps verifying and new rows chain onto it
  (`TestAChainWrittenByAnEarlierReleaseKeepsVerifying`, a row carrying the hash the old code
  computed; `TestClientsReadZTimesWhileTheHashKeepsItsForm`; `TestTheHashIsOverTheCanonicalForm`
  unchanged). Data values of new events (`user.locked` `until`, the prune checkpoint's `before`,
  the api-keys events' `expires_at`/`grace_until`) are written `Z`; old rows keep their text.
- **Agent receipts.** A receipt's `created_at` stays `+00:00` (`receiptTime`): `Receipt.hashed()`
  covers that text and the Go agent SDK hashes it as received, so a change would break every
  receipt chain already issued (`TestAReceiptHashesItsCreationTimeInTheIssuedForm`; the SDK's
  `receipt-chains.json` vectors pass). The receipts route keeps showing `+00:00`.

Client impact: every timestamp a plugin route answers ends in `Z` instead of `+00:00`, the audit
file and webhook sinks too. RFC 3339 parsers read both.

### 2. JSON

- **To clients:** standard Go encoding. The audit `FileSink` and `WebhookSink` write
  `json.Marshal` output (UTF-8, `/` unescaped, `{}` for an empty object, `<>&` escaped as Go does)
  instead of the hash chain's canonical form; the HMAC is over the bytes sent, so receivers still
  verify (`TestTheSinksWriteStandardJSON`).
- **Stored, writer switched** (every reader decodes both forms; each proven by a test reading a
  row in the old form): admin's `ip_allowlist` (`TestAKeyStoredWithEscapedSlashesStillReads`); sso
  provider `config`, `attributes`, `jit`, `redirect_uris` (`escapedJSON` and the ordered `object`
  are deleted, `store.JSONValue` writes them; `TestProviderRowsAreStandardJSONAndOldRowsStillRead`
  reads `[]`, `\/`, `Ü` and a surrogate pair); passwordless secrets' `data` (`escapedJSON`
  deleted, nil written `{}`; `TestTheDataColumnReadsBothForms`). None is hashed, signed or
  compared byte for byte. The lenient readers stay.
- **Not changed, byte for byte:** the audit trail's `canonicalJSON` (stored and hashed) and the
  agents receipts' `canonicalJSON` (hashed, verified by the SDK). Changing their bytes would break
  every chain and receipt already written.

### 3. Strict numbers, booleans and strings

- **Limits and paging.** `positiveInt` in admin, audit, sentinel, sso and scim reads a JSON
  integer or a query value of ASCII digits (`strconv.Atoi`, no trimming); `1.5`, `2.0`, `1e1`,
  ` 2`, `+2` and overflow answer 422 with each plugin's existing code. The default for an absent
  value and the clamp to the maximum are unchanged. SCIM `startIndex`/`count` (`integer`,
  `paging`) take an integer (an optional sign; below 1 still reads as 1, RFC 7644 §3.4.2.4);
  anything else is 400 `invalidValue`, audited as a refused request. agents `after`/`limit` on the
  receipts route are 422 `invalid_input` instead of truncating or silently falling back.
- **SCIM `active`** is a JSON boolean (RFC 7643) or the string `"true"`/`"false"` in any case, in
  POST, PUT and PATCH; `"on"`, `"yes"`, `"1"`, other strings and numbers are 400 `invalidValue`
  ("active must be a boolean (true or false, or the string "true" or "false")."). Before, PATCH
  read `"True"`/`"on"`/`"yes"`/`"1"` as true, and POST/PUT activated an account sent `"false"`.
  The two strings are not leniency kept from the port but interoperability with the most common
  SCIM client: Microsoft Entra ID sends `{"op":"Replace","path":"active","value":"False"}` by
  default, unless the application's Tenant URL carries `?aadOptscim062020`; refusing it would
  stop Entra from deprovisioning anyone. Op names were already matched in any case (RFC 7644
  §3.5.2). Tests: `TestActiveIsAJSONBoolean`, `TestEntraIDsPatchOfActiveWorks` (Entra's exact
  PATCH bodies deactivate and reactivate).
- **agents.** `max`/`min` constraints take a JSON number (a numeric string violates the
  constraint: fail closed); `in`/`not_in` compare numbers by value (`1`, `1.0`, `1e0` equal; int64
  exactly, else float64, no unbounded-precision parsing of client numbers), which closes a
  `not_in: [1]` bypass with `1.0`. `rowJSON` keeps reading stored JSON with `json.Number` (exact
  values); only its comment changed.
- **Casts.** mcp sends a boolean tool argument as `true`/`false` (was `1`/empty) and refuses an
  object, list or null path argument with JSON-RPC `-32602`; messaging renders a boolean variable
  `true`/`false`; apikeys reads `name` only as a JSON string (`true` was `"1"`); social reads a
  provider's string or number subject and gives `""` for a boolean (the existing empty-subject
  refusal applies; a float id keeps its old text so stored subjects still match); social
  `expires_in` must be an integer (garbage meant "expired at once", now "unknown").
- **Trimming.** The exact set `" \t\n\r\x00\x0b"` is kept wherever the value is stored or compared
  with stored values, so existing rows still match: usernames (`UserID`, `Set`, the sign-in
  identifier), admin key names (NUL never reaches a column), oauth client names, sso provider
  `name`/`issuer` and domains, scim display and name parts, `externalId`, group names, connection
  names, organization ids and cursors, passwordless email, phone, token, code, `redirect_uri` and
  `purpose`. `strings.TrimSpace` elsewhere: the SCIM filter string (parsed, not stored), agent and
  host names (labels, never looked up), social's blank test. Each kept site says why. An agent or
  host name containing a NUL or another control character (anywhere, not only at the ends) is
  refused with the empty name's 422 `invalid_input`, so PostgreSQL never sees it (it refuses NUL in
  text: a 500 before) (`TestAgentAndHostNamesRefuseControlCharacters`).

### 4. Arrays standing in for objects, objects for lists

Data from outside parties follows its RFC; stored data keeps reading:
- **oauth.** `fetchJSON` refuses a document that is not a JSON object (a list read as `{}`);
  `jwksKeys` requires `keys` to be an array (RFC 7517 §5): registering `jwks` otherwise is 422
  `invalid_client_metadata`, a `jwks_uri` document otherwise `invalid_client`. Registration used to
  store `keys` as an object; `storedJWKSKeys` still reads such a row, in key order
  (`TestAKeySetIsAnArrayButAStoredObjectStillReads`); a cached old-form `jwks_uri` document is a
  miss and is fetched again. `verifyWithKeySet` no longer names a key without `kid` by its index:
  a header `kid` selects only the key with that `kid`; a token without `kid` verifies against the
  set's only key and is refused when there are several (RFC 7515 §4.1.4); a non-string `kid` is
  refused (`TestAKeyIsChosenByItsKidOnly`). Breaking for a registered client whose keys have no
  `kid` and that sent `kid: "0"` (it had to: a `kid` was required): it drops the `kid` (one key)
  or registers keys with a `kid`. Kept narrow on purpose: a compatibility path would keep the
  positional naming forever.
- **sso.** `asMap` and `listOf` are gone: `config`, `attributes`, `jit` must be objects,
  `jit.enabled` a boolean, `jit.roles` and `redirect_uris` lists (422 `sso_invalid_input`, each
  with its message); a PATCH's absent or null field still keeps the stored value. JWKS and
  discovery were already strict.
- **scim.** `members` is a list of `{"value": id}` objects (no `{}`, no bare ids), and a PATCH
  operation without `path` carries an object (400 `invalidValue`).
- **agents.** `arguments`/`input` on `/agents/execute` must be an object or null ("arguments is an
  object."); constraints, their operators and `budget` must be objects (422 `invalid_input`;
  `{"x":["y"]}` was 400 `unknown_constraint_operator`); `capabilities` and `default_capabilities`
  must be lists. Stored grants read an old row's `[]` operators as `{}`
  (`TestStoredConstraintsReadTheirOldForms`).
- **apikeys.** `permissions` must be a list and `metadata` an object; a stored `[]` metadata still
  reads as `{}` (`TestInputIsReadAsItsJSONType`).

### 5. Error texts

The firebase/php-jwt texts in oauth (`jwt.go`, `clients.go`, `dpop.go`), agents
(`requestjwt.go`), sso (`oidc.go`) and social (`outbound.go`) are one Go vocabulary: "the
signature does not verify", "the claims are not a JSON object", "the token is not valid before
<time>" (sso and social: "… yet (nbf)"), "the token was issued in the future (<time>)", "the token
has expired", "the token is not a compact JWS", "no key in the key set has the token's kid", "the
token names no key (kid)…", "the key's alg is not the token's alg". The opis/json-schema texts of
agents' argument validation read as Go (`missing required properties: x`, `/p: must be string,
not integer`, `must be at least N characters, not M`, …; paths are JSON Pointers). Problem titles
in oauth, mcp and agents are sentences with acronyms capitalized ("Invalid DPoP proof", "Invalid
JWT", "Capability not granted"; were "Invalid Dpop Proof", "Invalid Jwt", "Capability Not
Granted"), as the other plugins' titles already were. Error codes and problem `type` URLs are
unchanged. Fixtures edited: the oauth-provider assertion step and titles (six files), the mcp
titles, the agents titles and the `properties not allowed: extra` step.

### 6. Encodings

- oauth `formEncode` is deleted: authorization redirects use `url.QueryEscape` (form encoding of a
  query, space `+`; `~` now unescaped, RFC 3986 unreserved). `basicAuth` keeps
  `url.QueryUnescape` (RFC 6749 §2.3.1).
- mcp path arguments were escaped twice (a space went out as `%2520`); `fillPath` escapes each
  segment once (`url.PathEscape`, `RawPath`) and query arguments go through `url.Values.Encode`.
- social: the authorization request query is form-encoded (`scope=openid+email+profile`, was
  `%20`), RFC 6749 §4.1.1 and Appendix B; token request bodies already used `url.Values.Encode`.
  The five social fixtures are edited at each start/link URL. `proxySignature` (base64url of the
  hex digest) is **kept**: the stable origin behind the proxy verifies it and may run an earlier
  release during a rollout.
- messaging's `htmlEscaper` is `html.EscapeString` (`'` is `&#39;`, `"` is `&#34;`); rendered
  output is sent, never stored or compared.
- sso `validURL` is `net/url`-based and requires an absolute `http`/`https` URL with a host, in
  printable ASCII: `sso_url`, `slo_url` and `slo_response_url` used to accept any scheme
  (`javascript:`, `urn:`), and the browser is redirected to them ("config.<k> must be an http(s)
  URL."). A provider stored with another scheme fails its next PATCH until corrected; it never
  worked with the redirect binding.
- scim `stripSlashes` is gone: a filter value is a JSON string literal (RFC 7644 §3.4.2.2) decoded
  by `encoding/json`; an unknown escape (`\0`, `\x`, `\'`), a raw control character or a NUL
  (`\u0000` or raw) is `invalidFilter`. `é`, `\/`, `\t` and surrogate pairs now decode (`\u`
  gave a literal `u`). `FuzzFilter` fails on a NUL in an accepted value.

### 7. Kept and documented

- **A JWK without `alg` (sso, social)** no longer defaults to RS256: `algorithmOf` infers it from
  the key type (RSA → RS256, EC P-256 → ES256, OKP Ed25519 → EdDSA) and refuses any other key
  without `alg` ("the key names no alg and its type implies none"): P-384/521, symmetric and
  private keys. A key's own `alg` still wins. EdDSA stays outside the accepted id_token
  algorithms, so an EdDSA id_token is still refused at parse
  (`TestAKeyWithoutAlgVerifiesTheAlgorithmItsTypeImplies` in both plugins).
- **An expired IdP certificate in SSO SAML still verifies: kept.** The certificate only carries
  the key the organization admin configured; no chain or revocation is consulted, so the
  configured key is the trust anchor and the validity dates add nothing. Shibboleth SP,
  SimpleSAMLphp and most SAML SPs do the same, and IdPs routinely ship long-lived or expired
  self-signed certificates: refusing them breaks working IdPs for no gain. A rotated or
  compromised key is handled by changing the configured certificate. The reasoning is in
  `saml.go`; `TestAnExpiredIdPCertificateStillVerifies` pins it and checks that a response signed
  by another key is still refused.

Security review. **oauth:** no check is weakened: signature and alg match, `jti` replay,
`sub`/`aud`/`exp`, the time checks and their leeways are unchanged; key selection is stricter (no
index naming); the one new acceptance (no `kid` with a single-key set) still verifies with the
client's own registered key and algorithm; `fetchJSON`/`jwksKeys` refuse more; the new texts reveal
no key material or internal host. **agents:** every change refuses more or compares more strictly
(numeric strings fail `max`/`min`; `in`/`not_in` by value close the `1.0` bypass); the request-JWT
checks (alg, signature, nbf/iat/exp with 60 s leeway, aud/htm/htu/body hash, jti) are unchanged;
receipts' hashed bytes are identical. **passkey:** display of two timestamps only; no ceremony,
verification or counter code touched. **social, sso:** alg inference makes each key verify only
the algorithm its type implies, HMAC and `none` stay excluded and the token's alg must still match
the key's; JWKS `keys` was already an array and a missing `kid` is refused outright (the
single-key fallback of OIDC Core §10.1 is not added); the http(s)-only URL rule rejects
`javascript:` redirects; `proxySignature`, `verifiedFlag` (decision 59), the constant-time
compares and the nonce check are unchanged; the SAML certificate decision above. **scim, admin,
audit:** stricter input only; the audit chain's hashed bytes are identical.

Left open: the route specs' `output.example` timestamps still read `+00:00` (they belong with the
core change, #64), as do `examples/b2b/README.md` and `examples/agents/README.md`.

## 64. 2026-11-22 — Core behaves as Go, not as the port it started from

Decision 58 renamed what read as a port; several behaviours of core still reproduced the PHP
runtime (its date format, its JSON encoder, its loose parsing). After v1.0.0 changing any of them
needs v2, so core drops them now, each deliberately. Scope: core packages (`token`, `manifest`,
`internal/httpapi`, `internal/observe`, `identity`, `orgs`, `mfa`, `notify`, `store`, `pipeline`,
`config`) and the route specs of every plugin under `internal/apispec/api`. The plugins' own code is
decision 65.

- **Timestamps on the wire are RFC 3339 with `Z`.** Core wrote UTC as `+00:00`
  (`2026-06-10T09:00:00+00:00`); it now writes Go's `time.RFC3339` in UTC
  (`2026-06-10T09:00:00Z`): `GET /auth/sessions` (`created_at`, `last_used_at`), `POST` and `GET
  /orgs/{id}/invites` (`expires_at`, `created_at`), `GET` and `PATCH /users/{id}` (`created_at`,
  `last_login_at`, also `identity.UserView`), and the `until` of a `user.locked` audit row. The same
  instant, to the second; every RFC 3339 parser reads both forms, and every timestamp core reads
  (`store.ParseTime`, the CLI's `--expires`) still accepts both. The core specs' examples and the
  OpenAPI goldens follow. **Client-visible** for a client comparing the strings byte for byte.
- **Empty objects are `{}`; JSON a client reads is standard Go JSON.** `manifest.Object` encoded an
  empty object as `[]`, so the exported manifest and OpenAPI documents held `"items": []` for an
  untyped schema (invalid JSON Schema), `"metadata": []` in examples, and an example written `{}`
  typed as an array; MCP tool schemas built from them held `"properties": []`, which a strict MCP
  client refuses. Now `{}` everywhere; an untyped schema is `{}` (any value), an empty mapping in an
  example is `{"type": "object"}`. Token claims: an empty object claim (and an empty claim set)
  encodes as `{}` instead of `[]`, and floats take `encoding/json`'s form (`100000000000000000`,
  not `1.0e+17`; whole-second dates and the six-decimal dates are unchanged). Tokens are verified
  over their own bytes, so tokens issued before keep verifying and the known-answer vectors are
  unchanged. "/" was already unescaped in everything a client reads (`token` and the CLI's
  output); the one `\/` writer was the audit metadata below.
  - **Kept, hashed or signed:** the agents plugin's receipt canonical JSON (`[]` for an empty
    object, `\uXXXX` for non-ASCII; receipt hashes are recomputed from it, decision 65's to keep)
    and the audit plugin's hash-chain canonical form are untouched; neither is core's encoder.
  - **Changed, stored:** core's `auth_audit_log.metadata` (`internal/observe`) is not hashed or
    signed and nothing in Polaris decodes it, so its writer now writes it as every other JSON
    column (`store.JSONValue`: `/` and non-ASCII as they are, `{}` for no fields, `Z`
    timestamps). Rows written before keep their bytes (nothing rewrites them) and decode to the
    same values: `TestAuditRowsOfEarlierReleasesStillRead` reads `[]`, `\/`, `é` and
    `+00:00` rows back through the repository on every backend. PostgreSQL and MySQL already
    stored the parsed form. A host decoding the column into a map now gets `{}` instead of `[]`
    for new rows with no fields.
- **Lenient parsing is gone where the client can fix it; stored data and issued tokens keep
  reading.** Per case:
  - Core routes check each field's JSON type against its spec before the endpoint runs
    (`internal/httpapi.typed`): a `string` field takes a string, a `boolean` field `true` or
    `false`, a `list<string>` field a list of strings; otherwise 422 `{"errors": ["<field> must
    be a string."]}` (or "true or false", "a list of strings"), one message per field. Before, a
    number was read as its JSON text, `true` as `"1"` and `false` as `""` (`authString`,
    `mfaString`), `"0"`, `0`, `""` and empty collections as false and anything else as true for
    `default` (`mfaTruthy`), and orgs routes read a non-string as absent. A null or absent field is
    left to the endpoint as before. **Client-visible:** a client sending `"code": 123456` or
    `"default": "1"` gets 422 and must send `"123456"` / `true`.
  - `manifest`: a `max:` rule's argument must be a whole number of characters (`max:10abc`
    read as 10, `max:abc` as 0; now the spec fails to load, naming the rule). `$` in the `regex`
    and `e164` rules is Go's end of text (it also matched before a final newline); the `D`
    modifier is accepted and changes nothing, `m` still makes `$` an end of line. New org slugs
    lose the trailing newline the slug check let through; stored slugs are never re-checked.
    Only specs and new input are affected. **Client-visible:** `"+15551234567\n"` and a slug
    `"acme\n"` are 422.
  - `store.Row.Bool` reads text with `strconv.ParseBool` (`1`, `t`, `T`, `TRUE`, `true`, `True`
    are true). It no longer reads `y`, `yes` or other casings of `true` as true. Kept lenient on
    purpose for what drivers hand back: Polaris writes booleans as booleans, which the drivers
    return as `bool`, an integer, or the text `1` / `t`, all still read. No stored value Polaris
    or the drivers produce reads differently.
  - `token`: a date claim (`iat`, `nbf`, `exp`) must be a JSON number and not negative; numeric
    strings (`" 1780833601.5 "`) and negative dates fail the token. `aud` must be a string or a
    list of strings (RFC 7519 §4.1.3); `null`, a number, an object or a list holding a
    non-string fail the token (before, an object contributed its values and a scalar became a
    one-element list). Polaris has always written dates as non-negative numbers and `aud` as a
    string or a list of strings, and the codec only accepts tokens signed with Polaris's own keys,
    so no issued token stops verifying; fractional dates still read to the microsecond.
  - Kept lenient, with the reason: `security.leadingInt` reads the counts of the breached-password
    range API (an external service's response, read defensively); `manifest`'s spec loader still
    reads YAML scalars loosely (`truthy`, `scalarString`) since specs are code reviewed with the
    package, not client input; the contract-test normalizer keeps its `\n?$` masks, which must
    match what the fixtures were normalized with.
- **The email rule is Polaris's own, unchanged.** `manifest.IsEmail` is documented as the rule
  itself (ASCII local part of atoms or quoted strings up to 64 units, a host name of two or more
  labels or a bracketed IPv4 / tagged IPv6 literal, 254 units in all) instead of as a translated
  PHP filter. The accepted set does not change: narrowing it would lock out accounts whose
  addresses passed it, widening it would admit addresses that never did. `testdata/manifest/email.tsv`
  and the new `TestEmailRuleEdgeCases` (case, whitespace, CR/LF, NUL, leading zeros, IDNs, label and
  local-part lengths) pin it. Normalization of stored addresses is unchanged byte for byte:
  `TestNormalizeEmailTrimsAndLowersASCIIOnly` gains form feed, `İ`, NUL/VT and inner-space cases, and
  `TestNormalizeEmailIsIdentitysRule` checks `orgs` normalizes invitation addresses exactly as
  `identity` does.
- **Route names are the operationIds; `domain.class` is gone.** Every spec named a PHP class
  (`Polaris\Http\Auth\LoginEndpoint`): the JSON manifest exported it as `class`, and the OpenAPI
  `operationId` was the method plus its short name (`post_LoginEndpoint`; the three OTP confirm
  routes of email and SMS shared `post_OtpFactorConfirmEndpoint`, an invalid duplicate). The 228 `class:` lines are
  removed from every spec under `internal/apispec/api` (core and the 15 plugins); the operationId is
  the route name (`polaris.auth.login`, `polaris.oauth.token`), unique by construction, and each
  JSON manifest entry carries `"name"` in place of `"class"`. A third-party spec that still has
  `domain.class` loads; the key is ignored. **Breaking:** `manifest.Route.Class` is removed (the
  plugin SDK; no Polaris code read it). **Client-visible** for OpenAPI code generators: generated
  method names change; regenerate clients.
- **Notify renders Go values.** `notify.Text` rendered `true` as `1` and `false` as an empty
  string; it now writes `true` / `false` (numbers were already decimal). None of the built-in
  templates' data carries a boolean, so no built-in mail changes.
- **TOTP secrets are 20 bytes.** New factors get 20 random bytes (160 bits, the length RFC 4226 §4
  recommends; 32 base32 characters) instead of 64 (103 characters, longer than some authenticator
  apps accept). Existing factors keep their secrets and keep verifying (`Match` takes any length;
  `TestAnEarlierReleasesLongSecretKeepsVerifying`). **Client-visible:** the enrollment `secret` and
  `otpauth_uri` are shorter.
- **One trim and one percent-encoder.** `internal/strutil` holds `Trim` (space, tab, LF, CR, NUL,
  vertical tab; not `strings.TrimSpace`, which would also strip form feed and Unicode spaces and so
  change stored emails and names) and `PercentEncode` (RFC 3986 unreserved kept, `%20` for space).
  They replace the copies in `identity`, `orgs`, `config`, `pipeline`, `mfa`, `manifest` and
  `internal/httpapi`, with the same results, pinned by tests.
- **The 501 fallback is gone.** Core routes without an endpoint answered 501 "This endpoint is not
  ported yet."; none can: `TestNoPendingRoutes` covers every core route, and `pipeline.New` refuses
  at startup to serve a route without an endpoint, naming it. No route answered it.
- **Kept:** `cache.ErrInvalidKey`'s reserved characters and its error text.

Contract fixtures: none is edited. The normalizer the fixtures were recorded with masks timestamps
as `<datetime>`, compares `{}` and `[]` as the same empty collection and masks TOTP secrets, and no
recorded request sends a value of the wrong type; every fixture replays unchanged. The exported
manifest and OpenAPI goldens are regenerated. Security review: the token change only refuses
claims no Polaris token carries and leaves every check and leeway in place; the type check runs
before any endpoint and only refuses input; the TOTP change keeps 160 bits of entropy (RFC 4226's
recommendation) and verification is unchanged. Tests: `TestAFieldOfTheWrongTypeIsA422NamingIt`,
`TestVerifyChecksAlgorithmIssuerAndDates` (new date and aud cases),
`TestClaimsEncodeInClaimOrderAsEncodingJSON`, `TestObjectEncoding`,
`TestExampleSchemaEmptyCollectionsAndDisagreeingShapes`, `TestOperationIDsAreRouteNames`,
`TestValidateValueKinds`, `TestParseRuleRegexDelimiters`, `TestRowAccessors`,
`TestMetadataJSONIsStandardJSONInFieldOrder`, `TestAuditRowsOfEarlierReleasesStillRead`,
`TestGeneratesABase32SecretOf20Bytes`, the sessions and invitations replays (`Z` timestamps),
`TestEmailRuleEdgeCases`, `TestTrimStripsOnlyItsSixEdgeBytes`,
`TestPercentEncodeKeepsOnlyUnreservedCharacters`.

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
- **Two-phase event delivery.** Under a host transaction, events (and so the verification and
  invitation mail the notify listener sends) were delivered when Polaris's part was done, before
  the host committed: a rolled-back signup still mailed. A first version of this change deferred
  every listener until the commit; review rejected it, because it traded that bug for another:
  the listeners that write to the store lose their atomicity with the action. The audit trail's
  row and the erasure listeners' deletes (`internal/maintenance.EraseOnUserDeleted`, decision 61,
  and the plugins' own erasure and revocation listeners) commit or roll back with the action only
  when they run inside its transaction; deferred, a crash between the commit and the dispatch
  loses an audit row or leaves an erased user's plugin rows behind, which breaks the erasure
  guarantee. So delivery now has two phases, decided per listener when the graph is built:
  - **Inside the transaction (as before):** core's audit log, every plugin's `Listeners` (every
    in-tree one writes to the store: audit recorder and activity, erasure, revocations, sentinel's
    device records), and the host's new `Config.TxListeners` (for a host listener that writes its
    own rows through `db.Conn(ctx)`).
  - **After the commit:** the mail listener, the metrics listener and `Config.Listeners`. They are
    wrapped by `wiring.Graph.Deferred(l)`, which queues the call on the transaction ctx carries
    (`sqlstore.Store.AfterCommit`) and runs it right after the outermost commit, in order, with the
    ctx the event was raised with (that ctx no longer joins the finished transaction). A rollback
    drops the queue, and a rolled-back savepoint drops what it queued. Outside a transaction, under
    `WithTx`, or on an adapter without `AfterCommit` (memstore), the call happens at once.
    `Deferred` finds `AfterCommit` through `Unwrap`, so `telemetry/otel.Store` keeps it. A plugin
    with a listener whose effect leaves the database (a webhook) wraps it in `g.Deferred`.

  The default for `Config.Listeners` is deferred, because a host listener is usually a side
  effect (mail, webhooks, queues, telemetry); the opt-in for database work is a separate field, not
  a marker on the function. A `Listener` is a func, so a marker such as `event.InTx(l)` could not be
  recognised later without comparing code pointers, and inlining makes those unreliable.
  `Config.Events` (a host dispatcher) receives every event when it is raised; the listeners
  `Graph.Listeners` hands it already carry their phase. `Store.Tx` is the host's transaction
  (`db.Tx(ctx, fn)`, writes through `db.Conn(ctx)`), and the hooks example uses it.
  `sqlstore.WithTx` (a host's own `*sql.Tx`) is unchanged and documented: Polaris cannot see that
  commit, so the deferred phase runs before it. Polaris's own code delivers after its
  transactions return, so outside a host transaction nothing changes for routes or Go calls.
  Rejected: deferring every listener (above); a transactional outbox table (durable delivery is a
  separate feature); wrapping `*sql.Tx` to see `Commit` (a host's ORM owns its transaction type).
  The deferred phase is at-most-once: a crash between the commit and the call loses a mail, as a
  crash after any commit did before. Tests: `TestStoreTxDeliversEventsInTwoPhases`. It uses the
  audit plugin, a `TxListeners` row, a `Listeners` recorder and the mailer. Inside a host
  `db.Tx`, a signup's audit row and host row exist while the mail and listener wait; after a
  rollback none survives; after a commit all ran once. An erasure's activity-row delete and its
  audit row roll back with the host's rollback and are kept with its commit. The test fails with
  the plugin listeners deferred. Also `TestDeferredWaitsForTheCommitOfAWrappedAdapter`,
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
`ErrEmailNotVerified`, `Config.TxListeners`, `Store.Tx`/`Conn`/`AfterCommit`/`Close`, `Conn`,
`polaristest.Hasher`, and package `event` for listeners; `wiring.Graph.Deferred` in §2); `scripts/api-stable.txt` already covers them (whole packages).
Security review: `DevEnv` cannot set a secret without the explicit flag and never replaces one
already set; the invitation token is returned once, as the event carried it, and is not part of
the loggable struct; `SignIn.OrganizationID` applies the switch route's membership checks and the
escalation guard still bounds `Invite`. Two-phase delivery keeps the audit trail and erasure atomic
with the action; it only delays what leaves the database.

## 72. 2026-11-22 — The audit chain's lock row is seeded by Migrate; no process-wide lock

The database matrix found two faults in decision 60's hash-chain lock, both reproduced by tests:

- **A Go mutex held while waiting for the chain's database row could deadlock.** `Store.Write`
  held a process-wide `sync.Mutex` across the whole append, including the wait for the row lock.
  A host transaction (`sqlstore.Store.Tx`, decision 66) that records two events owns the row
  after its first event; another request's writer then held the mutex while waiting for that row,
  and the host's second event waited for the mutex: neither the database nor Go detects it, so
  both hang. `TestTwoEventsInOneHostTransactionDoNotDeadlockConcurrentWriters` hung until the test
  timeout before the fix. The mutex is gone: the database row orders every writer.
- **Creating the lock row lazily raced.** On PostgreSQL a writer could see the row as present
  (another writer's still-uncommitted insert) and then fail with "the polaris_audit_chain row is
  missing", losing that event; on MySQL concurrent inserts of the row deadlock (InnoDB keeps the
  shared lock a duplicate-key error takes) and MySQL rolls back the host's whole transaction.
  The row is now created by `Polaris.Migrate` through a new optional plugin interface,
  `wiring.Seeder` (`Seed(ctx) error`, called after the schema is current, outside any
  transaction, idempotent). A writer reads the row before it would ever insert it, and if the row
  it read is not yet visible to its own transaction it creates it again (waiting for the other
  transaction) and retries once. Lazy creation remains only for a database that did not run
  `Migrate` since the upgrade.

Security review: no change to what is hashed or how the chain verifies; the change removes a hang
and a lost audit event. Tests: the deadlock test above and `TestSeedCreatesTheLockRowOnce` (every
backend), the existing chain tests (`-count=3` on PostgreSQL 17 and MySQL 8.4).

## 71. 2026-11-22 — v1 assurance: the stored-format inventory, the fuzz bar, the security policy after 1.0

Three rows of `docs/v1.md` asked for something to be written down and checked rather than built:
3.2 (every stored format has a vector), 4.4 (fuzzing), 4.7 (supported versions after 1.0). No
production code changes in this entry; tests, vectors, a workflow and documents do.

- **Stored formats (3.2).** [docs/stored-formats.md](stored-formats.md) is one table of what
  Polaris writes to the database or hands to clients and other deployments, where, in what format,
  and the test that pins it. Walking every `Pepper.Hash`, `Encrypt`, `sha256`/`hmac` call and every
  table found these gaps, now closed:
  - Passkey credentials had no vector: a change to the COSE parsing or the base64url form would
    have locked users out of the only copy of their credential. `testdata/vectors/passkey.json`
    records an ES256 and an RS256 registration, the row each stored and an assertion;
    `TestPasskeyVectors` stores the same row and verifies the assertion against it.
  - Peppered lookups were pinned as a function (`pepper.json`) but not by the context each table
    uses: renaming a context constant (`api_key`, `refresh`, …) would strand every stored digest
    without failing a test. `pepper.json` gains one case per context in use (`used_by` names the
    column), and `TestPepperContextsAreTheStoredOnes` in each owning package (`identity`, `mfa`,
    `orgs`, `session`, `plugins/{apikeys,admin,scim,oauth,agents,passwordless,social,ui}`) pins its
    constants, including the passwordless kinds that are also the stored `kind` column.
  - bcrypt imports (`$2a$`, `$2b$`, `$2y$`) were tested only by round trip with a freshly generated
    hash. `imported-hashes.json` gains the Openwall crypt_blowfish vectors.
  - Receipt hashes were pinned on the SDK side and by the server's canonical form of an ASCII
    receipt; `TestRecordedReceiptChainsHashAsTheyWereIssued` (`plugins/agents`) hashes the recorded
    chains (`agent/testdata/receipt-chains.json`, with non-ASCII capabilities) with the server code.
  - The default `kid` had only a relative test; `TestTheDefaultKeyIDIsTheRecordedOne` (`config`)
    pins it for the test RSA and EdDSA keys.
  - The passkey and social tables had no DDL golden (`TestPluginDDLGoldens` only walked the CLI's
    standard plugins, which leave out the two that need configuration), so row 3.5's "every plugin"
    was not true. `testdata/ddl/{passkey,social}.*.sql` now pin them; their models are unchanged
    since v0.4.1.
  Vectors were generated once from the current code by throwaway generators and checked in; the
  tests only read them.

  **Not stable enough to promise as they are**, for the owner to decide before 1.0:
  - *The default `kid` is the SHA-256 of the PEM text*, not of the key. The same key re-encoded
    (CRLF line ends, another line wrap) gets a new `kid`, so tokens and cached
    key sets from before the change stop verifying. Pinned as it is today; the options are to keep
    it and recommend `AUTH_JWT_KID` (llms.txt, `polaris init`), or to derive the default from the
    RFC 7638 thumbprint, which changes every deployment's `kid` once (a release note, and a
    rollover through `AUTH_JWT_PREVIOUS_KID`).
  - *`APP_KEY` cannot rotate.* The encrypter payload's version byte is the only marker and the
    pepper has none, so a new `APP_KEY` makes every encrypted secret (TOTP, SSO client secrets,
    social tokens, drain secrets) unreadable and every peppered digest (refresh tokens, API keys,
    …) unmatchable. The formats are stable; the promise must say that `APP_KEY` is forever until a
    key-id byte and a keyring exist (additive: a new version byte, the 0x01 payloads still read).
  - Transient formats (social and SSO hand-offs in the cache, MFA tickets' `mfa_factors`, cache
    keys) are not all pinned: a change fails only flows in progress during a rollout.
  The encrypter's HKDF info is `polaris:encrypter:mfa` for every use, not only MFA: a misnomer kept
  forever, since changing it changes the key.

- **Fuzzing (4.4).** The bar, set by the owner's delegate: every fuzz target fuzzed for at least
  60 minutes accumulated on the release-candidate code, across at least two separate runs, with no
  failing input outstanding; the weekly job keeps running after 1.0. It replaces "four green weeks
  at 4 minutes", which spent a month of calendar for less fuzzing than one dispatch. Nineteen
  targets at 60 minutes in one job is 19 hours, past GitHub's 6-hour job limit, so
  `.github/workflows/fuzz.yml` is now a matrix: a first job lists the targets
  (`scripts/fuzz.sh --list [regexp]`, the same discovery `make fuzz` uses, as JSON
  `{target, package, id}`; `FuzzDPoPProof` exists in two packages, so the package is part of the
  key), then one job per target runs `go test -fuzz` for `fuzztime` with `fail-fast: false` and a
  90-minute timeout (60 minutes of fuzzing plus the build and the seed corpus). The weekly
  schedule (60 s), `workflow_dispatch` inputs `fuzztime` and `targets`, `contents: read` and the
  `fuzz` concurrency group stay; a failing target uploads its corpus directory as
  `fuzz-failures-<package>-<target>`. Two dispatches with `fuzztime: 30m` (or one of `60m` plus any
  other) on the release candidate meet the bar. Row 4.4 stays open until they run. Validated with
  `actionlint`; `scripts/fuzz.sh --list` lists 19 targets and fails on a regexp that matches none.

- **Security policy after 1.0 (4.7).** SECURITY.md: the latest minor release of the current major
  gets every fix; the minor before it gets fixes rated Critical or High (CVSS 7.0 or more) for
  3 months after the new minor ships; older minors none. Semver makes the upgrade to the latest
  minor safe by promise, so one supported line would do, but hosts pin minors and a new minor can
  arrive the week before a disclosure: three months covers one release cycle of a careful host at
  the cost of a backport only for the severe fixes. From v1.0.0 each fix is announced, when it
  ships, as a GitHub security advisory with a CVE requested through GitHub (a CNA), in the release
  notes (CHANGELOG **Security**, the GitHub Release), and reported to the Go vulnerability
  database so `govulncheck` warns hosts. The private reporting flow is unchanged; the v0.x policy
  stays as "Before 1.0" (now naming `v0.5.x`). Rejected: a fixed support period per minor (dates
  to track, and a minor can be short-lived); supporting only the latest minor (simpler, and
  leaves a host that upgraded cautiously without a fix it can take as a patch).

Also ticked in `docs/v1.md`: 1.5 (the "API compatibility" check is required on `main`) and 7.3
(v0.4.0 to v0.5.1 were released by the workflow).
Security review: no production code changed. The new tests only read vectors; the vectors hold
test-only keys (`keys.json`, the vector `APP_KEY`) and published or generated test credentials.
The fuzz workflow keeps `contents: read`, takes its inputs through environment variables (no
expression is expanded into a script), and uploads only the fuzzed target's corpus directory.

## 70. 2026-11-22 — The v1 Go API is everything exported outside `internal/`

API.md split the module in three: the host surface (§1, stable), the plugin SDK (§2, stable, may
grow) and §3, "public but not stable": the concrete services and the rest of fifteen packages,
importable but free to change in any minor release. `make apicheck` guarded only the names in
`scripts/api-stable.txt`. That third category does not exist for a Go module at v1: every exported
name of a non-internal package is covered by semantic versioning in the eyes of `go get`,
`gorelease`, pkg.go.dev and whoever imported it. A carve-out written in a Markdown file is not
something they honour. So v1 has two categories only. **What is exported outside `internal/` is
the API, all of it; what Polaris must stay free to change is under `internal/`.**

**Inventory.** A `go/types` program listed every exported top-level name and method of the §3
packages (`identity`, `session`, `mfa`, `orgs`, `authz`, `repository`, `security`, `notify`,
`notify/notifytest`, `cache`, `clock`, `ratelimit`, `metrics`, `pipeline`, `store/memstore`,
`store/storetest`: 275 top-level names) with who uses each: (a) a host (the examples, llms.txt,
the READMEs), (b) a plugin or the plugin SDK (the source of an in-tree plugin, or a type an
exported signature of `polaris`, `wiring`, `endpoint`, `token`, `polaristest`, a plugin… names),
(c) only core (`wiring`'s construction, package `polaris`, `internal/…`, `cli`, tests). 109 were
(a) or (b); 166 were (c) only.

**Moved under `internal/`** (90 names; each was used by `wiring`, `internal/httpapi`, package
`polaris`, `polaristest` and tests only):

- `identity` → `internal/identity`: `Service`, `New`, `Config` and its ports (`Sessions`,
  `MFAGate`, `MFATickets`, `AuthorityResolver`), `NewUser`, `ImportedUser`, `UserView`,
  `ErrInvalidConfig`. The account flows; hosts reach them through `polaris.Users`, plugins through
  `wiring.Identity`.
- `session` → `internal/session`: `Service`, `New`, `Config`, `Issuer`, `PrincipalResolver`,
  `UserPrincipals`, `Denylist`, `NewDenylist`, `MFATickets`, `NewMFATickets`, `PurposeLoginMFA`,
  `ReservedClaim`, `ErrInvalidConfig`. Refresh rotation and the ticket; reached through
  `polaris.Sessions` and `wiring.Sessions` / `Denylist`.
- `mfa` → `internal/mfa`: `Service`, `New`, `Config` and its ports (`Sessions`, `Tickets`,
  `PrincipalResolver`), `TOTP`, `NewTOTP`, `TOTPProvider`, `QRRenderer`, `SVGQRCode`,
  `TOTPEnrollResult`, `OTPEnrollResult`, `OTPChallengeResult`, `ManagedFactorView`,
  `ManagedViewOf`, `RecoveryCodeCount`, `ErrInvalidConfig`. The MFA engine; reached through
  `wiring.MFA`.
- `orgs` → `internal/orgs`: `Service`, `New`, `Config`, `Sessions`, `Invitation`,
  `InvitationTTL`, `Role`, `NewRole`, `RoleChanges`, `ErrInvalidConfig` and the 27 `Msg*` wire
  messages. Reached through `polaris.Orgs` and `wiring.Orgs`.
- `authz` → `internal/authz`: `Resolver`, `NewResolver`, `Gate`, `NewGate`, `EscalationGuard`,
  `NewEscalationGuard`, `Principals`, `NewPrincipals`, `Seed`. Reached through `wiring.Resolver`,
  `Gate`, `Principals`, and `Polaris.Migrate` for the seed.
- `notify.Listener`, `notify.Users` → `internal/observe.Mail`, `MailUsers`: the listener that
  turns core events into mail is wiring, beside the audit and metrics observers.

The five domain packages were moved whole and then split, because plugins need a part of each.
The public package keeps the declarations; the internal one repeats them as aliases
(`internal/<pkg>/public.go`), so the service code and its callers inside the module read as
before and the public type is the only type. No logic changed: the files moved as they were,
except `PasswordPolicy.enforce`, now a function of `internal/identity` (a public type cannot keep
an unexported method its service calls).

**Stayed public, and why** (185 names of those packages):

- `identity`: `LoginResult`, `MFAChallenge` (what `wiring.Identity.Login` returns),
  `PasswordError`, `Error` and the ten sentinels (what its methods refuse with), `PasswordPolicy`
  (passwordless validates passwords with it), `NormalizeEmail` (the stored form of an email, used
  by five plugins).
- `session`: `Info` (`wiring.Sessions.List`) and the four sentinels its methods return.
- `mfa`: `FactorType` (a plugin implements it), `ChallengePurpose` and its values, `LoginChallenge`,
  `ConfirmResult`, `FactorView`, `ViewOf`, `MaskDestination`, `ValidE164`, `PolicyError` and the
  five sentinels.
- `orgs`: `Member` (`wiring.Orgs.ListMembers`), `Error` and its four kinds.
- `authz`: the permission keys and role slugs, `Permission`, `Catalog` / `NewCatalog` /
  `RoleTemplate` (agents reads core's catalog), `Authority`, `Caller`, `ErrForbidden`,
  `ForbiddenError`, `Forbidden` and its two messages.
- `repository`, whole: `Graph.Repos` returns `*Repos`, so every repository and its methods were
  already reachable; `New` completes it for a plugin's unit tests.
- `pipeline`, whole: `Graph.Pipeline` returns `*Pipeline`, `wiring.PipelineOption` names
  `Options` and so every interface in it, plugins implement `BearerResolver` and call
  `DeniesDelegate` / `DeniesBound`. Nine of its seventeen names were already in
  `api-stable.txt`; the rest are the constructor and the wire names (`CSRFHeader`,
  `RefreshCookie`).
- The ports with their default implementations and helpers, whole: `notify` (`Mailer`,
  `SMSSender`, the log and discard senders, the template names, `Subject`, `Text`), `cache`,
  `clock`, `ratelimit`, `metrics`, `security`. A host that implements a port wraps or falls back to
  the default (the webapp example wraps `notify.NewLogMailer`), and a few lines of default are not
  worth an internal package. `security` is also where the stored formats live; it was not touched
  (`Pepper` and `NewPepper` are used only by core, behind `wiring.Pepper`, and could move later:
  moving is not possible after v1, keeping is harmless).
- `notify/notifytest`, `store/memstore`, `store/storetest`: what a host's or a plugin's tests and
  a `store.Adapter` author use (`polaristest.Server` exposes the recorders; `storetest.Run` is the
  adapter conformance suite). As decision 51.
- The packages that were already stable whole (`polaris`, `wiring`, `endpoint`, `manifest`,
  `event`, `token`, `config`, `store`, `store/sqlstore`, `polaristest`, `agent`, `cli`, `verify`,
  `telemetry/otel`, `model`, `schema`, `plugins/*`) are unchanged.

**Interfaces: implemented or called.** "The plugin SDK may grow" needed a rule tools agree with,
because adding a method to an interface breaks whoever implements it.

- Every exported interface is one a host or a plugin may implement (`wiring.Plugin` and its
  optional interfaces, `endpoint.Endpoint`, `pipeline.BearerResolver`, `mfa.FactorType`,
  `event.Dispatcher`, the ports, `store.Adapter`, the plugins' own ports). They are frozen: no
  method is added in v1. A capability is added as a new optional interface found by type
  assertion (`security.HashChecker`, `wiring.AccessEraser`).
- Except the ten service interfaces of `wiring`: `Identity`, `Sessions`, `MFA`, `Orgs`,
  `Denylist`, `Catalog`, `Resolver`, `Gate`, `Principals`, `Pepper`. Polaris implements them and
  plugins only call them. They now carry an unexported method (`sealed()`), so no other package
  can implement one, and `apidiff` and `gorelease` then treat an added method as compatible, which
  is what "may grow" means. The `Graph` accessors return a small wrapper that embeds the concrete
  service and adds that method. A test double embeds the interface.

**`make apicheck`.** It runs `apidiff` over the whole module (`-m`; `internal/` is left out by
the tool, the `main` packages by the script) against `BASE`, the latest tag by default and the
pull request's base in CI. `scripts/api-stable.txt` is gone. Before v1.0.0 (the base's latest tag
is v0.x) an incompatible change passes only when `docs/decisions.md` gains a line containing
"Breaking". Once the base's latest tag is v1.0.0 or later it is refused, whatever the decisions
say; the one exception is a module path that changed (`/v2`), where there is nothing to compare.
`APICHECK_TAG=v1.0.0 make apicheck BASE=origin/main` on this branch shows the refusal.

**API.md** is rewritten as the promise: what is covered, what a user must do for it to hold
(keyed literals, no implementation of sealed interfaces, `errors.Is`, a `default` in switches),
and the deprecation policy: add and mark `// Deprecated:` in 1.x, keep working for all of v1,
remove only in v2.

**Verified.** `testdata/thirdparty/notes` is a plugin written as a third party would: its own
module, a table, three routes from its own embedded specs, a permission, an erasure listener, a
bearer resolver, an MFA factor type, `AccessEraser`, and every narrow service of the `Graph`.
`TestAThirdPartyPluginBuildsOutsideTheModule` type-checks it in a temporary directory against the
checkout through a `replace` directive on every `make qa`, and checks that the same module cannot
import `internal/services`. Its own test, run the same way with `go test`, boots it with
`polaristest`: sign-in through `wiring.Identity.Login`, a note written with a session, the
plugin's credential resolved, the user's notes erased with the account. The in-tree plugins'
sources needed no change: they compile against the public halves, which is the check that nothing
a plugin uses was moved. `TestGraphAccessorsReturnOnlyPublicTypes` replaces
`TestGraphAccessorsReturnOnlyStableTypes`. `make qa` and the contract fixtures are unchanged and
green: no route, schema or stored format is touched.

Not decided here. The in-tree plugins import some internal packages (`internal/apispec` for
their embedded route specs, `internal/maintenance` for `EraseOnUserDeleted` and `PruneExpired`,
`internal/netguard`, `internal/version`; `mcp` and `ui` also `internal/httpapi` and
`internal/jwtverify`). None is needed to write a plugin (the third-party plugin erases with a
plain listener), and each can be made public later without a break; making them public now would
promise them.

Breaking (pre-1.0): the 90 names above leave the public packages `identity`, `session`, `mfa`,
`orgs`, `authz` and `notify` (CHANGELOG lists each); `wiring`'s ten service interfaces gain an
unexported method and can no longer be implemented outside `wiring`. Nothing a host imports per
API.md §1 or a plugin per §2 is removed.

Security review (rule 6): `identity`, `session`, `mfa` and `authz` code moved without a change to
a check, a comparison or a token path; the diff of each moved file is its package path and the
declarations lifted to the public package. The sealing wrappers embed the same service values the
accessors returned. The gate adapter of the pipeline now goes through `Graph.Gate()`, the same
`*authz.Gate`.

## 73. 2026-11-22 — The default JWT kid is the RFC 7638 thumbprint; APP_KEY is fixed in 1.x

Decision 71 left two items for the owner before 1.0 (`docs/v1.md`, "Decisions to make before
1.0"). The owner's delegate decided both.

- **The default `kid` is the RFC 7638 JWK thumbprint of the public key.** Until now, without
  `AUTH_JWT_KID`, the `kid` was the SHA-256 hex of the public key *as configured*: the PEM text
  (edges trimmed) or the raw EdDSA key. Re-encoding the same key (CRLF line ends, another line
  wrap, a certificate instead of an SPKI block) changed the `kid`, and with it every issued token's
  and every cached key set's view of the key. From now on `config.Secrets.KeyID` (and
  `PreviousKeyID`) default to `token.Thumbprint`: unpadded base64url SHA-256 of
  `{"e":…,"kty":"RSA","n":…}` for RS256 and `{"crv":"Ed25519","kty":"OKP","x":…}` for EdDSA, the
  form the agents SDK, DPoP and `plugins/agents` already use. It depends on the key only. Pinned by
  `TestThumbprintIsRFC7638` (`token`, the RFC 7638 §3.1 RSA example and the RFC 8037 A.3 Ed25519
  example, plus a CRLF re-encoding) and `TestTheDefaultKeyIDIsTheThumbprint` (`config`, the test
  keys of `testdata/vectors/keys.json`). `config` infers the algorithm from the key's form (an
  EdDSA key is 32 raw bytes, never a PEM); an unparseable key has no thumbprint and `KeyID` is "",
  which `token.New` reports when the graph is built.

  *Upgrade without a rollover (AGENT.md rule 5).* Every deployment that relied on the default
  changes `kid` once, at the upgrade. So that nothing issued or cached before stops verifying:
  - The codec accepts the legacy value for the key it belongs to. `token.Config` gains
    `LegacyKeyID` and `PreviousLegacyKeyID`; `VerifyJWT` maps either to its key (previous first, as
    before), and a legacy kid presented with the other key fails the signature check. The wiring
    sets them from `config.Secrets.LegacyKeyID` / `PreviousLegacyKeyID`, which are the old
    derivation (`TestTheDefaultKeyIDIsTheRecordedOne` becomes `TestTheLegacyKeyIDIsTheRecordedOne`,
    same recorded values). Session tokens (`Parse`) never looked at `kid` and are unaffected.
  - The JWKS publishes each key under its new kid and then, as a second entry with identical key
    material, under its legacy kid: `[current, previous, current-legacy, previous-legacy]`.
    Verifiers elsewhere (`verify`, `mcp.Protect`, other services) holding a token that names the
    old kid find it; a verifier that cached the old document and meets a new kid refetches, as it
    does at any rotation.
  - Tokens are minted with the new kid only.
  - An explicit `AUTH_JWT_KID` / `AUTH_JWT_PREVIOUS_KID` is used as it is and gets no alias: it
    never changed.
  The aliases are not time-limited: they cost one JWKS entry per key, and a token naming the old
  kid can be a long-lived OAuth or ID token or an agent receipt signature. They go away with
  the key: once a pre-upgrade key is neither the current nor the previous key, neither it nor its
  alias is published or accepted. Rejected:
  keeping the PEM hash and recommending `AUTH_JWT_KID` (the trap stays the default); switching
  without aliases (every deployment's outstanding tokens and every downstream cache break at the
  upgrade, against rule 5).

  Client-visible: new tokens carry a different `kid`, and the JWKS gains one entry per key. The
  four recorded fixtures that fetch the JWKS (`JwksEndpointTest` ×2,
  `AuthMiddlewareTest::testAPublicPathSkipsAuthentication`, the OAuth discovery flow) gain the
  alias entry; `kid`, `n` and `e` are masked in the comparison, so the count of entries is what
  they pin. `TestTheLegacyDefaultKidKeepsVerifying` (`internal/httpapi`) boots a server and checks
  the JWKS order and key material, that a token minted with the legacy kid verifies, that new
  tokens carry the thumbprint, and that an explicit kid has no alias.

- **`APP_KEY` is fixed for the life of a deployment in 1.x.** It keys the pepper of every stored
  lookup digest (refresh tokens, API keys, operator and SCIM tokens, OAuth client secrets, codes,
  device codes and refresh tokens, recovery codes, verification, reset, invitation and passwordless
  tokens, agent host tokens) and the encrypter of every stored secret (TOTP, SSO client secrets,
  social tokens, audit drain secrets). Changing it invalidates all of them. That is now written
  where operators look: the `config.Secrets` doc, SECURITY.md ("Operating Polaris"), and
  docs/stored-formats.md. A key ring (`APP_KEY_PREVIOUS`) stays possible in a 1.x minor without a
  format change: the encrypter's payload starts with a version byte (`0x01` today; a new byte can
  name the key, the `0x01` payloads keep reading), and a peppered lookup can compute the digest
  under each key and match either, rehashing on a match under the old one. Nothing is built for it
  now. The HKDF info strings are frozen: `polaris:pepper:` + context, and `polaris:encrypter:mfa`
  for every encrypted secret (a misnomer, decision 71, kept because changing it changes the key).

Security review (AGENT.md rule 6; `token`, `config`, the key wiring): an alias entry in the JWKS
adds no key, only a second name for a key already published, so a verifier trusts nothing it did
not trust before. Accepting a legacy kid maps only to a key the deployment configured (the current
or the previous public key); the signature is still checked with that key, a legacy kid presented
with the other key fails, and an unknown kid is still refused. The legacy value is derived from the
public key, which is public; no secret enters a kid. Algorithm and issuer checks are unchanged.
`Thumbprint` parses the key with the same parsers the codec uses (RSA SPKI, PKCS #1 or certificate;
a canonical, non-small-order Ed25519 point). Fuzz targets unchanged and passing.

## 74. 2026-11-22 — Account provisioning and email proof: what a directory or an IdP may vouch for, registrations of an unverified address, the browser of an SSO sign-in

A security review with running tests found five ways around the account boundaries of decisions 43,
61 and 68. All are closed here; each is client-visible and listed in the changelog.

- **A directory or an identity provider vouches for a mailbox only on a domain its organization
  verified.** Any user can create an organization and configure a SCIM directory or an IdP for it
  (`org.update`). Both created accounts *verified* for whatever address they named
  (`scim.createUser`, the sso JIT path), a directory could rename an account it owned to any free
  address keeping its verification and credentials, and ownership never lapsed: the first proof of
  decision 68 did nothing on an account already marked verified. So an organization could stage an
  account under an address it controlled, set a password and keys through that mailbox, then move
  it onto somebody else's address (or have its IdP assert that address directly) and hold a
  verified account there. Now:
  - `scim.createUser` and the sso JIT path mark the account verified only when the address is on a
    domain verified for the organization; anywhere else the account is created unverified. The sso
    sign-in of an existing account proves it (`ProveEmail`) only on a verified domain, and the
    session and the exchange envelope carry the account's own `email_verified`.
  - A SCIM rename goes through a new `identity.Service.ChangeEmail` (`wiring.Identity.ChangeEmail`),
    the one place an account's address changes: verified at the new address when the caller
    vouches (a verified domain), unverified otherwise, and the reset and verification tokens of the
    old address deleted. A verified account is refused an address outside the verified domains
    (403 `mutability`); an unverified one moves and stays unverified.
  - `sso` and `scim` implement `wiring.AccessEraser`: the first proof of the mailbox deletes the
    `polaris_sso_account` rows and the SCIM provenance rows of the account, so the organization's
    IdP stops signing it in (`sso/user_unknown`) and the directory stops owning it (membership
    changes only). SCIM keeps the provenance of an organization that verified the account's domain,
    which answers for the mailbox; the membership, external id and name parts stay.
  - A token is for the mailbox it was sent to: `ResetPassword` and `VerifyEmail` refuse a challenge
    whose `email` is not the account's current one, and the passwordless `verify-email` and
    `reset-password` codes likewise (`spendFor`). Magic links and sign-in codes already resolve the
    account by the address they were sent to.
- **Two registrations of an address nobody verified confirm neither password; a verification
  token confirms only the password it was issued with.** A second registration of an existing
  unverified address was dropped silently, and the verification link then confirmed the *first*
  registrant's password (decision 68 keeps a registration's password on its own verification).
  Whoever registered an address first had their password confirmed by the owner's click. Letting
  the latest registration win instead only swaps the order: whoever registers *after* the owner,
  before the click, is confirmed. Only the mailbox tells the two apart, so `Register`, for an
  address whose account is unverified and not disabled, always sends a new verification message
  (the earlier tokens are deleted) and:
  - when the password is the one the account has (the same person registering twice), changes
    nothing else: the link confirms that registration as before;
  - when the account has another password, keeps neither: the stored hash and display name are
    removed with what their holder could act with (factors, the plugins' access rows, sessions:
    the removal `ProveEmail` does, without marking the account verified) and the new password is
    not stored. The link is then a plain proof of the mailbox (an account without a password gets
    the full first proof), and its owner sets a password by reset;
  - when the account has no password (a directory or a provider created it), stores none: the link
    is the mailbox's first proof, which ends that party's hold (above).

  The answer is the same 202 and every path costs one Argon2id computation (a verify where the
  stored hash is compared, a hash elsewhere). The removal is conditional on the account being
  unverified, so a verification that wins the race keeps its account. The token is now
  `<nonce>.<binding>`, the binding being 128 bits of
  `Pepper.Hash("email_verify_bind", nonce NUL password_hash)`; `VerifyEmail` recomputes it against
  the account's current hash and refuses a mismatch, so a token never confirms a password set
  after it was issued. The stored row is unchanged (the keyed hash of the whole token), so no
  schema change; tokens issued before this release have no binding and verify as before until
  they expire (24 h), and none can be made since the stored hash covers the whole token.
- **An SSO sign-in completes only in the browser that started it.** The state lived only in the
  cache, so an attacker could start a sign-in as themselves and have a victim's browser complete it
  (login CSRF). `POST /sso/sign-in` now sets a cookie holding a random nonce the state keeps, and
  the callbacks refuse a state whose browser does not present it: the social plugin's binding of
  decisions 39 and 50, same attributes (`__Host-` and `SameSite=None; Secure` under an https
  `Config.BaseURL`, `SameSite=Lax` under http; the scheme is `BaseURL`'s, not the connection's).
  An IdP-initiated SAML response has no state and no binding, as before, behind `idp_initiated`.
- **The roles a provider or a directory hands out are within the authority of whoever configures
  it.** `jit.roles` accepted any slug and a directory assigns any role, so an administrator
  (`org.update`, not every permission) could have their own IdP or directory make them an owner.
  `POST`/`PATCH /orgs/{id}/sso/providers` now pass the roles through the escalation guard
  (`authz.EscalationGuard.CheckRoles`, the rule of role changes and invitations; 403
  `sso/forbidden`) and refuse a slug the organization does not have (422); a PATCH without `jit`
  is not checked. Creating a SCIM connection or rotating its token takes the authority to grant
  every role of the organization (403 `scim/forbidden`): a directory's token is that power, so it
  goes only to someone for whom it is no escalation. The Go APIs (`Providers().Create`,
  `Connections().Create`) are the host's and unchecked.
- **sso, smaller items.** `verifyIDToken` required no `exp`; it does now (OpenID Connect Core §2).
  The discovery document's `issuer` was not compared with the configured one; it is (Discovery
  §4.3, a trailing slash aside). An unverified domain claim blocked every other organization from
  claiming the domain, forever. An expiry would not help (the claimant deletes and claims again),
  so an unverified claim now reserves nothing: another organization's claim replaces it, a verified
  domain stays its organization's, and an organization's verification token for a domain is
  derived (`Pepper.Hash("sso_domain", organization NUL domain)`), the same on every claim, so a
  displaced organization claims again and verifies with the record it already published. Claims
  made before this release keep their stored random token. `polaris.SignIn.AMR` documents that
  `"sso"` yields an organization-bound session.

Security review (rule 6), per item:

- *Vouching and ownership.* Only narrows: accounts are verified in fewer cases, renames refused in
  more, ownership ends earlier. `ChangeEmail` runs in one transaction with the token deletion; the
  spend-path checks hold for a token row that survives it (an older release's, a race). The eraser
  runs inside the first proof's transaction, so a failure rolls the proof back. Accounts created
  verified by a directory or a provider before this release stay verified and owned (no record
  tells them from the mailbox owner's): they can no longer be renamed off a verified domain, which
  is the step that moved them onto another person's address. Residual: an unverified account at an
  address its owner has not claimed yet stays the creating organization's until the owner proves
  the mailbox (reset, email code, magic link, or the verification message a registration of that
  address sends; the registration itself changes nothing, so nobody detaches a directory's
  accounts anonymously). `ChangeEmail` onto a vouched address is a first proof for an unverified
  account, with its removals. An
  organization that verified a domain speaks for every mailbox on it, as before. Tests:
  `TestADirectoryVouchesOnlyForItsOrganizationsDomains`,
  `TestTheFirstProofOfTheMailboxEndsADirectorysHoldOnTheAccount` (scim),
  `TestAProviderVouchesOnlyForItsOrganizationsDomains` (sso),
  `TestTokensSentToAnAddressDieWhenTheAccountLeavesIt` (identity),
  `TestACodeSentToAnAddressDiesWhenTheAccountLeavesIt` (passwordless); all failed before.
- *Registration.* A registration can be anyone's, so it is given nothing: it never sets a password
  on an existing account and never grants access, only removes a password nobody proved, and the
  account stays unverified until the mailbox answers. Comparing the submitted password with the
  stored hash answers nothing to the caller (same 202, a message to the mailbox either way).
  Accepted costs: anyone who knows an unverified account's address can remove its password and
  sessions by registering it with another password (the holder recovers by verifying and a
  reset; hosts with `RequireVerifiedEmail`, the default, have no sessions on unverified accounts
  to lose); a person who registers twice with two passwords verifies and then resets; and the
  paths differ in the writes they do after the Argon2id computation, a delta the register rate
  limit covers as it did for the taken path. Residual, as in decision 68: the owner of a mailbox
  who presses the link of a single, uncontested registration they did not make confirms that
  registrant's password. Considered and not done: treating the first password reset after a
  confirmed registration as a full first proof. It would remove the MFA factors of every account
  that registered by form and never reset, at its first reset, which lets a mailbox compromise
  bypass MFA; that is worse than the residual. The binding compare is constant time; the binding
  context is not a stored format. Tests:
  `TestTwoRegistrationsOfAnUnverifiedAddressConfirmNeitherPassword`,
  `TestAVerificationTokenConfirmsOnlyThePasswordItWasIssuedWith` (failed before),
  `TestRegisteringAgainWithTheSamePasswordKeepsTheRegistration`,
  `TestRegisteringAnAddressWithoutAPasswordStoresNone`,
  `TestAVerificationTokenOfAnEarlierReleaseStillVerifies`.
- *Browser binding.* The nonce is 128 random bits, compared in constant time, stored with the
  state (encrypted in the cache) and consumed with it; a state without one (started before the
  upgrade, at most ten minutes old) is refused. The cookie value is useless without the state it
  names. Test: `TestASignInCompletesOnlyInTheBrowserThatStartedIt` (HTTP; failed before: the
  callback answered 302 without the cookie).
- *Roles.* The check is at configuration time, with the authority the request's authorization step
  resolved; a superadmin is exempt as everywhere. A role's permissions can grow later only through
  a role change, which the same guard covers. Providers and connections configured before this
  release keep their roles and tokens: review `jit.roles` naming `owner` or `admin`, and rotate
  directory tokens an administrator created. Residual: a directory token outlives a later
  demotion of whoever obtained it; an owner rotates or decommissions it. Tests:
  `TestAProvidersRolesStayWithinItsConfigurersAuthority`,
  `TestADirectoryIsConnectedOnlyByWhoCouldGrantEveryRole` (HTTP; both failed before).
- *OIDC and domains.* The two OIDC checks only refuse more. Displacing an unverified claim gives
  the displacing organization nothing until it verifies, which takes control of the domain's DNS
  or web root; the derived token is published in DNS anyway and proves nothing by being known.
  Tests: `TestIDTokenTimeErrorsAreGoNative`, `TestOIDCRunsDiscoveryTheCodeExchangeAndVerifiesTheIdToken`
  (new cases), `TestAnUnverifiedDomainClaimReservesNothing` (failed before).

Contract fixtures: `SsoFlowTest::testSignInThroughOidcAndSamlEndsOnTheApplicationWithACode` gains
the `Set-Cookie` of each started sign-in and replays with a cookie-keeping client; the others
replay unchanged. The route specs of the changed routes describe the new behaviour.

Go API. Breaking, recorded here for `make apicheck`: `sso.Plugin.CompleteOIDC` and
`sso.Plugin.CompleteSAML` take the browser's binding (a new `binding string` parameter after the
state); `wiring.Identity` gains `ChangeEmail` (a sealed interface, API.md §2). Additive:
`sso.Started.State` and `Started.Binding`, `sso.Plugin.EraseAccess`, `scim.Plugin.EraseAccess`.

Left open: `docs/v1.md` row 4.2 is the owner's. Accounts a directory or a provider created
verified before this release are not re-examined (above).

## 75. 2026-11-22 — OAuth boundaries: trusted clients, token exchange, DPoP origin, introspection, consent, grant windows

Six findings of the security review before 1.0 in `plugins/oauth`, each reproduced by a failing
test before its fix (`plugins/oauth/boundaries_test.go`, through HTTP, unless noted). Each is
client-visible; the changelog lists what a client sees.

- **An organization cannot change what an operator trusted.** A client registered `trusted` (or
  listed in `Config.TrustedClients`) gets its code without a consent screen, and decision 69 made
  its `scopes` its own authority. The organization's route (`PATCH
  /orgs/{id}/oauth/clients/{clientId}`, `org.update`) guarded only `scopes`: an organization admin
  could change `redirect_uris`, `type` and `token_endpoint_auth_method`, or add `jwks` and
  `client_credentials`, on a client that stayed trusted. Now `clients.apply`, which every update
  goes through, compares the client before and after when the caller may not trust
  (`sameRegistration`): `type`, `redirect_uris`, `grant_types`, `scopes`,
  `token_endpoint_auth_method`, `jwks`, `jwks_uri`, `client_uri` and `dpop_bound_access_tokens`
  must be unchanged, else 400 `invalid_client_metadata`. `name`, `logo_uri`, `policy_uri`,
  `tos_uri` and `disabled` stay the organization's (stopping a client is never an escalation), and
  re-sending the registered values is accepted. `settings.trusts` is the one definition of
  "operator-trusted" (the row's flag or the host's list), used here, by the consent skip, the
  exchange and introspection. Tests: `TestAnOrganizationCannotRepointATrustedClient`,
  `TestOnlyAnOperatorRepointsAClientTheHostTrusts` (in process: the host's list cannot name a
  client before it exists).
  Security note: the guard is a comparison of the whole protocol identity rather than a list of
  refused keys, so a field added to `Client` later is one line in `sameRegistration` and a key
  spelled another way (`scope`, a null) cannot slip past it. There is no operator update route;
  an operator changes a trusted client with `UpdateClient(…, true)` or re-registers it.
- **A token exchange stays within the subject's client and audience (RFC 8693, RFC 8707).**
  `exchange` accepted any live `at+jwt` as the subject, whoever it was issued to and for, and
  minted the new token for the `resource` asked, the issuer when none: a token restricted to
  `aud=https://rs1…` became, in the hands of any client with the exchange grant, a token this
  server and every `verify` / `mcp.Protect` service accepts. Now (`Plugin.subject`,
  `Plugin.target`): a provider token is a subject or an actor only for the client it was issued
  to, a client its `aud` names, or a trusted client (`invalid_grant` otherwise); the new token's
  audience is the subject's when no `resource` is asked; another `resource` is accepted from a
  subject that was for this server (a session, `aud` the issuer or one of `Config.Audiences`:
  narrowing), from a trusted client, or, away from this server, from the authenticated client the
  subject's `aud` names (`invalid_target` otherwise). The ownership rule alone is not enough, which
  is why the audience rule does not depend on it: a public client (an agent's) authenticates with
  nothing, so "its own token" proves only possession.
  A session token was accepted after `Parse` alone. An exchanged token lives an access-token
  lifetime with `amr: ["oauth"]`, so it outlived a logout and dropped the marks of a session that
  is not the account holder's. Now (`Plugin.sessionSubject`): an impersonation token
  (`impersonated_by`) and an organization-bound session (decision 68, `OrganizationBound`) are
  refused, as is a session whose user logged out everywhere (the denylist's watermark, read
  whether or not `AUTH_ACCESS_TOKEN_DENYLIST` makes the pipeline enforce it) or whose own session
  (`sid`) is no longer live. Refusing is the choice over carrying the marks into the token: no
  consumer of an `at+jwt` reads them, and a bound or impersonated principal has no business
  delegating the account. Tests: `TestAnExchangeStaysWithinTheSubjectsClientAndAudience`,
  `TestAnExchangeRefusesASessionThatEndedOrIsNotTheUsersOwn`. One recorded fixture is re-recorded
  (`OAuthFlowTest::testDpopBindsTokensToTheClientsKeyAndRefusesAReplayedProof`): its last steps
  exchanged a DPoP-bound token through a second client; the client now exchanges its own token,
  and the refusal it pins is the proof of another key.
  Security note: the checks are in the two functions every exchange goes through (the token
  endpoint and `Plugin.Exchange`); scopes are still narrowed and bounded by `tokens.issue`
  (decision 69); the DPoP binding of the subject is still required. `plugins/agents` exchanges
  a session for this server and is unaffected. Not done: a registry of resource servers (which
  client is `https://rs1…`). A resource server that exchanges or introspects tokens issued to
  other clients is registered `trusted` by an operator; a self-declared resource would be an
  authority an organization could claim.
- **A DPoP proof is for this server's URL.** `htu` was compared with a URL built from the
  request's `Host` header (and its TLS state), which the caller chooses: a proof made for another
  server verified here when replayed with that server's name. `ownURL` now builds it from the
  origin of the configured base URL and the path the client sent, as `plugins/agents` does for a
  request JWT's `aud` (decision 69). Test: `TestADPoPProofIsForTheConfiguredOrigin`. Security
  note: one function serves the token endpoint, the bearer resolver and `Plugin.VerifyDPoP`;
  method, `ath`, `iat` window and single use are unchanged. A deployment that clients reach under
  a name other than `BaseURL` was already advertising the wrong endpoints; it sets `BaseURL`.
- **Introspection answers the token's own client.** Any confidential client could introspect any
  token and read its user, organization and scopes. `serveIntrospect` now answers
  `{"active": false}` (RFC 7662 §4) unless the token was issued to the caller, its `aud` is the
  caller's client id, or the caller is trusted. Test: `TestIntrospectionAnswersTheTokensOwnClient`.
  Security note: the refusal is the same body as an unknown token, so it is not an oracle for
  whether a token is live.
- **A consent counts in its organization.** `polaris_oauth_consent` held one row per user and
  client, so scopes approved while acting in one organization were granted silently in another,
  where the same permission scopes reach other data. Consent is now keyed by user, client and
  organization (NULL outside any); `needsConsent` and `grant` take the session's organization.
  Stored data (rule 5): the unique index `polaris_oauth_consent_unique (user_id, client_id)` is
  replaced by `polaris_oauth_consent_org_unique (user_id, client_id, organization_id)` through the
  schema DSL (`DropIndex`, decision 63; `TestMigrateUpgradesEveryReleasedSchema` covers it, DDL
  goldens regenerated). An existing row keeps its `organization_id` (the organization of the
  user's latest approval) and counts for that organization only; its scopes may include ones
  approved elsewhere before, which is the most an old row can say, and no row is rewritten or
  deleted. `DELETE /oauth2/consents/{clientId}` removes the client's consents in every
  organization. Test: `TestAConsentCountsInItsOrganizationOnly`. Security note: the lookup fails
  closed (no row for the organization: ask); a NULL organization is its own key, never a wildcard.
- **A token ends with the grant behind its permission scopes.** Decision 69 bounded a user's
  token by the user's authority and left the agent's part to the client's `scopes`, which
  `plugins/agents` re-syncs when a grant changes but not when a windowed grant (`expires_at`)
  runs out; and a token minted inside the window kept the scope for its full lifetime. The host
  was not affected (the agent principal is intersected with live grants on every request); a
  service checking the JWT alone was. New optional interface `oauth.ClientGrantWindows`
  (`ClientPermissionsUntil`), beside `ClientAuthority`: for a client whose owner implements it,
  `tokens.held` keeps a permission scope only when a grant covers it now, and `tokens.issue` ends
  the access token no later than the first such grant (`expires_in` follows). `plugins/agents`
  implements it (`windows.go`: per permission, the latest end among the live grants requiring
  it). Tests: `TestATokenEndsWithTheGrantBehindItsScopes` (a plugin double),
  `TestADelegatedTokenEndsWithTheGrantsWindow` (`plugins/agents`). Security note: the bound is in
  the function that mints every access token; a refresh is bounded again; without an owner
  implementing the interface nothing changes. Additive Go API (`make apicheck` clean).

Verified with `make qa`, `make apicheck BASE=origin/main` and `scripts/test-db-matrix.sh
./plugins/oauth/...` (PostgreSQL, MySQL). Fuzz targets unchanged and passing.

## 76. 2026-11-22 — Operator reach and hardening before 1.0

Findings of the security review for v1 in the operator API, the agents' approval policy, the audit
drains, erasure and a few defaults. Each one that changes behaviour had a failing test before its
fix. The changelog lists what a client sees.

- **admin: impersonation follows the reach rule, and its token is not the account holder.**
  Decision 69 gave ban, password, MFA and delete one helper, `manageUser`; `impersonate` kept the
  bare capability check, so an `admin` operator could mint a token for an `owner` operator's
  account. The token carried a fresh `auth_time` and no marker the pipeline read, so it passed
  step-up and every self-service route: it could enrol a factor or register a passkey on the
  account and keep it. Now (1) `impersonate` goes through the same rule (`reachUser`: below
  `owner`, not a superadmin, not an operator of the caller's role or above); (2) the token is
  minted without `auth_time`: it is nobody's recent authentication; (3) the pipeline's
  authorization step refuses a token carrying `impersonated_by` on every route that needs no
  permission and writes, destroys or is a step-up route (`pipeline.DeniesImpersonation`), the
  rule by route shape that already keeps delegated credentials and SSO-bound sessions off the
  account holder's routes (decision 68), without the logout exception: the token has no session.
  `plugins/mcp` hides those tools from it. `token.ClaimImpersonatedBy` and
  `Token.ImpersonatedBy` are the claim in core; `admin.ClaimImpersonatedBy` is that constant.
  (4) `audit.Recorder.Record` adds `impersonated_by` to the data of every row written while the
  request's token is an impersonation, so what was done with one names the operator beside the
  user.
  Security review: only refuses more. The token still reads what the user reads and does what
  the user's permissions allow; with no organization in it, that is reads. A host route that
  resolves the actor from the user id alone does not see the claim (`Token.ImpersonatedBy` is
  there for it). Tests: `TestImpersonationDoesNotReachUpNorActAsTheAccountHolder` (admin, HTTP;
  failed before: 201 for an owner and a peer admin, `auth_time` present, factor enrolment,
  password change, organization creation and logout-all all answered 2xx),
  `TestAnImpersonatedActionNamesTheOperator` (audit; failed before). Admin fixtures replay
  unchanged.

- **admin: a grant is replaced only from within the caller's scope.** One grant per user
  (decision 60) means `POST /admin/grants` replaces the target's grant. The route checked `Own` on
  the *new* scope only, so an owner scoped to one organization could replace an instance owner's
  grant, or another organization's operator's, with a `viewer` grant on its own organization,
  and give a superadmin a grant that then stood in for the superadmin's instance role
  (`Resolve` reads the grant first). Now an organization-scoped caller is refused (403
  `admin/forbidden`) when the target holds a live grant its scope does not cover, or is a
  superadmin (`replacesGrant`); an instance owner is unchanged. Security review: only refuses
  more. The check and the upsert are two statements: two owners racing on one user can still
  interleave, both being allowed on what they read. `Grants().Grant`, the Go API and the CLI, is
  the host's and is not bounded. Test: `TestAGrantIsReplacedOnlyFromWithinTheCallersScope`
  (failed before: 201 and the three grants rewritten).

- **admin: an organization-bound session is no operator.** The admin routes are `auth: public`
  (the plugin resolves the operator itself), so `DeniesBound` never ran, and `Resolve` never read
  the binding: a session an organization's IdP opened for a user who holds a grant, or is a
  superadmin, had the full role on `/admin/*`. `Resolve` now answers nobody for
  `tok.OrganizationBound()`, which covers the middleware, `OperatorOf`, `IsOperator` and the
  plugins that ask through `AuthorizeOperator`. Capping it to the organization was considered:
  whoever runs the IdP would still hold an operator role they were never given. Test:
  `TestAnOrganizationBoundSessionIsNoOperator` (failed before: 200). Not covered here:
  `plugins/oauth`'s own default operator check, used when the admin plugin is absent.

- **agents: the auto-approval policy does not refill a budget.** A grant that spent its budget
  is `exhausted`, which is not live, so the next request for the capability found no grant and
  the policy approved a new one with a full budget: a budget of 2 allowed any number of
  executions. Now the policy does not apply while the agent has an exhausted grant of that
  capability whose window has not passed (`spentGrant`; a budget without a window never passes):
  the request is `pending` and a person decides. After the window the policy applies again,
  which is what a window means. Security review: only withholds an automatic approval. A grant a
  person revoked is still re-approved by the policy when asked again (unchanged, and tested as
  such): the policy is the host's statement that the tier needs no person. Tests:
  `TestASpentAutoApprovedBudgetIsNotRefilledByAskingAgain` (failed before: `active`, via `auto`),
  `TestThePolicyAppliesAgainAfterTheSpentGrantsWindow`. Agents fixtures replay unchanged.

- **audit: drains are guarded, never hold the writer, and report a category.** An organization's
  owner chooses a drain's endpoint. Delivery used the host's client as given (any address, any
  redirect), ran inside the write (under a host transaction, with the chain's lock row held, a
  slow endpoint stalled every audit writer for attempts × timeout), and stored the transport's
  error text in `last_error`, which the owner reads: together, a way to probe what the server can
  reach. Now:
  - `audit.Config.Drains` turns delivery on with `internal/netguard`'s client: public unicast
    addresses only, decided at connect time after DNS resolution; redirects are never followed,
    whichever client is used (`netguard.NoRedirects`, as oauth and sso do). `Config.HTTPClient`
    still turns delivery on and is used as given: the host's client says where it may go.
    **Hosts that passed a plain client and want the guard set `Drains: true` and drop the
    client.** `POST /admin/organizations/{id}/drains` also refuses an endpoint with credentials,
    a literal non-public address or `localhost` (422); names are judged at connect time.
  - A batch is handed to `wiring.Graph.Deferred` (decision 66), so it starts after the outermost
    commit and never after a rollback, and then runs on its own goroutine with its own context
    (15 s for the batch, retries included; at most 32 batches in flight, one more is dropped
    and logged). Under `sqlstore.WithTx` there is no commit to wait for and it starts at once,
    off the transaction. `Plugin.WaitDrains` waits for the deliveries in flight (shutdown,
    tests); the admin test route calls it, so it still answers the outcome.
  - `last_error` is `refused`, `timeout`, `unreachable` or `HTTP <status>`
    (`audit.DrainRefused`, …); the full error goes to the log.
  Security review: with the default client a DNS answer that changes between resolution and
  connect is still judged at connect. The status code of a public endpoint is not a secret. With
  the host's own client the guard is the host's, and the status code then reports on whatever
  that client reaches; the README says so. Delivery order between batches is no longer
  guaranteed. A process that exits with deliveries in flight loses them, as it lost a delivery in
  flight before; drains are best-effort (the database row is the record). Tests:
  `TestADrainReachesPublicAddressesOnlyAndReportsACategory`,
  `TestADrainFollowsNoRedirectAndEchoesNoTransportError` (failed before: the redirect target was
  reached), `TestADrainNeverHoldsTheTransactionThatRecorded` (failed before: delivered inside
  the transaction and for a rolled-back one), `TestADrainEndpointIsNotALiteralInternalAddress`
  (admin; failed before: 201). The admin drain fixture replays unchanged.

- **authz: no organization role grants a platform permission.** Decision 67 closed the path by
  which an organization role passed for the superadmin; while it was open, such a member was
  exempt from the escalation guard and could put `users.read` / `users.manage` into an
  organization role, and those rows kept granting the cross-tenant `/users/{id}` routes after the
  upgrade. The resolver now skips a platform permission (`authz.PlatformOnly`: the catalog's
  admin-scoped keys) when it flattens an organization's roles; only the system superadmin role
  yields them. `Migrate` deletes such grants from organization roles
  (`authz.DropPlatformGrants`, internal), returns one line per removal and logs each as a
  warning: a removed grant is evidence, and the host should review what the role's members did.
  Security review: only removes authority no template ever gave an organization role. Tests:
  `TestAnOrganizationRoleNeverGrantsAPlatformPermission`,
  `TestPlatformGrantsAreRemovedFromOrganizationRoles` (every backend; both failed before).

- **Erasure erases the plugins' rows in its own transaction.** `AnonymizeUser` committed, then
  dispatched `event.UserDeleted`; each plugin deleted its rows in a listener that logged a
  failure. An erasure could report success with an operator grant, a username or device records
  left behind. Now `Identity.OnUserDeleted`, which every path that erases or removes an account
  already calls inside its transaction (AGENT.md), runs every plugin's `wiring.AccessEraser`,
  then every `wiring.UserEraser` (new optional interface: rows about a user that are not ways to
  act as one), then the host's hook; any error rolls the erasure back. admin, audit, sentinel,
  multisession, anonymous, username, sso and scim implement `UserEraser` in place of their
  listener (`maintenance.EraseUser` replaces `EraseOnUserDeleted`); passwordless's listener
  deleted what its `EraseAccess` deletes and is gone; oauth, passkey, apikeys, agents and social
  are `AccessEraser`s and keep their listeners for the other events they handle, where the
  `UserDeleted` case now finds nothing. Sessions are still revoked after the commit (the
  denylist watermark is in the cache) and `UserDeleted` is still dispatched after it, for hosts
  and third-party plugins. Test: `TestAnErasureThatCannotEraseAPluginsRowsErasesNothing`
  (failed before: success reported, account anonymised, the grant's failure only logged).

- **Smaller items.**
  - *Device cookies behind a proxy.* multisession's and sentinel's cookies were `Secure` only
    when `r.TLS != nil`; behind a proxy that ends TLS they were not. They are now also `Secure`
    when the configured issuer is https. Tests:
    `TestTheDeviceCookieIsSecureBehindATLSTerminatingProxy`,
    `TestObserveModeRecordsWhatASignalSaidAndLetsEverythingThrough` (both failed before).
  - *messaging without a channel.* The fallback logged whole messages: reset links and codes. The
    `Log` channel now logs kind, template and recipient; `Bodies: true` adds the rest, for a
    developer's machine; `Init` warns when it falls back. Core's own development mail driver
    (`notify`, with its startup warning) is unchanged. Test: `TestTheLogAndArrayChannels`
    (failed before).
  - *IPv6 rate limits.* The per-IP key was the full address, and one subscriber holds a /64. The
    key is now the /64 for IPv6 and the IPv4 address for an IPv4-mapped one. Test:
    `TestAnIPv6ClientIsLimitedByItsNetwork` (failed before).
  - *A weak hasher is named.* `polaris.New` warns when `Config.Hasher` is an Argon2id below the
    default memory or passes (`polaristest.Hasher()` in production); not under `go test`
    (`testing.Testing`). Test: `TestAHasherBelowTheDefaultCostIsNamed`.
  - *Checked, unchanged.* `logout-all` is already refused to an SSO-bound session: the route is
    `effect: destructive` and `DeniesBound` excepts only the `write` logout of the session itself
    (`TestAuthorization`'s bound cases and sso's `TestAnSSOSessionStaysInItsOrganization` cover
    it). ui's refresh and MFA cookies stay `__Secure-`: they are scoped to the pages' path so the
    refresh token is not sent to every route, and a `__Host-` cookie must be `Path=/`.

API (additive): `token.ClaimImpersonatedBy`, `Token.ImpersonatedBy`, `pipeline.DeniesImpersonation`,
`pipeline.MsgImpersonation`, `authz.PlatformOnly`, `wiring.UserEraser`, `audit.Config.Drains`,
`audit.Plugin.WaitDrains`, `audit.Plugin.EraseUser` and the other plugins' `EraseUser`,
`audit.DrainRefused` / `DrainTimeout` / `DrainUnreachable`, `messaging.Log.Bodies`.
**Breaking** (Go API, before v1; nothing a host or a plugin calls): the `Listeners` method of the
admin, multisession, anonymous, username, sso, scim and passwordless plugins is gone (each had no
other listener; the graph calls it only through `wiring.ListenerProvider`). No new dependency. No schema change; `Migrate` may delete rows of
`auth_role_permissions` as described. Stored data stays readable; an impersonation token minted
before the upgrade keeps its `auth_time` until it expires (one access-token TTL) and is refused by
the new rule all the same.

## 77. 2026-11-22 — Follow-ups to decisions 75 and 76

- **The OAuth plugin's default operator check ignores organization-bound sessions.** Without the
  admin plugin, `plugins/oauth` treats a superadmin's session as an instance operator on its admin
  routes (`superadmins`). A session an organization's identity provider opened (amr `sso`,
  decision 68) is no operator there, as decision 76 made it for `/admin/*`. Test:
  `TestAnOrganizationBoundSessionIsNoDefaultOperator`.
- **A revoked capability is not auto-approved again.** Revoking a grant took access back, but the
  agent could ask again and the auto-approval policy handed it back. A request for a capability
  of which the agent holds a revoked grant now waits for a person (`personDecides`, next to the
  exhausted-budget rule of decision 76). A denial is not binding the same way: a person denied a
  request the policy did not cover, and the policy still covers the smaller requests it was set
  for (the recorded `testTheAskerCannotChooseItsAutoApprovalBudget` relies on it). Test:
  `TestARevokedCapabilityIsNotAutoApprovedAgain`.
- The READMEs of anonymous, username, scim, passwordless, oauth and social say erasure runs inside
  the erasure's transaction (`wiring.AccessEraser` / `wiring.UserEraser`, decision 76). The
  plugins' `event.UserDeleted` listener cases that duplicate it stay: they delete nothing more and
  cover any path that dispatches the event without the transactional erasers.
- Left as decision 76 records it: the check and the write of `createGrant` are two statements.

Security review: both changes only refuse more.

## 78. 2026-11-23 — Configuring single sign-on, deprovisioning unproven accounts, one JSON value

- **Configuring single sign-on takes the authority to grant every role of the organization.** The
  rule decision 74 set for connecting a SCIM directory now holds for an organization's providers and
  domains, for the same reason: whoever runs the identity provider signs in as any account the
  organization owns, with the roles it holds, and a verified domain says which accounts those are, so
  `org.update` alone let an administrator act as an owner. `POST /orgs/{id}/sso/providers`, `PATCH`
  and `DELETE …/{providerId}`, `POST /orgs/{id}/sso/domains`, `POST …/{domainId}/verify` and `DELETE
  …/{domainId}` need every permission
  the organization's roles grant (403 `sso/forbidden`), checked before anything is read. The check
  moved to `authz.EscalationGuard.CheckEveryRole` and `sso`'s `ownerRoute`; a write route added later
  is an `ownerRoute` or it is reviewed. `jit.roles` keeps the 422 for an unknown slug; its own
  escalation check (decision 74) is contained in the new one and gone. Reading, listing and testing
  stay with `org.update`. Test: `TestOnlyWhoCouldGrantEveryRoleConfiguresSingleSignOn` (HTTP).
- **A SCIM DELETE frees the address of an account nobody proved.** A directory of any organization
  could create an unverified account for an address nobody had registered and deprovision it: disabled,
  it could not be registered, reset or verified by the mailbox's owner. An owned account whose
  `email_verified_at` is empty is anonymised whatever the connection's `deprovision`; RFC 7644 §3.6
  asks that a deleted User is no conflict for a new one. A proven account keeps its mode.
  `directory.erase` writes the account's row first and decides on what it then reads, removes the
  membership under the owner guarantee (409 for the last active owner, in `delete` mode too), and
  anonymises in the same transaction. The host's `OnUserDeleted` runs, so a host that wants
  deprovisioned accounts kept verifies its organizations' domains (the accounts are then proven).
  Considered: leaving the account enabled and only removing the membership (the host's
  `user.disabled` would not fire for a deprovisioned employee), and letting a registration reopen a
  disabled account (nothing tells a directory's disable from an operator's). `ResendVerification`
  skips disabled accounts. Tests: `TestADeprovisionedAccountNobodyProvedFreesItsAddress`,
  `TestErasingADeprovisionedAccountChecksItAgain`, `TestResendSkipsADisabledAccount`.
- **An address is erased as often as it is registered.** The tombstone's email is the keyed hash of
  the address, so erasing a second account of one address hit the unique index and failed. When the
  hash is taken the user's id follows it (`docs/stored-formats.md`); the first erasure's format is
  unchanged. Test: `TestAnAddressCanBeErasedAgain`.
- **A provider creates accounts for email addresses only.** `sso` refuses to create an account whose
  normalized email is not one (`manifest.IsEmail`, the rule of every other account's address),
  whichever protocol implementation answered it. An account that exists with another address
  (`ada@intranet`, from an earlier release) keeps signing in. Test: `TestAnAssertionNamesAnEmailAddress`.
- **A sign-in checks the account where it opens the session.** `finish` writes the account's row,
  reads it again, repeats the ownership, status and membership checks and resolves the roles in the
  transaction that issues the session, so it and whatever ends the organization's hold queue on the row: one that committed
  since the provisioning is read, one that follows revokes the session. For the latter `RevokeAll`
  revokes by user instead of by the families it read: on MySQL (repeatable read) the families
  predate the transaction. Tests: `TestASignInThatLosesTheAccountOpensNoSession`,
  `TestRevokeAllRevokesTheSessionsIssuedSinceItsTransactionBegan` (PostgreSQL, MySQL; failed on
  MySQL).
- **A confirmed registration ends an organization's hold.** `ProveEmail` keeps everything when it
  confirms a registration's password, the plugins' access rows included; `sso` and `scim` now listen
  to `user.email_verified` and run their `EraseAccess`. Tests: `TestAConfirmedRegistrationEndsAProvidersHold`,
  `TestAConfirmedRegistrationEndsADirectorysHold`.
- **A signed payload is one JSON value.** Fuzzing (`FuzzRequestJWT`) found a request JWT whose payload
  carried data after its object accepted. `json.Decoder.Decode` reads one value and ignores the rest;
  `internal/strictjson.Decode` requires the end, and replaces it in `plugins/agents` (request JWTs,
  the body's arguments), `internal/jwtverify`, `plugins/oauth` (headers, assertions, DPoP proofs),
  `plugins/social`, `plugins/sso` (ID tokens), `plugins/mcp` (messages) and `agent` (receipts). `token/decode.go` had the check.
  A payload of `null` is refused too. `FuzzCookieCSRF`'s failing input was the test's oracle: it
  decoded a valid number beyond a float64; the pipeline's output was right. Both inputs are seeds.
- **Accepted, documented in the READMEs.** A directory learns from a 409 that an address has an
  account (RFC 7644 uniqueness; a limit on the SCIM routes would break a first sync). A domain's
  verification does not expire and its HTTPS method proves the web root. The agents policy decides
  per agent and capability name, so a new enrolment or a renamed capability starts fresh.

`plugins/ui`: the `www.`, host-route cookie and `return_to` assertions of `TestOriginIsTheConfiguredOne`
were each shown to catch their regression by mutation, and `plugins/oauth` has a test of
`oauth.PageProvider` (`TestAPageProviderFillsTheURLsTheHostLeftEmpty`).

Go API: additive (`sso.Plugin.Listeners`, `scim.Plugin.Listeners`). Contract fixtures: unchanged.

Security review (rule 6): every change refuses more, or ends more (sessions, an organization's hold),
except three. Erasing instead of disabling an unproven account removes data a directory could already
remove in `delete` mode, and only for accounts it owns and nobody claimed. The tombstone with an id
reveals no more than the row's own id. `verified` in the session and the exchange envelope is now read
in the issuing transaction, so it is never staler than before. The lock order of the two new
transactions is the account's row, then the organization's.

## 79. 2026-11-23 — Sessions: one lock per user; sign-ins checked where they open a session; domain proofs

A review of decision 78's code found races older than it, each reproduced by a failing test.

- **Opening, rotating, changing and revoking a user's sessions run one after the other.** On
  PostgreSQL (read committed) a revocation's UPDATE waited on the parent token a rotation in flight
  had claimed and never saw the child that rotation inserted, so a refresh running during a password
  reset, logout, disabling, erasure or first proof could outlive it; every revocation was affected.
  `internal/session` now takes one lock first: a no-op UPDATE of the user's `auth_users` row
  (`lockOrganization`'s idiom), in `Issue`, `Refresh`, `StepUp`, `SwitchOrganization` and every
  revocation, which all write by user. The order is the user, the user's tokens, an organization;
  `plugins/multisession` and `plugins/anonymous` take the user first too. `StepUp`,
  `SwitchOrganization` and a refresh without rotation write to the live token as it is under the
  lock, so an ended session mints nothing and a concurrent rotation does not drop the change. A
  refresh that loses to a revocation reads its token again and is an invalid grant, no longer a
  reuse alert; reuse detection is unchanged. `Issue` refuses a disabled account (`ErrInvalidGrant`).
  Tests: `TestARevocationEndsARotationInFlight`, `TestNoSessionRefreshingBackToBackOutlivesARevocation`
  (PostgreSQL, MySQL), `TestARotationThatLosesToARevocationIsNoReuse`, `TestAChangeToASessionIsMadeToItsLiveToken`,
  `TestADisabledAccountOpensNoSession`.
- **A sign-in is checked again where it opens its session.** A login read the account, verified the
  password and issued a session without looking again, so one in flight during a reset opened a
  session with the old password, and one due a rehash wrote the old password back. The transaction
  that opens the session (or issues the login_mfa ticket) starts with a conditional UPDATE that locks
  the row and holds only for an enabled account with the password that was verified
  (`holdForLogin`; a hash another login replaced is verified again). `SignIn`, passkey, social and
  passwordless sign-ins start theirs with `HoldForSignIn`: the account is enabled and its mailbox was
  not proven for the first time since it was read (which takes what signed in with it). `sso` did so
  since decision 78. Tests: `TestALoginThatLosesItsPasswordOrAccountOpensNoSession`,
  `TestAHostsSignInIsCheckedWhereItOpensItsSession`, `TestASignInWhoseAccountChangedOpensNoSession` (social,
  passkey), passwordless `AnAccountThatChangedSinceItWasReadOpensNoSession`.
- **A login_mfa ticket ends with the sessions.** The ticket stands for the first step for five
  minutes whatever happened to the account. The pipeline refuses (401) one issued before the user's
  sessions were revoked, by the denylist's watermark (written whether or not
  `AUTH_ACCESS_TOKEN_DENYLIST` makes access tokens read it); `RevokeAllExcept` (a password change)
  writes one for tickets only. A watermark lives as long as the longer of the two tokens. Test:
  `TestAnMFATicketDiesWithTheSessionsOfItsUser`, `TestRevokingTheOtherSessionsEndsTheTicketsIssuedBefore`.
- **A domain's proof stands whatever was claimed meanwhile.** Another organization's claim during the
  lookup of a verification deleted the claim being verified, which then answered 200 for a domain
  that was not verified; repeated, it kept a domain from its owner. `Domains.MarkVerified` makes the
  claim again, in place of an unverified one, in one transaction; it answers 409 when another
  organization verified the domain first and 404 when the domain's provider is gone. A claim displaces
  only a claim that is still unverified when it is deleted. Tests:
  `TestAVerifiedDomainIsItsProversWhateverWasClaimedMeanwhile`, `TestAClaimDoesNotDisplaceADomainVerifiedSinceItWasRead`.
- **A directory's write decides in its transaction.** `writeUser` locks the account and reads
  ownership, verification and address there, as `erase` does (decision 78, whose re-checks are tested
  now too). Test: `TestADirectorysWriteDecidesInItsTransaction`.
- **Smaller.** A provider's display name is trimmed and bounded (120 characters) as every other is;
  social's signed proxy state and `verify` have the one-JSON-value rule tested; tests of
  `CheckEveryRole`; a flaky assertion of `TestAnAddressCanBeErasedAgain`.
- **Accepted.** The SSO and social hand-off code is not bound to the browser that started the
  sign-in: the callback is (decision 74), but someone who completes their own sign-in can send the
  redirect with their code to another person within its minute, who is then signed in to the sender's
  account. An application ties the two itself (the READMEs say how); binding the exchange is additive
  and can come in 1.x. Deleting or disabling a provider does not end the sessions it opened; they stay
  bound to the organization and end with the membership (README). A ticket of the watermark's own
  second passes, as a login right after a reset does. A password sign-in of an unverified account
  (`RequireVerifiedEmail` off) through `SignIn` or a plugin is refused when its mailbox is proven
  while it runs, a confirmed registration included; signing in again works.

Go API: compatible; `sso.Domains.MarkVerified` may now fail with `store.ErrDuplicate` and
`repository.ErrNotFound`. The spec of `POST …/domains/{domainId}/verify` gains the 409
(`testdata/manifest/all*.json`). Contract fixtures: unchanged. No schema change.

Security review (rule 6): the lock adds one statement to each of these operations and no new
dependency; a stress of 4,800 mixed operations per database found no deadlock. What is refused that
was not: a login whose account changed, a ticket older than a revocation, a session of a disabled
account.

## 80. 2026-11-23 — Account writes under the user's lock; a lockout is the password's; disabled accounts' grants

A review of decision 79's code found it sound and five older defects beside it, each reproduced by a
failing test.

- **A password change is checked again where it is written.** `ChangePassword` verified the old
  password, hashed the new one (Argon2id, so a wide window) and wrote it unconditionally: one in flight
  during a reset replaced the reset's password and, through `RevokeAllExcept`, ended the owner's new
  sessions. It now writes in a transaction that starts with `holdForLogin`, as a login does. Test:
  `TestAPasswordChangeThatLosesItsPasswordOrAccountChangesNothing`.
- **`locked` is the password sign-in's status.** Anyone who knows an address can lock it, and nothing
  clears the status when the lock ends. `ForgotPassword`, API keys, the OAuth resolver and CIBA
  required `active`; they now refuse `disabled` only, as passkey, social, passwordless and sso already
  did. Admin impersonation still takes an active account (an operator's action, not the user's). Tests:
  `TestALockedAccountIsSentAReset`, `TestALockedAccountsGrantsKeepWorking`, the apikeys resolver's.
- **A disabled account's OAuth grants issue nothing.** `tokens.issue`, through which every grant passes,
  answers `invalid_grant` when the user behind it is disabled or gone; introspection answers inactive.
  Nothing is revoked, so enabling the account restores its grants. Test:
  `TestADisabledAccountsGrantsIssueNothing`.
- **An expired session mints nothing.** `ActiveInFamily` reads the token that is not revoked, expired or
  not; step-up, organization switch, one-time tokens and guest conversion now check its expiry. Tests:
  `TestAnExpiredSessionMintsNothing`, the passwordless and anonymous flows.
- **A rotation builds on the token as it claimed it**, so it keeps a step-up or an organization switch
  committed since it read the token; a refresh without rotation reads it again too. Test:
  `TestARotationKeepsAChangeMadeMeanwhile`.
- **Smaller.** `EnableUser` and `AnonymizeUser` lock the account and read it there
  (`TestAnErasureOutlivesAConcurrentEnable`); `Issue` refuses an account that does not exist, which also
  closes the case of a MySQL pool without `clientFoundRows`
  (`TestADisabledOrUnknownAccountOpensNoSession`); `ResetPassword` and a guest's conversion lock the user
  before the user's rows, the order everything else uses (no test of their own).
- **CI runs the tests on the newest Go** (not a required check). Go 1.27 writes U+FFFD as it is where
  1.26 escapes it; only a test depended on that. The hashed and signed forms escape it themselves.
- **Accepted.** An access token is minted after the transaction that opened or rotated its session: a
  revocation in between that crosses a second leaves it valid for its lifetime, the window access tokens
  have anyway. `/auth/switch-org` checks the membership before the session's lock: a session left on an
  organization its user just left carries no authority there. Logging out everywhere and a password reset
  do not end OAuth grants (the README says how to).

Go API: compatible. Routes, specs and contract fixtures: unchanged. No schema change.

Security review (rule 6): no check is weaker except `locked`, which was never a check on these paths'
own credentials and let anyone turn them off.

## 81. 2026-11-23 — The plugins before 1.0: what a check reads, whose authority a credential carries, what ends it

A review of the areas earlier ones had not reached. Each item was reproduced and its fix has a test that
fails without it, except where said.

- **`agents.Guard` matched a capability by the whole URL, Host included,** which the client writes: any
  other Host passed through. `capabilities.at` falls back to the path; several hosts' locations on one
  path under a Host that is none of them is refused. The rule that a JWT for several capabilities cannot
  use a location follows it (no test of its own for an unknown Host). Tests:
  `testEverySpellingOfALocationIsGuardedAndABoundMiddlewareGuardsItsRoute`,
  `TestABodyWhoseMembersAreAmbiguousIsRefused`.
  The path is compared decoded whole, as a router may read it, slash included
  (`TestGuardDecodesThePathAsARouterDoes`: `net/http.ServeMux` and a handler matching `URL.Path`).
- **A body two readers read differently is refused.** encoding/json matches struct fields by case folding
  and keeps the last; the constraint check read a map. Exact duplicates are refused too (a nested object
  given twice merges into a struct and replaces in a map), so is a declared argument in another case
  (`TestAMisspelledArgumentIsFound`) and a body that begins as an object and is not exactly one. A body
  that is no JSON object still has no arguments.
- **`AutoApprove`'s window is the window.** `withinPolicy` takes the policy's window or none asked. A shorter
  one was the whole budget again each time it passed, spent or not; decision 76's rule only saw spent
  ones.
- **A user's OAuth grants take the user's lock** (decision 79's idiom, the user before the user's tokens): every
  mint, rotation and revocation. Under read committed a revocation waited for the rotation in flight and
  missed the token it inserted. A code, an approved request, a session or a token behind a mint is looked
  at again under the lock (`issueWhile`), and taking a grant back deletes its codes and requests, which a
  redemption in flight then finds gone. Tests: `TestARotationInFlightDoesNotOutliveARevocation`
  (PostgreSQL, MySQL; fails on PostgreSQL without the lock), `TestTakingAGrantBackEndsWhatWasNotRedeemedYet`.
  Client-wide revocations (an agent's kill switch, deleting a client) do not take its users' locks: the
  client is disabled or gone, so at most an access token being minted at that moment is left.
- **`trusted` and CIBA take an owner of the instance** (`TestOnlyAnInstanceOwnerRegistersATrustedClient`).
  Clients registered before are not changed: the changelog asks to review them.
- **A token exchanged from a token ends with it** (`Grant.NotAfter`, additive;
  `TestAnExchangedTokenDoesNotOutliveItsSubject`). The recorded fixtures exchange an exchanged token at
  once and expect a whole lifetime, so that suite now runs on a standing clock; no fixture changed.
- **Revoking a client revokes its tokens, consent or not** (`TestRevokingAClientEndsItsTokensWithoutAConsent`).
- **Adding a credential takes a recent authentication.** The three MFA confirm routes,
  `/one-time-token/generate` and creating and rotating an API key are `step_up` (passkeys, phones and social
  links were; `TestRoutesThatAddACredentialTakeAStepUp` lists them). Consent decisions (OAuth, device, CIBA,
  agents) are not: they answer an application the user is using. A user with no
  factor is unaffected, as on every step-up route. Enrolling stays open: an unconfirmed factor does
  nothing. Tests: `TestConfirmingAnotherFactorTakesAFreshStepUp`, `TestConfirmingTheFirstFactorTakesNone`,
  `TestCreatingAndRotatingAKeyTakeAStepUp`.
- **MFA factors and recovery codes.** A fresh batch of recovery codes retires the one before, so codes of an
  earlier enrolment do not work after the next (`TestANewBatchRetiresTheOneBefore`); removing a factor
  is decided under the user's lock, so two concurrent removals do not leave a user for whom MFA is
  enforced without one (`TestConcurrentRemovalsLeaveAnEnforcedUserAFactor`, PostgreSQL and MySQL).
- **A social link is made while the session that started it lives** (`TestALinkEndsWithTheSessionThatStartedIt`),
  checked under the user's lock. A link in flight across the upgrade is refused; starting again works.
- **Passkey keys are bounded above** (`TestAWeakRSAKeyIsRefusedWhateverItsEncodedLength`,
  `TestCBORAllocatesWhatItReads`).
- **A credential acts as who reads its secret** (`TestARotatedKeyActsAsWhoRotatedIt`), and
  `/api-keys/verify` answers what the key would do (`TestVerifyAnswersWhatTheKeyWouldDo`).
- **Sentinel judges `endpoint.NewInput`** (`TestTheGuardReadsTheRequestAsTheEndpointDoes`); quiet mode follows
  enforced decisions and never drops account-change mail
  (`TestQuietModeFollowsEnforcedDecisionsAndLeavesSecurityMail`). A recipient's `Caps` still bound every
  message: they are the host's own limit.
- **SCIM's `active` is the membership's** (`TestADirectoryDoesNotUndoAnOperatorsBan`). A directory's own
  deprovisioning disables an account and removes it from the organization, which ends its ownership, so
  nothing else used the lines removed.
- **SSO:** `TestADiscoveryDocumentsEndpointsAreWebURLs`, `TestOnlyAMemberLogsOutThroughAnOrganization`,
  `TestSAMLRefusesSHA1Signatures` (the library's `RejectSHA1Signatures`; decided now because refusing
  later would break 1.x).
- **Passwordless sends** are bounded per destination and per account
  (`TestSendsAreBoundedPerDestinationAndPerAccount`). A destination's window is a message's own lifetime, so
  whoever spends its budget leaves its owner a live message; an account's is counted before the number is
  looked up, so it does not tell whose the number is.
- **The audit chain with per-name retention.** A checkpoint now carries each gap as the pair of hashes it
  joins (`gaps` in the `audit.pruned` event's data, additive; `last_hash` stays and older checkpoints
  read as before), re-recorded when a checkpoint is itself pruned, and none where the pruned rows did not
  chain (`TestAPrunedChainWithPerNameRetentionVerifies`). A pruning walks the table twice with the chain
  on.
- **`Migrate` reads indexes from the catalog's rows on PostgreSQL.** `pg_indexes` calls `pg_get_indexdef`, which
  does not read the query's snapshot: replicas migrating at once could fail with `cache lookup failed`
  (7 of 300 runs of `TestMigrateIsSafeOnConcurrentReplicas`, none of 1000 since).
- **Accepted for 1.0.** `amr` after the MFA gate is `pwd, otp` whatever the first step was (the recorded
  contract). The audit chain is unkeyed: it shows an alteration to whoever keeps a hash elsewhere (a sink
  or a drain), not to one who can rewrite the table; a keyed one is additive. Refresh cookies are
  path-bound and so `__Secure-`, not `__Host-`. Passwordless sends answer later for a known address where
  the host's mailer is slow: queue in the mailer. A provider's test route answers its organization's
  administrators the transport's error. Personal keys of a removed member (no permissions), the
  `MaxPerOwner` race, the lack of a prune for passwordless secrets and sentinel decisions, and sentinel's
  full IPv6 addresses are left for 1.x: none gives anyone authority they lack. The per-principal rate limit
  is the user's for every credential that acts for them. Two presentations of one refresh token (or code)
  at the same moment give one success and one plain `invalid_grant`, without the reuse alert: a client
  that submits twice does not lose its session, and a later presentation raises it. A destination is sent
  at most `SendMax` codes while one lives and as many links, more an hour than core's codes, so that
  nobody can lock its owner out; the per-address route limits bound the rest. `RevokeClientTokens` on a
  client left enabled can miss a grant being refreshed at that moment on PostgreSQL: disable the client
  first, as an agent's kill switch does. The spelling check of an agent's body covers the declared
  properties of `Protect` and `Guard`, not `additionalProperties` schemas nor `Handler` capabilities, whose
  handlers read the decoded arguments; constraints and budgets fail closed either way. These are 1.x work.

Go API: compatible (`oauth.Grant.NotAfter` added). Route specs: `step_up` and its 401 on six routes,
descriptions on five; `testdata/manifest/{core,all}*.json` follow. Contract fixtures: one step re-recorded (an
API key creating a key now answers `api-keys/not_allowed`, as on every step-up route). No schema change.

Security review (rule 6): every change refuses more than before, except quiet mode (which drops less) and
`DELETE /oauth2/consents` (which revokes more).


## 82. 2026-11-23 — 1.0: Go versions, dependencies before their 1.0, skipping v0.7.4

The three things `docs/v1.md` left to decide.

- **Go versions.** `go.mod` says `go 1.26.0`; the tests run on the latest 1.26 and on the newest Go (CI,
  decision 80). A minor release may raise the `go` line, never past the older of the two releases the Go team
  supports at the time. A patch release does not raise it, unless a security fix needs the Go release.
- **Dependencies before their 1.0.** `crewjam/saml` (v0.6), `otelhttp` (v0.72) and `skip2/go-qrcode` stay. None
  of their types is in the exported API (`go doc -all`), so any can be replaced in a 1.x release without a
  break: SAML is behind `sso.SAML` and `sso.DefaultSAML`, the QR code is drawn in `internal/mfa`, and only
  `telemetry/otel` imports OpenTelemetry. `govulncheck` watches them; its one ignore (GO-2026-6909) is
  re-reviewed at each release that moves `crewjam/saml`.
- **No v0.7.4.** Decision 81's fixes go from `main` into v1.0.0, whose notes carry them.

## 83. 2026-11-24 — Agent Auth Protocol, parts 0.1, 0.2 and 1: the client read, a harness, discovery and capabilities

The work package is [`agent-auth-compat.md`](agent-auth-compat.md): an unmodified Agent Auth Protocol
(v1.0-draft) client signs in to a Polaris server, with nothing in v1 breaking. This entry covers the
reading, the interop harness, and discovery with the capability routes; parts 2 to 4 (host keys,
registration, lifecycle) are not started.

**What the reading answered** (the protocol whole; `@auth/agent` 0.6.2 and 0.5.1 as published,
`better-auth/agent-auth` at `e89bd03`; §1.1 of the document has the detail).

- *How it finds the document:* `{url}/.well-known/agent-configuration`, then two `/api/auth/…` paths; the
  first with `version`, `issuer` and `endpoints`. It checks no version. Without `urls` (or
  `allowDirectDiscovery`) it asks only `agent-auth.directory`.
- *Absolute URLs in `endpoints`:* accepted, and Better Auth's own server sends them, against §5.1.
- *Which endpoints, in what order:* capabilities (host JWT when it has a host key; after a 401, and only a
  401, again without one), register, status while pending, execute (at the `location` the **list** gave,
  else `default_location`, else `endpoints.execute`), request-capability and status again. It reads status
  before an execution whose grant it does not know to be active, so `/agent/status` moves from part 4 to 2.
- *Each agent status:* `active` and `claimed` end a wait, `rejected` and `revoked` throw; `pending`,
  `expired` and any non-2xx answer keep it polling to the sooner of `expires_in` and 5 minutes. It never
  reactivates by itself.
- *`limit_exceeded`:* not in it. Any refusal is an error with the body's code and message.
- *Not asked, and it matters:* its agent JWTs carry no `iss`, which §4.3 requires. Part 2 checks `iss` when
  it is there; requiring it would refuse every agent this client registers.
- The protocol's published version is `1.0-draft`, so the document's `version` was not a gap.

**Discovery (5.1): a document the host chooses,** not a merged one. Absolute URLs do not rule a merged
document out; the names do. `register`, `capabilities`, `request_capability`, `status`, `revoke` and
`execute` are in the v1 document with other URLs and meanings, and that document stays as it is.
`Config.Discovery` is `DiscoveryPolaris` (the zero value) or `DiscoveryAgentAuth`;
`GET /agents/configuration` is always Polaris's, and the Go SDK falls back to it when the well-known
document names no `enroll` (a usable document without one is still used when there is no second). A
v1.0.0 SDK finds no server in `DiscoveryAgentAuth` mode: documented, and the mode is opt-in.

- The protocol document's `issuer` is `Config.BaseURL`, not `AUTH_ISSUER`: §5 resolves its relative paths
  against it, and `AUTH_ISSUER` may be any string and knows no mount prefix. It is the `aud` too.
- It names only the endpoints served, so it never promises a 404; each part adds its own.
- Also decided: 5.5 (`limit_exceeded`, from §5.13) and 5.6 (the version label stays). Open with what is
  now known: 5.2, 5.3, 5.4, and a new 5.7, the rate limit of the protocol routes (§8.13): the three
  routes here have none, as the two they sit beside.

**The capability routes.**

- List entries carry `location`, which §5.2's text leaves out: the reference client executes at the list's
  location and at no other (Better Auth's server lists it). `permission` and `risk` stay off the protocol's
  bodies. `query` matches when each word is in the name or the description; `cursor` is opaque (the last
  name), and one the server did not answer is 400 `invalid_request`; a page is at most 100.
- An agent authenticates with a request JWT or its OAuth token (§12.1 allows it) and then gets
  `grant_status` on every entry, `granted` or `not_granted`. Any other credential is 401 `invalid_jwt`, a
  host JWT included until part 2: never read as anonymous, and the client asks again without it.
- Codes and statuses are §5.13's: 400 `invalid_request`, 401 `invalid_jwt` (a wrong `aud` too), 403
  `agent_revoked`; a suspended agent is 403 `agent_suspended`, an extra code, until 5.2 is decided.
- Anonymous answers are cached for five minutes with `Vary: Authorization`, an agent's not at all.

**The harness.** `scripts/e2e-agent-auth.sh` runs `@auth/agent` against `internal/e2e/agentauthserver`, in
its own CI job, which is not a required check. It exits 3 when it stops exactly where the server stops
today, at registration and for a missing route, with every step before it passed, and 1 for anything else;
CI accepts 0 and 3. So a regression before registration fails the job, and the job cannot go quiet when
registration starts to work. New dependency, for this job only: `@auth/agent` 0.6.2 and its `jose`, from
npm, pinned by hash in the harness's lock file and installed without scripts; nothing a host builds, and
no change to `go.mod`.

**Where the specs are.** `internal/apispec/api/agents/agents/protocol/`: the manifest reads the plugin and
the route's name from the path, so they are `polaris.agents.protocol.*` of the plugin `agents`. The
router takes the first match in load order, so a spec must sort before any whose parameter matches its
path; `TestNoRouteIsHiddenByAParameter` now checks that for every route.

Go API: additions only (`make apicheck BASE=v1.0.0`): `Config.Discovery`, `DiscoveryMode` and its two
values, three `Err*` names. Fixtures: three added, none changed; `testdata/discovery-v1.0.0.json`, written
by v1.0.0's code, holds the default document. Manifest goldens: three routes added. No schema or stored
format.

Security review (rule 6): `requestJWTs` gains an exact audience and a clock leeway, used only by the two
capability routes; with neither set, what the Polaris routes check is unchanged, and their tests and
fixtures pass untouched. On the new routes the `aud` is compared exactly (§8.18), `iat` and `exp` have 30 s
(§8.2), a `jti` is spent once across both surfaces and remembered past lifetime plus leeway (§4.6), and
`htu` is still the URL called. They answer what `GET /agents/capabilities` already answers anyone, and write
nothing. §4.5's host checks wait for host keys: no agent registered through the protocol exists yet. Tests
name the section of each rule.

## 84. 2026-11-24 — Agent Auth Protocol, part 2: hosts with keys, registration, status, requests, execution

Part 2 of [`agent-auth-compat.md`](agent-auth-compat.md). The unmodified `@auth/agent` client signs in
through a host whose key its owner registered: register, wait for a person, request a capability, execute
it, read its status. A receipt is appended and verifies. Hosts the server does not know are part 3.

- **A host with a key** is a `polaris_agent_host` row with `public_key` or `jwks_url` from
  `POST /agents/hosts`, and no enrolment token (the column holds the hash of a secret nobody is given).
  There is no `status` column: a stored host is live or revoked, and one nobody approved is never stored.
  A key and a URL are one host's for good (unique, revoked hosts included, §8.8.1).
- **A host JWT** is verified against the stored host only: `iss` finds it, its stored key (or the key `kid`
  names in its set) verifies, and `iss` must be that key's thumbprint. The delivery mode is fixed (§8.7).
  The shared rules (time, lifetime, single use) are `requestJWTs`' own methods, so the two edges differ
  only in what §2.4 lists.
- **JWKS URLs** go through `netguard`, follow no redirect (§8.12 allows three, none is needed), are bounded
  in size and time, and are fetched at most once a minute each, only for a host an owner registered. The
  whole set is validated first; one bad key refuses it. Taken with `DiscoveryAgentAuth` unless
  `DisableJWKSURLs`. `agent_jwks_url` is refused: no client needs it yet.
- **An agent's `iss`** is checked when it is there, as the reference client sends none (decision 83). Its
  host is the one it is stored under; a revoked one refuses it.
- **`pending` and `rejected`** are new agent statuses, for a registration in which a person must approve
  everything. Reporting an active agent with pending grants would not work: the client shows an approval
  only for a `status` of `pending`. They are stored, not computed, so "a pending agent cannot
  authenticate" (§2.3) is the check every suspended agent meets, on every surface. The decision and the
  status change in one transaction; a denial is terminal (§7.1) and disables the agent's OAuth client.
  §5.3 also describes a fully denied registration as active; §7.1 and the client agree on `rejected`.
- **Revoking a host with a key revokes its agents** (§8.5) with the kill switch, in one transaction that
  takes the host's row first, as a registration does: a registration in flight is revoked with it or
  finds it revoked. `decide` now takes the agent's row first too, the kill switch's order.
- **Answers.** `status` beside §5.4's members, because the client reads it; one grant per capability;
  `violations` with the constraint's operand; `limit_exceeded` for a spent budget; 400 `invalid_request`
  for arguments the schema refuses; a removed capability is 403 (§2.12). An exact value (§2.13) becomes
  `in` with one value; an unknown operator is refused by name.
- **429** answers the code a plugin route's spec declares: `rate_limited` on these four.
- **A protocol key has one spelling.** base64url's last character has spare bits and Go's decoder ignores
  them, so one Ed25519 key had four spellings and four thumbprints: one key could be several hosts. Keys
  of the protocol surface are taken in the canonical form only, and points of small order (for which
  anyone can make signatures) are refused. `/agents/register` and `/agents/enroll` take keys as in v1.0.0.
- **Left open, in §5 and §6 of the document:** capabilities with a `Location`, whose protocol body
  `Protect` does not read (5.8); proof that a pre-registered key is the owner's (5.9); limits per host and
  agent (5.7); what `suspended` reports (5.2; `pending` for now).

Go API: additions only. Routes: four added, two (`POST`, `DELETE /agents/hosts`) describe more and answer as
before without a key. Fixtures: three added, none changed; the harness masks the receipt's id in a header.
Schema: three nullable columns and two unique indexes on `polaris_agent_host`; `testdata/upgrade` gains the
v1.0.0 export and `Migrate` reaches HEAD from it. Fuzz targets: `FuzzHostJWT`, `FuzzKeySet`. The interop
harness now stops at an unknown host, exit status 3.

Security review (rule 6), independent, of the whole change: no bypass, confusion of credentials, SSRF or
escalation. Fixed from it, each with a test: the spellings and small-order keys above; a host revocation
that read before it locked, and on MySQL could miss an agent registered at that moment
(`TestARegistrationDoesNotOutliveItsHost`; SQLite answered busy); what an unverified `iss`,
`host_jwks_url` or `sub` may look up (a NUL was a 500 on PostgreSQL, for `sub` since v1.0.0); a denied
registration's tokens, now revoked; a revoked host's URL, no longer fetched. Accepted: a pending agent's
OAuth client can mint tokens, which nothing accepts, as a suspended one's; an agent of a token host that
sends an `iss` is refused on the protocol routes, where it has no host key to name; a removed key of a
JWKS host verifies until the cached set expires (five minutes, §10.4). For part 3: the cleanup also
deletes a known host's registrations whose approval expired, which stay pending until then.


## 85. 2026-11-24 — Agent Auth Protocol, part 3: hosts the server does not know

Part 3 of [`agent-auth-compat.md`](agent-auth-compat.md). The unmodified `@auth/agent` client signs in from a
host nobody registered: it registers an agent, shows a person a code, they approve, and it works. The
interop harness passes whole (exit status 0), and its CI job stops accepting 3.

- **A registration is a row of its own** (`polaris_agent_registration`), and nothing is a host, an agent or an
  OAuth client before a person approves it (§8.10). Its grants and its approval are ordinary rows that name
  the agent it may become, so the approval routes read and decide it as any other. The policy approves none
  of it. The agent keeps the id the client was told: `oauth.Plugin.CreateClientAs`, new, creates a client
  under a `client_id` its caller chose. No route lets a requester choose one.
- **Opt-in.** Taken with `DiscoveryAgentAuth` only, and not with `Config.DisableDynamicHosts`: it is an
  unauthenticated write, which an upgrade must not switch on. In the default mode nothing changes.
- **Who approves owns it.** Whoever signs in with the code decides (device authorization, never a push to
  somebody an unknown host names), and the host and the agent are theirs, in their active organization. The
  first approval links the host (§2.9); from then on only its owner decides its other waiting registrations,
  and a key an owner registers meanwhile makes it theirs the same way. The unique key and a check in the
  transaction hold that under a race; a revoked host's registrations cannot be approved (§2.11).
- **A fresh sign-in, always** (§8.11): `step_up` at least, whatever `Strengths` says, and `auth_time` within
  `StepUpMaxAge` for a person without a second factor too, whose any session satisfies `step_up`. 5.3 (the
  grants' own strengths) stays open.
- **A denial is of that agent, not of the host.** §2.11's `rejected` host is not stored: anyone signed in with
  the code could close the server to a device for good. The host may ask again with another key.
- **A pending host** registers and reads the status of its own registrations, which §7.1 needs and §4.5.1
  step 8 does not name. Elsewhere it is unknown, 401 (2.4). An agent JWT of it is `agent_pending`, 403.
- **JWKS URLs of unknown hosts are refused** (5.10): the server would fetch a URL an anonymous caller chose.
- **Idempotent by host and agent key** (§5.3), known hosts too: pending answers the same agent, its approval
  opened again when that expired (`expires_in` is what is left of an open one), any other state is 409
  `agent_exists`. `polaris_agent.key_thumbprint`, unique with the host, holds it.
- **Cleanup** (§7.1, §10.9): a registration ends a day after its approval expired or was denied, and reads as
  gone then, deleted or not. A new registration deletes a few ended ones; `Plugin.Prune`, new, deletes all,
  and the pending agents of known hosts nobody decided, which decision 84 left.
- **Limits** (§8.13): a new registration of an unknown host spends a budget per address of its own, at
  `RateLimits.Register` (5 an hour); a retry does not. IPv6 counts per /64, as everywhere: the key moved from
  `pipeline` to `internal/netguard` so that both use it. Where unknown hosts are taken, on `GET /agents/approvals/code` a code that stands
  for none of the caller's agents' approvals spends `RateLimits.MFAConfirm` per person, a right one for an unowned
  registration too: codes used to be worth guessing to nobody but their owner.
- **What people are shown** (§8.10): names need a visible character, and text written by a host holds no
  control, bidirectional or line separator character. `host` and `reason` are in the approval, unproven.
- A host JWT's `jti` is spent under its signing key's thumbprint, not the host's id, so one used before the
  approval is not usable after it.

Go API: additions only (`make apicheck BASE=v1.0.0`): `Config.DisableDynamicHosts`, `Plugin.Prune`,
`ErrAgentExists`, `EventRegistrationRequested`, `EventRegistrationDenied`, `TableRegistrations`,
`oauth.Plugin.CreateClientAs`. Routes: none added; four specs say more. Fixtures: two added, none changed.
Schema: one table, one nullable column and one unique index on `polaris_agent`; `Migrate` reaches HEAD from every
released schema. Fuzz target: `FuzzUnknownHostJWT`.

Security review (rule 6), independent, by reading the whole change: no bypass, takeover, replay across the
approval, or change in the default mode. Fixed from it and from the correctness review, with a test except
for the last two: the approval's id was in the event (whoever signs in with it may approve), an old session of a person without a
second factor could approve, names of invisible characters only, a denied key that stayed taken until
something pruned it, the size of the cleanup a registration runs, and an agent key registered twice
answering 500. Accepted: linking a host is a standing grant to what the policy approves, which the approval
page must say (README); a person can be sent somebody else's code, as with any device code; guessing a code
(19^8) is bounded per account, not across accounts; confusable names are shown as they are.

## 86. 2026-11-24 — Agent Auth Protocol: a host's key is proven, and approvals prove a person

What parts 2 and 3 left open in [`agent-auth-compat.md`](agent-auth-compat.md) §5 is decided there (5.2, 5.3, 5.4,
5.7 to 5.10). This entry builds the two that were holes, 5.9 and 5.3. Neither is in a release: `public_key`,
`jwks_url` and `DiscoveryAgentAuth` are all new since v1.0.0.

- **A key is registered with its holder's proof (5.9).** `POST /agents/hosts` took any public key: Eve could
  register Ada's, and Ada's client was then active at once as Eve's agent, with nobody asked, what it wrote in
  Eve's account, and Ada's own registration refused. `public_key` and `jwks_url` now need `proof`, a JWT signed by
  that key (`typ` `host-link+jwt`) whose `sub` is the account that will own the host. A host JWT would prove
  possession and not consent, and a server a client was lured to may hold one for this server (§8.9). With a URL,
  the account, the audience and the times are read before the URL is fetched, how many a person sends is limited
  (the `MFAConfirm` budget), what the URL served is not told, and the host is known from the start by the key that
  signed. Refused with 422 like any other field.
- **`agent.SignHostLink`** makes it. The reference client cannot, and comes in as an unknown host instead; its
  `enroll_host` posts an unsigned key, so it would prove nothing.
- **Approvals in `DiscoveryAgentAuth` mode (5.3).** The defaults are `step_up` for low risk and `passkey` for medium
  and high (§8.11: proof of presence for what changes data; an undeclared risk is medium). Every approval needs
  a sign-in within `StepUpMaxAge`, whatever `Strengths` says, which `step_up` alone does not ask of a person without
  a second factor. `passkey` needs the session's `mfa`: a passkey that only proved presence (possible with the passkey
  plugin's `NoMFAFactor`) is not enough. API keys and OAuth tokens have no `auth_time` and approve nothing there.
- **Linking a host takes the strength of what the policy then gives without a person.** With
  `AutoApprove[high]` and `Strengths[high]: passkey`, a `step_up` link was followed by a high-risk execution nobody
  approved.
- **What an owner registers by hand needs the same.** A host or an agent the owner creates (`POST /agents/hosts`,
  `POST /agents/register`) gets what the policy approves too. In `DiscoveryAgentAuth` mode both need the strength an
  unknown host's approval has, a recent sign-in included (403 `step_up_required`).
- **It fails closed.** Such a server without the passkey plugin could approve nothing, so it does not start unless it
  sets `Strengths` for the tiers it uses; the error names both ways out.
- In the default mode nothing changes: strengths, `satisfies` and its passkey rule are v1.0.0's.

Go API: additions only: `agents.HostLinkJWTType`, `agent.HostLinkJWTType`, `agent.SignHostLink`. Routes: none added;
`POST /agents/hosts` has one more field. Fixtures: three of part 2's, in no release, re-recorded, because their request
now carries the proof; their responses replay unchanged. No schema or stored format.

Security review (rule 6), independent, of the whole change: no way to register a key for an account its holder did not
name, and no way to approve in protocol mode below the approval's strength. Fixed from it, each with a test: an owner's
old session could create a host (and, found beside it, an agent) that the policy then serves; the unbounded fetches
and the telling refusals of an unproven `jwks_url`; a proof `SignHostLink` makes being refused where
`RequestJWTMaxAge` is under five minutes (a link has its own bound now). Two tests it showed missing were added.
Accepted: an approval keeps the strength it was opened with, so one opened before a restart with stricter `Strengths` is
decided at the old one until `ApprovalTTL` ends (the recent sign-in is asked all the same); `Strengths` set to
`passkey` without the passkey plugin starts, as another plugin may sign people in with passkeys.

## 87. 2026-11-24 — Agent Auth Protocol: capabilities at a Location, and rate limits

The other half of part 3b of [`agent-auth-compat.md`](agent-auth-compat.md): 5.8 and 5.7.

- **A protocol agent at a `Location` (5.8).** Its client posts `{capability, arguments}` there (§2.15), which `Protect`
  and `Guard` read as the arguments, so none could be called. They now unwrap it for an agent a host's JWT
  registered (it has a `key_thumbprint`). What is stored decides, never the body: a capability may take arguments of those names,
  and no agent v1.0.0 had is one, so every caller it had is served as it was. Such an agent
  whose host is gone is refused.
- The body is those two members and nothing else, `capability` is the location's, and `next` reads the bytes of
  `arguments` as they were sent: what was checked is what is read. `body_hash` covers the body as sent.
- The JWT is held to 2.4 there: `aud` is exactly the configured `Location` (the Host header plays no part), 30 s of
  skew, the host's `iss` and revocation. Refusals of the caller and of what it sends are §5.13's.
- Only the body is checked, so such a call has no query, the handler is told the body is JSON, and trailers and
  `Content-Encoding` are dropped.
- A handler's JSON success is answered as `{"data": ...}`, 200: §5.11 requires it, and a handler's own
  `{"status": "pending", "status_url": ...}` would read as an asynchronous answer, which the client polls with its
  JWT. An empty success is `{"data": null}`, and headers that described the body are dropped. Anything encoded, partial,
  not JSON or not a success passes as it is.
- **Rate limits by identity (5.7, §8.13).** Per agent 60 and per host 300 a minute, its agents' requests included, counted
  only once the JWT verified: a `sub` or an `iss` anybody can write spends nobody's budget. Per address 600, before
  anything is verified. `Config.RateLimits` sets others. They apply on the six protocol routes, and per agent and host
  at a `Location`. Discovery, a cached constant, has none; an unknown host's new registration keeps its 5 an hour.
- **These routes left the `token_refresh` group,** which they shared with the refresh of people's sessions: five agents
  waiting for approval behind one address used it up. A group of their own would be a field of `config.RateLimits`,
  which breaks a host that fills that struct in, so the plugin counts. Their successes no longer carry `X-RateLimit-*`.
  The Polaris agent routes of v1.0.0 keep the group: a follow-up.

Go API: additions only: `agents.Config.RateLimits`, `agents.RateLimits`, `agents.ErrRateLimited`. Routes: none added; four
lost `rate_limit`, two declare 429. Fixtures: five of parts 2 and 3, in no release, re-recorded; statuses and headers
compared with the old ones, only `X-RateLimit-*` left. No schema or stored format.

Security review (rule 6), independent, of the whole change: nothing critical or high. Fixed from it, each with a test: an
argument in the query or a form, which only the handler would read; an agent whose host row is missing being served by
the looser rules; a wrapped answer keeping headers, or a type, of the body it replaced; the agent read twice per
call. Three checks no test held now have one. Accepted: 413 and an ambiguous URL are answered before the caller is
known, in Polaris's words; the same agent on the Polaris routes is bounded by the `token_refresh` group and its budgets,
not by these limits; at another route `Protect` guards for the same capability the JWT still names the `Location`. For
an agent v1.0.0 had, a query is passed on as it was; the README says to read the body.

## 88. 2026-11-24 — Agent Auth Protocol, part 4: the lifecycle

Part 4 of [`agent-auth-compat.md`](agent-auth-compat.md): all twelve endpoints are served. The unmodified client reads a
paused agent, rotates its host's key and revokes an agent in the harness.

- **Revoking** (§5.7, §5.10) is the kill switch the owner has, called with the host's JWT; again, it answers the same. A
  denied registration is over already (`agent_rejected`).
- **Rotating an agent's key** (§5.8) takes the host's JWT only (5.11), as the section says and the reference client does
  not: whoever stole an agent's key could otherwise replace it. The old key and every token it minted stop in one
  transaction. A suspended agent's leaked key is replaced too.
- **Rotating a host's key** (§5.9) proves nothing of the new key, so it would have reopened what decision 86 closed. The
  new key is only claimed (`claimed_thumbprint`, not unique; `key_thumbprint` is null): it is the host's once a call it
  signs names an agent of the host, or the host's owner approves a registration it signs, or with `proof`. Until then
  the server does not know the key, and a claim keeps nobody from using theirs. A host's key is refused. A JWKS host
  rotates at its URL.
- **Lifetimes** (§2.4), off by default, bound the agents hosts' JWTs registered: the others have no host to reactivate
  them. `expired`, and `revoked` past the absolute lifetime, are read from the clocks, not stored, so every check meets
  them wherever an agent is loaded; `Prune` and a reactivation run the kill switch past the absolute one. The last use
  is written at most once a minute, so a session lasts at least two.
- **Reactivating** (§5.6) brings an agent back to its host's default capabilities. What a person gave, and what is no
  default, ends. A live grant the policy gave of a default is kept with what is left of its budget: ended and given
  again it would be refilled, which the policy never does. When a person must approve all of it the agent is pending,
  its clocks unchanged: denied, it is expired as it was, not rejected, and a pruning does not delete it.
- **`suspended` is `pending`** (5.2), reactivation included: 403 `agent_pending`. The absolute lifetime outranks it.
- **Introspection** (§5.12) is for an OAuth client an operator trusted (5.4), as `POST /oauth2/introspect`;
  `oauth.Plugin.AuthenticateTrusted` is the check. The JWT's `aud` must be the issuer, the execute route or a configured
  `Location` and is answered, so that one resource server's JWT is not another's. The `jti` is not spent. A refused
  caller spends the address's budget, a resource server none.

Go API: additions only: `agents.Config.Lifetimes`, `agents.Lifetimes`, `agents.StatusExpired`, `Agent.ActivatedAt`,
`Agent.LastUsedAt`, two `Err*`, three `Event*`, `oauth.Plugin.AuthenticateTrusted`. Routes: six
added. Fixtures: one added; three of parts 2 and 3, in no release, re-recorded, as a status now has `activated_at` and
`last_used_at`. Schema: two nullable columns on `polaris_agent`, one, and an index, on `polaris_agent_host`; `Migrate` reaches HEAD from
every released schema.

Security review (rule 6), independent, of the whole change: nothing critical or high, no way to gain anything from
another's client, and no expired agent that acts. Fixed from it, each with a test except where said: a claimed key
took the unique column, so that it locked a JWKS host out of a key it published (the claim above is the second design);
two reactivations at once (a check in the transaction, no test: a race); a denied registration reading revoked past
the absolute lifetime. Two checks of introspection no test held now have one. Accepted: introspection limits who is
refused, not who is right, and a client's secret is 256 random bits; it counts as a use of the agent; an approval denied
after `Lifetimes` was turned off leaves the agent active with no grant it had to ask for; a registration that waited under
a host's old key expires; an agent past its absolute lifetime keeps its OAuth client until `Prune`, and nothing here
accepts its tokens.

The claim was reviewed once more on its own: nothing critical or high. Fixed from it, each with a test: a colleague's
claim, by an organization's host, on the key of a registration its approver made (only a host the approver registered
counts now); a claim made over between being read and taken. Accepted: a host JWT taken from an open TLS connection
before it is spent can rotate the host's key, as §5.9 binds it to no body; a host revoked while its new key is only
claimed no longer reserves its old key, which must then be approved by a person as any unknown one; the 409 tells that a
key is a host's.

## 89. 2026-11-24 — Behind Protect only the JSON body carries arguments, and agents' own rate limit

The user decided both, and that the passkey default for medium risk (5.3 of [`agent-auth-compat.md`](agent-auth-compat.md))
stays, before `v1.1.0`. Both change what v1.0.0 does.

- **What was checked is what is read.** Constraints are checked on the JSON body. A handler that calls `FormValue` read the
  query, and a JSON text sent as a form, as a form: `{"amount":1}` with `?amount=999` was checked at 1 and ran at 999. The
  request JWT's `aud` and `htu` leave the query out, so nothing bound it either. Decision 87 closed it for protocol agents;
  now every agent is held to it, by `Protect` and by `Guard`.
- **Refused,** with 422 `agents/invalid_arguments`, audited: a query; a body that is not one JSON object (a form, XML, an array
  and `null` ran with no arguments); one whose `Content-Type` is not JSON, is sent twice, malformed or not
  UTF-8, or whose bytes are not. Refusing forms alone would have left every other type. `+json` types pass and stay as they were sent. A request
  without a body has no arguments, whatever its type.
- **Dropped:** a form that something before `Protect` parsed (it left no body to check, and the handler read it), trailers,
  `Content-Encoding`, `GetBody`. Headers, cookies and path values are the route's and stay: the README says no constraint covers them.
- **No opt-out:** a switch back would be an insecure setting in the v1 API. It breaks clients that send a query,
  a form, or JSON as another type; the 1.0.0 release notes allow that for a security fix nothing else closes. JSON without a type was first
  refused too, which broke the plugin's own example and every `agent.Do` that sets none, and closes nothing: it passes, and the
  handler is told `application/json`. The release note
  says so, and a GitHub advisory follows with `v1.1.0`.
- **Agents' own rate limit.** The four v1.0.0 routes agents call (`/agents/enroll`, `execute`, `grants/request`, `session`) spent
  the `token_refresh` budget of their address, with people's refreshes. Their group is `agents` now: as large as
  `RateLimits.TokenRefresh`, so that a host that sized it keeps what it set, and counted under a key of its own. A field
  of its own in `config.RateLimits` would refuse a host that fills that struct in, as in decision 87. Same headers and
  429. `/oauth2/*`, `/mcp` and passkey's options still share `token_refresh`.

Go API: none. Routes: none added; four specs name another `rate_limit`, as do the manifest goldens. Fixtures: none changed. No schema
or stored format.

Security review (rule 6), independent, of the whole change: nothing critical or high. Fixed from it, each with a test: an RFC 2231
`charset*=`, which Go reads as no parameter; a body that is not UTF-8; `GetBody`, with which a proxy behind `Protect` reads the
body as it was sent; a parsed multipart form and an agent's access token had no test. Each check was removed, with a failing
test. Accepted: a refused request has spent its `jti`, as before; lone surrogates in a JSON string are read as U+FFFD by Go;
a key prefix a host chose for another group could be the agents' one (`<TokenRefresh's>.agents`); an envelope a protocol
agent sends wrong is refused unaudited, as before.

Taking a body without a type was reviewed once more on its own, with the fixes above: nothing a client can reach. Accepted: a
host's own middleware that writes a header key which is not canonical (`r.Header["content-type"]`) is not seen by the check.

## 90. 2026-11-24 — Agent Auth Protocol, part 5: the release

The documents of `v1.1.0`, and what the package's acceptance ([`agent-auth-compat.md`](agent-auth-compat.md) §4) still asked.

- **`examples/agents -protocol`** serves the protocol's clients beside its own demo, which its test plays in both modes. Against it, by
  hand, the unmodified `@auth/agent-cli` 0.5.1 connected from an unknown host, was approved by code, ran both capabilities (one at its
  `Location`), was refused past its constraint and revoked its agent; its MCP server ran one. That is not in CI, which runs
  `@auth/agent` 0.6.2 (decision 83). The CLI's `--url` takes a list, so a flag must follow it: the README says so.
- **A minor version,** although decision 89 changes what v1.0.0 took behind `Protect`: no Go API, route or stored data breaks, and the
  1.0.0 release notes keep that room for a security fix nothing else closes.
- **Held back until the release:** decision 89 describes a hole v1.0.0 has, so it is pushed, merged and tagged in one go, and the
  advisory follows (SECURITY.md).

Go API, routes, fixtures, schema: none.

## 91. 2026-11-25 — With the denylist on, a session's access tokens end with it

With `AUTH_ACCESS_TOKEN_DENYLIST` on, ending one session ended its refresh token only. The denylist held one watermark per
user, and only ending every session wrote it, so the access token answered until it expired: after a logout, a session
revoked from another one, a replayed refresh token, a suspended membership, and, for the sessions it was meant to
throw out, a changed password.

- **An entry per session** (`polaris.denylist.session.<sid>`), and its presence is the refusal. A watermark would let through
  what a racing refresh, step-up or organization switch signs after the session ended. Presence is safe because no
  family opens again: `revoked_at` is never cleared, a row joins a family only by a rotation that claimed its live
  token under the user's lock, and a new family has a new id.
- **It lives one minute more than the watermark.** That racing token is signed after the entry is written, and
  replicas' clocks differ; with the same lifetime its last moments would pass.
- **Written where sessions end** (`Service.end`): for the session named, or for every family with a token that matches and was
  ended on purpose within an entry's lifetime. They are read after the UPDATE, in its transaction, under the user's lock:
  MySQL's repeatable read shows a transaction the rows it updated. Families another call ended are included, so the
  same call again completes one whose cache failed. The bound keeps a user's history out. Rotated ancestors, which name an
  organization their session left, are not matched. The multisession switch ends a family itself, so it calls `RevokeFamily`, last.
- **After the commit;** in a transaction of the caller's, by the call, as the watermark is. A rollback there leaves the
  session live and its access tokens refused, refreshed ones too, until the entry expires: `Sessions.Revoke` says so.
  `AfterCommit` would avoid that and could not return a cache's error. The write does not stop when the caller
  hangs up, and takes 5 seconds at most; one key that fails does not keep the others from being written.
- **A cache that fails is an error** once the database is done. The theft alert of a replayed refresh token is dispatched first.
- **With the denylist off** nothing is written and nothing asked: a cache must not fail a logout it plays no part in.
- **Every place that takes a session's token:** the pipeline (`Require`, `Protect`, `Authenticate`, every route), the admin
  resolver, and two that had no check at all. `oauth.superadmins`, the default operators of `/admin/oauth`, whose routes are public to
  the pipeline, took a superadmin's token after a logout everywhere, against what `config.AccessToken.Denylist` documented.
  MCP listed tools for such a token and would have run those of a third-party plugin (Polaris's own run behind the pipeline).
  `oauth.sessionSubject` already asks the database, and is unchanged.
- **Guests' `Prune`** deleted sessions without any entry, or the watermark. It calls `RevokeAll` in the guest's transaction:
  before the rows that name the sessions go, so that a cache that fails leaves the guest to the next prune, and after the
  host's `OnUserDeleted`, which now runs first, so that a hook that fails leaves a live guest its access token.
- **Not changed:** tokens without a `sid` from API keys, OAuth and agents. `ChangePassword` commits the password
  before it ends the sessions, so a retry after a failed cache is ending them (`DELETE /auth/sessions/{id}`, `/auth/logout-all`), not
  changing the password again.

Go API: additions only: `pipeline.SessionDenylist`, an optional interface as `MFATicketFactors` is; `wiring.Denylist.Refuses`, on a sealed
interface. Routes, schema: none. Fixtures: none changed, as they run with the denylist off but for one, whose answers are the same.
Stored formats: one transient cache key. Clients of a host with the denylist on see 401 `session_ended` where an
ended session answered, a second logout included.

Security review (rule 6), two independent ones, of the whole change: nothing critical or high. Fixed from them, with a test: MCP skipped the
watermark for a token of no session (an impersonation). Each check was removed in turn, with a failing test. Accepted: the rollback above; a cache that is down holds the user's
lock up to 5 seconds in the calls made within a transaction, as the watermark's did; a token signed more than a minute after its session
ended (a host's slow `Claims` hook) can outlive the entry by as much; a host that replaces `pipeline.Options.Denylist` with one that
is no `SessionDenylist` keeps the per-user check only. The reviews ran no PostgreSQL or MySQL, and
do not cover `Prune`, which was added after them.

Tests: `TestEndingASessionEndsItsAccessToken`, `TestSuspendingAMemberEndsTheAccessTokensOfThatOrganization`, `TestAFailedRevocationIsRetried`,
`TestARevocationInTheHostsTransactionEndsTheAccessToken`; `internal/session/denylist_test.go`; `TestTheDenylistRefusesTheTokensOfAnEndedSession`
(pipeline); `TestAnEndedSession…` (admin, oauth, mcp), `TestAnEndedDeviceSessionsAccessTokenIsRefused` (multisession);
`TestAPrunedGuestsAccessTokenEndsWithTheDenylist` (anonymous).
