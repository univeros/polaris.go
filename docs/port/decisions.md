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
