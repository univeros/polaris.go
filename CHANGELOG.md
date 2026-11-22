# Changelog

What changes for an application (a "host") or a plugin author in each release of Polaris for Go.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the pre-1.0 rule that a minor
release may break what [API.md](API.md) does not mark stable, and breaks a stable name only with a
decision in [docs/decisions.md](docs/decisions.md) ("decision N" below). Breaking changes are
marked **Breaking**.

## [Unreleased]

## [0.5.0] - 2026-11-22

Security fixes for replicas, account lifecycle and MFA; your own permissions grantable to roles;
`Migrate` that evolves an existing database. **Run `Migrate` after upgrading**: it adds two
tables (`polaris_audit_chain`, `polaris_scim_user_name`) and swaps an admin index, and it stops with
a remedy if your data needs a manual step (see the admin entry under Security). Read the
**Client-visible** entries under Changed if you have front ends or API clients: the magic-link page,
429 bodies, `budget_exhausted` and whole-second token timestamps.

### Added

- `Migrate` (and `polaris migrate`) keeps an existing database current: besides creating missing
  tables, it adds the columns and indexes a release declares on an existing table and drops the
  indexes it retires. It never drops a table or a column, never changes a column's type, and is
  safe on replicas booting together. New: `sqlstore.Store.Migrate`, `schema.Model.DropIndex`
  (decision 63).
- Runnable examples for `Protect`, `PrincipalFrom`, `Can`, `Orgs`, `Sessions` and `polaristest.New`.
- For plugin authors: `endpoint.WithMFATicketFactors` and `endpoint.MFATicketAllows`,
  `pipeline.MFATicketFactors`, `session.MFATickets.IssueFor` / `AuthenticateFactors`,
  `passwordless.RouteMagicLinkConfirm`, `passwordless.KindMFASameChannel` /
  `ErrMFASameChannel`. `mfa.Tickets` (not in the stable API) has `IssueFor` instead of `Issue`, and
  `mfa_factors` joined the reserved claim names (`session.ReservedClaim`).
- `Config.RolePermissions`: say which system roles (`owner`, `admin`, `member`) hold your own
  permissions, e.g. `{"owner": {"invoices.read"}}`. Every organization's copy of the role holds
  them (existing organizations on the next `Migrate`), so an owner can put them into custom roles,
  invitations, API keys and agent grants. Before, nobody but a superadmin could grant a host
  permission; drop any workaround that wrote role grants through `Graph().Repos()` (decision 62).
- `endpoint.TooManyRequests` for plugin authors: the 429 in the route's error style (decision 62).

### Changed

- `Polaris.Migrate` returns every change it made: the tables it created, as before, then one
  `"<table>: added column <c>"`, `"created index <i>"` or `"dropped index <i>"` line per change to
  an existing table. `polaris migrate` prints "Applied N change(s)"; its JSON `created` list holds
  the same lines (decision 63).
- **Client-visible:** `GET /magic-link/verify` answers an HTML page (no JavaScript) with one "Sign
  in" button instead of the 302; the button posts to the new `POST /magic-link/verify`, which
  spends the link and answers the 302 with the hand-off code as before. The emailed link,
  `/magic-link/exchange` and the codes are unchanged. A front end that fetched the link itself
  and expected the redirect must now POST to it (decision 61).
- `anonymous.Config.OnConvert` runs inside the conversion's transaction (like
  `Hooks.OnUserCreated`): write through `ctx` and the move commits or rolls back with the
  conversion. A hook that writes elsewhere may run again on a retry; keep it idempotent.
- `plugins/mcp`: `tools/list` is paginated. A result carries at most `mcp.ToolsPageSize` (100)
  tools and a `nextCursor` when more follow; send it back as `params.cursor`. An invalid cursor is
  `-32602`. Lists of 100 tools or fewer are unchanged; MCP clients that follow `nextCursor` (the
  specification requires it) see every tool (decision 60).
- **Client-visible:** access tokens and OAuth access / ID tokens carry `iat`, `nbf` and `exp` as
  whole seconds, with `exp` = `iat` + the lifetime exactly; they used to carry microsecond
  fractions that many JWT libraries refuse. Tokens issued before still verify (decision 62).
- **Client-visible:** a 429 now has a JSON body: `{"error":"too_many_requests","message":…}` on
  core routes and your `Protect` routes, an `application/problem+json` document on plugin routes.
  `Retry-After` and `X-RateLimit-*` are unchanged (decision 62).
- **Client-visible:** `plugins/agents`: once a grant's budget is spent, further calls answer 403
  `budget_exhausted` (`agent.ErrBudgetExhausted`) instead of `capability_not_granted`
  (decision 62).
- `plugins/scim` adds a table, `polaris_scim_user_name`; run `Migrate` after upgrading
  (decision 62).

### Fixed

- Erasing a user (`Users().Delete`, the self-service and admin erase, SCIM delete, guest pruning)
  now deletes every plugin row keyed to it: usernames, verified phones and pending passwordless
  codes and links, multi-session and sentinel device records, operator grants, OAuth authorization
  codes, device codes and CIBA requests, SCIM provenance and user mappings, the guest row and the
  audit activity row. Client-visible: `GET /admin/users/{id}` of an erased user answers
  `last_active_at: null` (decision 61).
- The anonymous README said conversion ends the guest's sessions without saying that, with
  `AUTH_ACCESS_TOKEN_DENYLIST` off, the guest's access token answers until it expires (as every
  revoked session's does). It now says so; `config.AccessToken.Denylist` documents the window.
- `plugins/audit`: audit rows of core events (`org.*`, `session.*`, `mfa.*`, `user.*`) record the
  request's `ip` and `user_agent`, as plugin events already did (decision 62).
- `plugins/scim`: a User answers back `name.givenName` and `name.familyName` as the directory sent
  them, so a directory comparing resources sees no difference. A PATCH of one part keeps the other
  (decision 62).

### Security

- MFA: a passwordless sign-in and a second factor on the same channel no longer count as two
  factors. After an email code or magic link to an address (or an SMS code to a phone), the
  `mfa_required` envelope lists only factors that do not deliver there, and the `mfa_token` is
  bound to the factors it lists: `/auth/mfa/challenge` and `/auth/mfa/verify` answer 404 for
  another factor (recovery codes still work). A user whose only factor delivers there gets 403
  `passwordless/mfa_same_channel` and signs in with the password, or adds a factor. The passkey
  sign-in, which already left its own passkey out of the list, now has the same enforcement
  (decision 61).
- `plugins/passwordless`: email security scanners can no longer spend magic links; opening the
  link spends nothing (see Changed) (decision 61).
- `plugins/social`: two concurrent unlinks can no longer remove an account's last way to sign in;
  the check and the delete are one transaction with the user's row locked (decision 61).
- `plugins/anonymous`: a guest conversion is one transaction. Before, if ending the guest failed
  after `OnConvert` ran, the conversion stayed recorded, the guest's sessions stayed live and a
  retry answered `not_a_guest`; now any failure leaves the guest as it was and a retry converts it
  (decision 61).
- `plugins/audit`: with `HashChain` on, replicas writing at the same time no longer fork the hash
  chain (two rows linked to one predecessor, or ids out of chain order), which made `Verify`
  report breaks in an untampered table. Each chained write now first takes the lock row of a new
  table, `polaris_audit_chain`, so writers in every process append one at a time. **Run
  `Migrate` after upgrading**: it creates the table; until then chained writes fail (logged) with
  an error naming it. Existing chains keep verifying. On SQLite, set a busy timeout
  (`_pragma=busy_timeout(5000)`) so concurrent writers wait (decision 60).
- `plugins/admin`: two concurrent first grants for one user could both insert, leaving the user
  with two operator grants of which either one applied. `polaris_admin_grant.user_id` is now unique
  and the losing grant is applied as an update, as if it had come second (decision 60).
  **Upgrade:** `Migrate` adds the unique index (`polaris_admin_grant_user_unique`) and drops the old
  `polaris_admin_grant_user_index`. If your database already holds two grants for one user,
  `Migrate` stops with an error naming `polaris_admin_grant` and `user_id`. Find them with
  `SELECT user_id FROM polaris_admin_grant GROUP BY user_id HAVING COUNT(*) > 1`, revoke the ones
  you do not want (`DELETE /admin/grants/{id}` or `Grants().Revoke`), and run `Migrate` again.

## [0.4.1] - 2026-11-22

Security fixes. Upgrade: `go get github.com/univeros/polaris.go@v0.4.1`. Check the `mcp.Protect`
entry if your MCP server accepts tokens from an issuer other than Polaris.

### Security

- `plugins/social`: a provider's `email_verified` / `verified` is true only when the provider
  sends true, "true" or 1. The string "false", other strings and container values were read as
  verified, which could let a trusted provider link to an existing account (decision 59).
- `mcp.Protect` refuses OpenID ID tokens, even when their `aud` equals the resource. **Changed:**
  a typ JWT token (or one without typ) is accepted only with a Polaris session token's `roles`
  list; tokens from another issuer must be `at+jwt` (decision 59).

## [0.4.0] - 2026-11-22

Drop-in sign-in pages, users brought over with their existing passwords, middleware for every Go
router, and token verification in your other services. No breaking change: the stable API
([API.md](API.md)), the routes, the database schema and every stored format are unchanged, so an
upgrade is `go get github.com/univeros/polaris.go@v0.4.0`.

### Added

- `plugins/ui`: server-rendered sign-in, MFA, sign-up, email verification, forgot / reset password,
  sign-out and OAuth consent / device pages under `/auth/ui`, without JavaScript;
  `RequireSignIn(p.Protect(h))` for your own pages; `examples/webapp` (decision 57). The pages
  serve one configured origin (`ui.Config.BaseURL`, default `AUTH_ISSUER`), so they work behind a
  TLS-terminating proxy. Passkey, social and magic-link buttons are not in the pages yet.
- `wiring.HandlerProvider`: a plugin serves HTML pages under its own path prefix.
- `oauth.PageProvider`: a plugin (`ui`) fills the `ConsentURL` and `DeviceURL` you left empty.
- `p.Users().Import(ctx, polaris.ImportedUser{…})`: create an account with the password hash your
  previous system stored. The user signs in with the password they already have, and that first
  sign-in rehashes it to Argon2id. Verified (never created): bcrypt, Argon2id/Argon2i, Django and
  passlib PBKDF2-SHA256/512 and scrypt, Firebase's scrypt. Cost parameters are bounded; imports go
  through `Hooks.OnUserCreated` and join `sqlstore.WithTx` (decision 56).
- `security.HashChecker` and `security.ErrUnsupportedHash`: an optional method on a custom
  `Hasher` that `Import` uses to refuse a hash it could not verify.
- `p.Require(permissions...)`, `Protect` as `func(http.Handler) http.Handler` middleware, and
  `p.Authenticate` for routes open to anonymous callers (a token that does not verify is still
  401). `polaris.RequireKind` and `polaris.RequireOrganization` (decision 55).
- Package `verify`: checks Polaris access tokens in another Go service against the issuer's JWK Set
  (RS256 and EdDSA only, typ, iss, aud, exp, scopes; ID tokens and DPoP-bound tokens refused). It
  cannot see revocations or permission changes until a token expires; see its package
  documentation (decision 55).
- Runnable examples: `examples/agents`, `mcp`, `b2b`, `signin-methods`, `hooks` and `webapp`, each
  with a curl walkthrough and a test that keeps it working.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and `docs/v1.md` (what 1.0 requires). Each
  GitHub Release now carries its version's section as release notes.

### Changed

- The code reads as a Go library: comments, internal names and test names no longer refer to the
  PHP project (decision 58). No behaviour changed.
- The `cache.ErrInvalidKey` message says "contains a reserved character" (was "reserved by
  PSR-16"). Match the error with `errors.Is`, not its text.

### Fixed

- Nested guards (`Authenticate` then `Require`, or `Protect` inside `Protect`) resolve the
  credential and run plugin middleware once per request; an API key's rate limit was counted
  twice.

## [0.3.1] - 2026-11-22

Documentation only; no code change. Upgrade freely.

### Changed

- Package documentation (pkg.go.dev) and the README describe Polaris for Go as its own product and
  say what each package does. The README's code snippets are compiled by the test suite.

## [0.3.0] - 2026-11-21

Polaris for Go is its own product (decision 53): it no longer tracks the PHP Polaris
(`polaris-core`), and the two may diverge. Routes, tables and stored formats are still the same in
this release; if you share a database or clients with the PHP version, read the release notes of
each upgrade from now on.

### Changed

- **Breaking (client-visible):** the server identifies as Polaris for Go (decision 54). MCP
  `serverInfo` carries the running Polaris release as its version and a "Polaris for Go: …"
  description. The OpenAPI document (`polaris manifest --format=openapi`, the MCP schema resource)
  is titled "Polaris for Go" and versioned with the running release.
  `/.well-known/agent-configuration` `agent_sdk_versions` names the Go agent SDK,
  `{"github.com/univeros/polaris.go/agent": "<release>"}`, instead of the PHP and TypeScript SDKs.
  Update clients that match on any of these strings. The release is read from the build
  information: the version of `github.com/univeros/polaris.go` your `go.mod` requires, or `devel`.

### Removed

- **Breaking:** `manifest.UpstreamVersion` (decision 54). There is no replacement constant; the
  version in the documents above comes from the build information.

### Fixed

- MCP tool output schemas let every inferred scalar be `null` (decision 52). An MCP client that
  validates a tool result against its `outputSchema` no longer rejects results such as
  `GET /auth/me` with `"display_name": null`.

## [0.2.1] - 2026-11-20

Documentation only; no code change.

### Added

- `plugins/sso/README.md`: configuring SAML and OIDC single sign-on for an organization.

## [0.2.0] - 2026-11-20

### Added

- [API.md](API.md) states what is stable in v0.x: the host surface (package `polaris`, plugin
  constructors and configs, `store/sqlstore`, `polaristest`, `agent`, `cli`, `config`,
  `telemetry/otel`), the plugin SDK (`wiring`, `endpoint`, `manifest`, `event`, `token`) and the
  interfaces a host implements (`security.PasswordHasher`, `notify.Mailer`, `notify.SMSSender`,
  `cache.Cache`, `ratelimit.Store`, `clock.Clock`, `metrics.Metrics`, ...). Pull requests are
  checked against it (`make apicheck`).

### Changed

- **Breaking (plugin SDK):** `wiring.Graph`'s `Identity`, `Sessions`, `MFA`, `Orgs`, `Denylist`,
  `Catalog`, `Resolver`, `Gate`, `Principals` and `Pepper` return narrow interfaces declared in
  `wiring` instead of the concrete services (decision 51). Code that only uses package `polaris`
  is not affected. If you called a method through `Graph()` that the interface no longer has, use
  the programmatic API (`p.Users()`, `p.Orgs()`, `p.Sessions()`, `p.Can()`) or open an issue
  asking for the method.

### Removed

- **Breaking (plugin SDK):** `Graph.Escalation` and `Graph.Tickets` (decision 51).

## [0.1.2] - 2026-11-20

### Fixed

- Social sign-in: the binding cookie's `__Host-` prefix, `Secure` and `SameSite=None` follow the
  scheme of `Config.BaseURL` instead of the incoming connection (decision 50). Behind a
  TLS-terminating proxy the cookie was set `SameSite=Lax`, Apple's cross-site `form_post` callback
  did not carry it, and Sign in with Apple failed with `state_invalid`. Set `Config.BaseURL` to
  your public `https://` URL.

### Changed

- The module is public: `GOPRIVATE` is no longer needed to fetch it.

## [0.1.1] - 2026-11-20

First release under the module path `github.com/univeros/polaris.go`.

### Added

- Package `polaris`: `New` / `FromEnv`, an `http.Handler` with the core auth routes (accounts,
  email verification, password reset, MFA, sessions with rotating refresh tokens, organizations,
  invitations, roles and permissions), `Protect` middleware, `PrincipalFrom`, host hooks, and a
  programmatic API (`Users`, `Orgs`, `Sessions`, `Can`) that applies the routes' checks, events and
  audit.
- Storage in your own PostgreSQL, MySQL or SQLite database (`store/sqlstore`), with `Migrate`
  creating the missing tables; `polaristest` for a test server in one line.
- Plugins: `audit`, `admin`, `apikeys`, `oauth` (OAuth 2.1 / OpenID Connect provider), `agents`,
  `mcp`, `passwordless`, `username`, `anonymous`, `multisession`, `social`, `passkey`, `messaging`
  (SMTP, Twilio, Vonage, HTTP), `sentinel` (risk scoring), `scim`, `sso` (SAML and OIDC).
- The Go agent SDK (`agent`), the `polaris` CLI (`cmd/polaris`, `cli.Run`), OpenTelemetry
  instrumentation (`telemetry/otel`), EdDSA signing keys published in the JWKS.

### Security

- Ships the fixes from the pre-release security review (decisions 38, 39, 42, 43): an
  organization's SCIM connection or identity provider could take over accounts outside that
  organization; social login and account linking were open to login CSRF; `mcp.Protect` accepted a
  login MFA ticket as an access token when the issuer was also a configured audience. No released
  version contains these vulnerabilities.

`v0.1.0` was tagged under the earlier module path `github.com/univeros/polaris-go`; it cannot be
fetched as `github.com/univeros/polaris.go`. `v0.1.1` is the same code under the new path.

[Unreleased]: https://github.com/univeros/polaris.go/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/univeros/polaris.go/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/univeros/polaris.go/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/univeros/polaris.go/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/univeros/polaris.go/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/univeros/polaris.go/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/univeros/polaris.go/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/univeros/polaris.go/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/univeros/polaris.go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/univeros/polaris.go/releases/tag/v0.1.1
