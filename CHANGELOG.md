# Changelog

What changes for an application (a "host") or a plugin author in each release of Polaris for Go.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the pre-1.0 rule that a minor
release may break what [API.md](API.md) does not mark stable, and breaks a stable name only with a
decision in [docs/decisions.md](docs/decisions.md) ("decision N" below). Breaking changes are
marked **Breaking**.

## [Unreleased]

### Added

- `SECURITY.md`: how to report a vulnerability privately, and what happens next.
- This changelog. Each GitHub Release now carries its version's section as release notes.
- `plugins/ui`: server-rendered sign-in, MFA, sign-up, email verification, forgot / reset password,
  sign-out and OAuth consent / device pages under `/auth/ui`, without JavaScript;
  `RequireSignIn(p.Protect(h))` for your own pages; `examples/webapp` (decision 57).
- `wiring.HandlerProvider`: a plugin serves HTML pages under its own path prefix.
- `oauth.PageProvider`: a plugin (`ui`) fills the `ConsentURL` and `DeviceURL` you left empty.
- `p.Require(permissions...)`, `Protect` as `func(http.Handler) http.Handler` middleware, and
  `p.Authenticate` for routes open to anonymous callers (a token that does not verify is still
  401). `polaris.RequireKind` and `polaris.RequireOrganization` (decision 55).
- Package `verify`: checks Polaris access tokens in another Go service against the issuer's JWK Set
  (RS256 and EdDSA only, typ, iss, aud, exp, scopes). It cannot see revocations or permission
  changes until a token expires; see its package documentation (decision 55).

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

[Unreleased]: https://github.com/univeros/polaris.go/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/univeros/polaris.go/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/univeros/polaris.go/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/univeros/polaris.go/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/univeros/polaris.go/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/univeros/polaris.go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/univeros/polaris.go/releases/tag/v0.1.1
