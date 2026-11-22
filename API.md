# API stability (v0.x)

Polaris for Go is pre-1.0. This page says what an application or a plugin may rely on, and what may
still change. Any change to a **stable** name below needs a decision entry in
`docs/decisions.md` and a note in the release; everything else may change in a minor release.
`scripts/api-stable.txt` lists the stable names for the machine: `make apicheck` (CI, on every pull
request) fails on an incompatible change to one of them that `decisions.md` does not record.
The HTTP routes, the database schema and the stored formats (password hashes, ciphertexts, tokens)
are a contract of their own: the contract tests replay every route, `testdata/vectors` pins the
formats, and a change to any of them is a decision in `docs/decisions.md` and a release note (AGENT.md
rules 4 and 5).

## 1. The host surface (stable)

What an application imports. A host never needs another package.

| Package | Stable names |
|---|---|
| `polaris` | `New`, `FromEnv`, `Config` (every field), `Polaris` (`Handler`, `Protect`, `Require`, `Authenticate`, `Migrate`, `Users`, `Orgs`, `Sessions`, `Can`, `Graph`), `PrincipalFrom`, `Principal`, `Kind` and `Kind*`, `RequireKind`, `RequireOrganization`, `Hooks`, `ClaimsInput`, `User`, `NewUser`, `Organization`, `Tokens`, `SignIn`, `ImportedUser`, `Users`, `Orgs`, `Sessions` and their methods (`Users.Import` included), `ErrNotFound`, `ErrConflict`, `ErrForbidden`, `ErrInvalidInput`, `ErrInvalidCredentials`, `PasswordError` |
| `plugins/<id>` | `New(Config)`, the `Config` fields, the documented claim / AMR / route constants, the services a README names (`apikeys.Of(g).Keys()`, `ui.Plugin.RequireSignIn`, …) |
| `store/sqlstore` | `Open`, `New`, `WithTx`, `Store.DB` |
| `store` | `Dialect` values, `Adapter` (to pass one), `ErrDuplicate` |
| `polaristest` | `New` and its options, `Server` fields |
| `agent` | the Go agent SDK: `New`, `GenerateKey`, `ImportKey`, `Enroll`, `RequestGrants`, `WaitForApproval`, `Execute`, `Do`, its errors |
| `plugins/mcp` | `Protect`, `ProtectConfig`, `Claims`, `ServeStdio` |
| `verify` | for a service that is not the Polaris host: `New`, `Config` (every field), `Verifier` (`Verify`, `Require`), `Claims`, `ClaimsFrom`, `ErrInvalidToken`, `ErrUnavailable` |
| `cli` | `Run` |
| `config` | `Secrets`, `Auth` and `Defaults`, the `Signer*` values (fields may be added) |
| `telemetry/otel` | `Middleware`, `Store`, `Listener` and their options |
| ports a host implements | `security.PasswordHasher` (and the optional `security.HashChecker`, with `security.ErrUnsupportedHash`), `security.BreachedPasswordCheck`, `notify.Mailer`, `notify.SMSSender`, `clock.Clock`, `cache.Cache`, `ratelimit.Store` (and `ratelimit.Result`), `metrics.Metrics` |

Behaviour that is part of the contract: `Protect` answers 401 without a principal and 403 without a
permission, and resolves the caller's authority on every request; `Require(perms...)(next)` is
`Protect(next, perms...)`; `Authenticate` lets a request without a credential through anonymous and
answers 401 to a credential that does not verify (never anonymous); `verify` accepts only RS256 and
EdDSA access tokens of the configured issuer and audience, and refuses DPoP-bound ones; hooks run
inside the account's transaction; `Hooks.Claims` refuses reserved names; the programmatic API applies the HTTP routes'
rules, events and audit, for a trusted caller (the actor recorded is `system`).

Adding a field to a stable struct, a method, an option or a constant is not a breaking change;
hosts should use keyed struct literals.

## 2. The plugin SDK (stable, may grow)

What a third-party plugin builds on: `wiring` (`Plugin` and its optional interfaces, `HandlerProvider` for HTML pages included, `Graph` and its
read-only accessors, `Hooks`, `User`, `Tool*`, `Ports`), `endpoint` (`Endpoint`, `Input`, `Result`,
the request-context accessors, envelope and problem helpers), `manifest` (`Route`, `Load`, input
rules), `event` (`Event`, `Listener`, `Dispatcher`, `Bus`, the core event types and names) and
`token` (`Token`, `Kind`, `KindOf`, `NewPrincipal`, `Delegate`, `Claims`, `Codec`).

The core services reach a plugin as narrow interfaces declared in `wiring`: `Identity`, `Sessions`,
`MFA`, `Orgs`, `Denylist`, `Catalog`, `Resolver`, `Gate`, `Principals`, `Pepper`. Each holds only
the methods plugins call; the services behind them may grow and change freely. A method a plugin
needs is added to its interface. `TestGraphAccessorsReturnOnlyStableTypes` keeps every `Graph`
accessor on a stable type.

Two rules a plugin follows (decision 68). A path that establishes control of an account's mailbox
calls `Graph.Identity().ProveEmail` and never writes `email_verified_at` itself; a plugin whose
tables hold a way to act as a user (a credential, a key, a grant) implements `wiring.AccessEraser`,
so a mailbox's first proof removes what was there before it. And a route reserved to the account
holder declares no `requires_permissions` and an `effect` other than `read` (or `step_up`): the
pipeline keeps delegated credentials (`pipeline.DeniesDelegate`) and organization-bound SSO
sessions (`pipeline.DeniesBound`, `token.Token.OrganizationBound`) off it.

Stable with them, because the SDK's signatures name them: packages `model` (the rows; frozen with
the database) and `schema` (the table DSL a `SchemaProvider` uses); `Graph.Repos` (`repository.Repos`,
its repositories, `repository.Table`, `NewID`, `ErrNotFound`); `security.Encrypter`; and the
values the narrow interfaces and plugin hooks take or return (`identity.LoginResult`,
`session.Info`, `mfa.LoginChallenge`, `mfa.FactorType`, `orgs.Member`, `authz.Authority`,
`authz.Caller`, `authz.Permission`, `pipeline.Pipeline`, `pipeline.BearerResolver`, …; the full
list is `scripts/api-stable.txt`).

New optional plugin interfaces, new `Graph` accessors and new methods on the narrow interfaces are
added without notice. Removing or changing one is a breaking change.

## 3. Public but not stable

Everything else in the domain packages: the concrete services (`identity.Service`,
`session.Service`, `mfa.Service`, `orgs.Service`, `authz.Gate`, …) and the rest of `identity`,
`orgs`, `session`, `mfa`, `authz`, `repository`, `security`, `notify`, `cache`, `clock`,
`ratelimit`, `metrics`, `pipeline`, plus `store/memstore` and `store/storetest`. They are
importable, but their API follows the implementation and may change in any minor release. A host
that finds itself importing one of them for an everyday task should report it: the host surface is
missing something.

## 4. Internal

`internal/…` (core's endpoints, the observers, maintenance jobs, the route specs and
fixtures, the contract-test harness, the SSRF guard, the access-token verifier `verify` and `plugins/mcp` share, the concrete services for core) cannot be imported from outside the module.

## 5. Changes

What changes in each release, breaking changes marked, is in [CHANGELOG.md](CHANGELOG.md); the
reason for each is in [docs/decisions.md](docs/decisions.md).
