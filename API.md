# API stability (v0.x)

Polaris for Go is pre-1.0. This page says what an application or a plugin may rely on, and what may
still change. Any change to a **stable** name below needs a decision entry in
`docs/port/decisions.md` and a note in the release; everything else may change in a minor release.
The HTTP routes, the database schema and the token formats are frozen separately (they match
polaris-core; `docs/port/spec.md` §3) and never change without an upstream change.

## 1. The host surface (stable)

What an application imports. A host never needs another package.

| Package | Stable names |
|---|---|
| `polaris` | `New`, `FromEnv`, `Config` (every field), `Polaris` (`Handler`, `Protect`, `Migrate`, `Users`, `Orgs`, `Sessions`, `Can`, `Graph`), `PrincipalFrom`, `Principal`, `Kind` and `Kind*`, `Hooks`, `ClaimsInput`, `User`, `NewUser`, `Organization`, `Tokens`, `SignIn`, `Users`, `Orgs`, `Sessions` and their methods, `ErrNotFound`, `ErrConflict`, `ErrForbidden`, `ErrInvalidInput`, `ErrInvalidCredentials`, `PasswordError` |
| `plugins/<id>` | `New(Config)`, the `Config` fields, the documented claim / AMR / route constants, the services a README names (`apikeys.Of(g).Keys()`, …) |
| `store/sqlstore` | `Open`, `New`, `WithTx`, `Store.DB` |
| `store` | `Dialect` values, `Adapter` (to pass one), `ErrDuplicate` |
| `polaristest` | `New` and its options, `Server` fields |
| `agent` | the Go agent SDK: `New`, `GenerateKey`, `ImportKey`, `Enroll`, `RequestGrants`, `WaitForApproval`, `Execute`, `Do`, its errors |
| `plugins/mcp` | `Protect`, `ProtectConfig`, `Claims`, `ServeStdio` |
| `cli` | `Run` |
| `config` | `Secrets`, `Auth` and `Defaults`, the `Signer*` values (fields may be added) |

Behaviour that is part of the contract: `Protect` answers 401 without a principal and 403 without a
permission, and resolves the caller's authority on every request; hooks run inside the account's
transaction; `Hooks.Claims` refuses reserved names; the programmatic API applies the HTTP routes'
rules, events and audit, for a trusted caller (the actor recorded is `system`).

Adding a field to a stable struct, a method, an option or a constant is not a breaking change;
hosts should use keyed struct literals.

## 2. The plugin SDK (stable, may grow)

What a third-party plugin builds on: `wiring` (`Plugin` and its optional interfaces, `Graph` and its
read-only accessors, `Hooks`, `User`, `Tool*`, `Ports`), `endpoint` (`Endpoint`, `Input`, `Result`,
the request-context accessors, envelope and problem helpers), `manifest` (`Route`, `Load`, input
rules), `event` (`Event`, `Listener`, `Dispatcher`, `Bus`, the core event types and names) and
`token` (`Token`, `Kind`, `KindOf`, `NewPrincipal`, `Delegate`, `Claims`, `Codec`).

New optional plugin interfaces and new `Graph` accessors are added without notice. Removing or
changing one is a breaking change.

## 3. Public but not stable

The domain packages the SDK's signatures name are importable, and a plugin may call them, but their
API follows the implementation and may change in any minor release: `identity`, `orgs`, `session`,
`mfa`, `authz`, `repository`, `model`, `schema`, `security`, `notify`, `cache`, `clock`,
`ratelimit`, `metrics`, `pipeline`, `store/memstore`, `store/storetest`. A host that finds itself
importing one of them for an everyday task should report it: the host surface is missing something.

## 4. Internal

`internal/…` (core's endpoints, the observers, maintenance jobs, the upstream manifest mirror and
fixtures, the contract-test harness, the SSRF guard) cannot be imported from outside the module.

## 5. Changed in this release (from the first port)

- `polaris.Principal(ctx) *token.Token` and `polaris.Authority(ctx)` are replaced by
  `polaris.PrincipalFrom(ctx) (polaris.Principal, bool)`; plugin code reads the raw token with
  `endpoint.Token(ctx)`.
- `wiring.Graph` fields became accessor methods (`g.Repos` is `g.Repos()`).
- `session.Service.Mint` takes a `context.Context` first.
- `contracttest`, `httpapi`, `upstream`, `observe` and `maintenance` moved under `internal/`; the
  upstream mirror lives in `internal/upstream/`.
- `Protect` without permissions now resolves the caller's authority (one more query per request).
