# The Go API and what v1 promises

Polaris for Go follows Go's module rules, not a list of its own: **every exported name of every
package outside `internal/` is the API**, and from `v1.0.0` on it is covered by semantic versioning.
What you can import is what is promised; nothing is "public but not stable". What Polaris must stay
free to change lives under `internal/`, where the compiler keeps it out of reach (decision 70).

Until `v1.0.0` is tagged, a release may still break a name; each break is a decision in
`docs/decisions.md` and a **Breaking** line in [CHANGELOG.md](CHANGELOG.md).

The HTTP routes, the database schema and the stored formats (password hashes, ciphertexts, tokens)
are contracts of their own, kept by other means: the contract tests replay every route,
`testdata/vectors` pins the formats, and a change to any of them is a decision and a release note
(AGENT.md rules 4 and 5).

## 1. The promise

From `v1.0.0`, within major version 1:

- **Nothing is removed or changed incompatibly.** A program that compiles against `v1.x` compiles
  against every later `v1.y`, and what it relied on keeps its documented behaviour.
- **Things are added.** New packages, functions, methods, struct fields, constants, event types,
  optional plugin interfaces and `Config` fields arrive in minor releases.
- **Things are deprecated, not removed.** A name with a better replacement gets a `// Deprecated:`
  comment that names the replacement, and a CHANGELOG entry. It keeps working for the rest of v1.
- **A removal needs v2.** An incompatible change ships only as a new major version, whose module
  path ends in `/v2`; v1 code keeps building against v1.

`make apicheck` holds the module to this (section 6).

What you must do for the promise to hold, as for the Go standard library:

- Use keyed struct literals (`polaris.Config{DB: db}`), so a new field does not break you.
- Do not implement an interface Polaris implements for you (the sealed ones, section 3); in a test,
  embed it.
- Do not depend on what is documented as unspecified, on the text of an error message meant for
  logs (match errors with `errors.Is` / `errors.As`), or on the order of things documented as
  unordered. A `switch` over event types or kinds needs a `default`: new ones are added.
- A security fix may change behaviour when nothing else closes the hole. It is then a decision and
  a release note, and the Go API still compiles.

Not covered: `internal/…`, the programs (`cmd/polaris`'s `main`, `examples/…`), test files and
`testdata/`.

## 2. For a host

What an application imports. An everyday host needs nothing else.

| Package | What it is |
|---|---|
| `polaris` | `New`, `FromEnv`, `DevEnv`, `Config`, `Polaris` (`Handler`, `Protect`, `Require`, `Authenticate`, `Wrap`, `Migrate`, `Prune`, `Users`, `Orgs`, `Sessions`, `Can`, `Graph`), `PrincipalFrom`, `Principal`, `Kind*`, `RequireKind`, `RequireOrganization`, `Hooks`, the `Users` / `Orgs` / `Sessions` services and their values, the `Err*` sentinels, `PasswordError` |
| `event` | for `Config.Listeners`: `Event`, `Listener`, the event types and their `Name*` constants |
| `plugins/<id>` | `New(Config)`, the `Config` fields, the claim / AMR / route constants, the services a README names (`apikeys.Of(g).Keys()`, `ui.Plugin.RequireSignIn`, `mcp.Protect`, …) |
| `store/sqlstore`, `store` | `Open`, `New`, `WithTx`, `Store` (`DB`, `Tx`, `Conn`, `AfterCommit`, `Close`); the `Dialect` values, `Adapter`, `ErrDuplicate` |
| `config` | `Secrets`, `Auth`, `Defaults`, the `Signer*` values |
| `verify` | for a service that is not the Polaris host: `New`, `Config`, `Verifier`, `Claims`, `ClaimsFrom` |
| `agent` | the Go agent SDK: `New`, `GenerateKey`, `Enroll`, `RequestGrants`, `WaitForApproval`, `Execute`, `Do` |
| `telemetry/otel` | `Middleware`, `Store`, `Listener` and their options |
| `cli` | `Run` |
| `polaristest`, `notify/notifytest` | `New` and its options, `Server`, `Hasher`; the recording mailer and SMS sender |

The ports a host may implement, each with the implementation Polaris uses by default:

| Port | Default, and helpers |
|---|---|
| `security.PasswordHasher` (optional `security.HashChecker`, `security.ErrUnsupportedHash`) | `security.Argon2id` |
| `security.BreachedPasswordCheck` | `security.HIBP`, `security.NoBreachCheck` |
| `notify.Mailer`, `notify.SMSSender` | `notify.NewLogMailer`, `NewLogSMS`, `DiscardMailer`, `DiscardSMS`; the `Template*` names a mailer switches on, `Subject`, `Text` |
| `cache.Cache` | `cache.NewMemory`; `ValidateKey` |
| `ratelimit.Store` (`ratelimit.Result`) | `ratelimit.NewCacheStore`; `Check`, `Headers` |
| `clock.Clock` | `clock.System`; `clock.NewFrozen` for tests |
| `metrics.Metrics` | `metrics.NewLog` |
| `store.Adapter` | `store/sqlstore`; `store/memstore` for tests; `store/storetest.Run` is the conformance suite an adapter passes |

Behaviour that is part of the contract: `Protect` answers 401 without a principal and 403 without a
permission, and resolves the caller's authority on every request; `Require(perms...)(next)` is
`Protect(next, perms...)`; `Authenticate` lets a request without a credential through anonymous and
answers 401 to a credential that does not verify (never anonymous); `verify` accepts only RS256 and
EdDSA access tokens of the configured issuer and audience, and refuses DPoP-bound ones; hooks run
inside the account's transaction; `Hooks.Claims` refuses reserved names; the programmatic API
applies the HTTP routes' rules, events and audit, for a trusted caller (the actor recorded is
`system`); listeners that write to the store (core's audit, plugins' listeners,
`Config.TxListeners`) run inside the transaction that raised the event, while `Config.Listeners`
and the mail run after a `sqlstore.Store.Tx` commits and never after it rolls back (under
`sqlstore.WithTx`, whose commit Polaris does not see, when Polaris's work is done); `DevEnv`
refuses to run without `POLARIS_DEV=1`.

## 3. For a plugin

A plugin outside this module builds on the same public packages the in-tree plugins do.
`testdata/thirdparty/notes` is one, type-checked as a module of its own on every `make qa`
(`TestAThirdPartyPluginBuildsOutsideTheModule`).

| Package | What it is |
|---|---|
| `wiring` | `Plugin` and its optional interfaces, `Graph` and its accessors, the service interfaces, `Hooks`, `User`, `Tool*`, `Ports`, `Caller`, `Authority` |
| `endpoint` | `Endpoint`, `Input`, `Result`, the request-context accessors, the envelope and problem helpers |
| `manifest` | `Route`, `Load`, the input rules |
| `event` | `Event`, `Listener`, `Dispatcher`, `Bus`, the event types and names |
| `token` | `Token`, `Kind`, `KindOf`, `NewPrincipal`, `Delegate`, `Claims`, `Codec` |
| `pipeline` | `BearerResolver` (a plugin's own credential), `Pipeline` and `Options` (`Graph.Pipeline`), `DeniesDelegate`, `DeniesBound` |
| `model`, `schema`, `repository` | the rows (frozen with the database), the table DSL a `SchemaProvider` uses, the core repositories behind `Graph.Repos` |
| `authz` | permission keys, role slugs, `Catalog`, `Authority`, `Caller`, `ErrForbidden` |
| `identity`, `session`, `mfa`, `orgs` | what the services return and refuse with: `identity.LoginResult`, `identity.Err*`, `identity.PasswordPolicy`, `identity.NormalizeEmail`, `session.Info`, `mfa.FactorType`, `mfa.LoginChallenge`, `mfa.FactorView`, `mfa.Err*`, `orgs.Member`, `orgs.Error`, … |
| `security` | `Encrypter` (`Graph.Encrypter`; its payload format is frozen) |

**Interfaces you implement are frozen.** Every exported interface in the module is one a host or
a plugin may implement (`wiring.Plugin` and the optional interfaces beside it, `endpoint.Endpoint`,
`pipeline.BearerResolver`, `mfa.FactorType`, `event.Dispatcher`, the ports of section 2, the
plugins' own ports such as `sso.DomainVerifier`), except the ten named below. None of them gains,
loses or changes a method in v1: your implementation keeps compiling. A new capability arrives as
a **new optional interface**, found by type assertion, the way `security.HashChecker` extends
`PasswordHasher` and `wiring.AccessEraser` extends `Plugin`.

**Interfaces you only call may grow.** `wiring.Identity`, `Sessions`, `MFA`, `Orgs`, `Denylist`,
`Catalog`, `Resolver`, `Gate`, `Principals` and `Pepper` are the core services as a plugin sees
them (`Graph.Identity()`, …). Polaris implements them; they are sealed with an unexported method,
so no other package can, and a minor release may add a method to one. No method is removed or
changed. A test double embeds the interface (`struct{ wiring.Identity }`) and overrides the
methods the test calls. A method a plugin needs is added to its interface.

Likewise additive, in minor releases: new `Graph` accessors, new optional plugin interfaces, new
fields on `wiring.Config`, `wiring.Hooks`, `pipeline.Options` and the other structs, new event
types and manifest rules.

Two rules a plugin follows (decision 68). A path that establishes control of an account's mailbox
calls `Graph.Identity().ProveEmail` and never writes `email_verified_at` itself; a plugin whose
tables hold a way to act as a user (a credential, a key, a grant) implements `wiring.AccessEraser`,
so a mailbox's first proof removes what was there before it. And a route reserved to the account
holder declares no `requires_permissions` and an `effect` other than `read` (or `step_up`): the
pipeline keeps delegated credentials (`pipeline.DeniesDelegate`) and organization-bound SSO
sessions (`pipeline.DeniesBound`, `token.Token.OrganizationBound`) off it. Every path that creates
or deletes an account goes through `Graph.Identity().InsertUser` / `OnUserDeleted`.

## 4. Internal

`internal/…` cannot be imported from outside the module, and changes freely: the concrete
services (`internal/identity`, `session`, `mfa`, `orgs`, `authz`: registration, login, refresh
rotation, the MFA engine, the resolver and the gate), `internal/services` (how core reaches them),
core's endpoints (`internal/httpapi`), the observers (audit, metrics, mail), maintenance jobs, the
route specs and fixtures, the contract-test harness, the SSRF guard, and the access-token verifier
`verify` and `plugins/mcp` share. The in-tree plugins use some of it (their route specs, the
erasure helper, the SSRF guard); none of it is needed to write a plugin.

A host or a plugin that needs something that is internal should report it: the public surface is
missing something, and adding to it is not a breaking change.

## 5. Deprecation

1. The replacement is added in a minor release.
2. The old name gets `// Deprecated: use X.` and a CHANGELOG entry under *Deprecated*; it keeps
   its behaviour, usually by calling the replacement.
3. It stays for the rest of v1. It is removed, at the earliest, in v2.

## 6. How it is kept

- `make apicheck` (CI job "API compatibility", on every pull request) compares every public
  package with the base using `apidiff`. Before `v1.0.0` an incompatible change passes only when
  `docs/decisions.md` gains a line containing "Breaking" in the same change. Once the base is
  `v1.0.0` or later it is refused: the only way through is a module path that moved to `/v2`.
- `TestAThirdPartyPluginBuildsOutsideTheModule` builds a plugin outside the module and checks that
  `internal/` is out of its reach; `TestGraphAccessorsReturnOnlyPublicTypes` keeps every `Graph`
  accessor on a type a plugin can name.
- The contract tests, the known-answer vectors and the upgrade test keep the HTTP, stored-format
  and schema contracts.

## 7. Changes

What changes in each release, breaking changes marked, is in [CHANGELOG.md](CHANGELOG.md); the
reason for each is in [docs/decisions.md](docs/decisions.md).
