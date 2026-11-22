# AGENT.md — polaris-go (Polaris for Go)

Orientation for coding agents working in this repository. Read before editing.

Polaris for Go is an authentication and authorization system for Go services, for users and for AI
agents: everything an auth system needs (accounts, MFA, sessions, organizations and RBAC, every common
sign-in method, API keys, an OAuth 2.1 / OIDC provider, agents, MCP, SSO, SCIM, audit, risk), self-hosted
in the application's database. It started as a port of the PHP `univeros/polaris-core` and is now its
own product (decision #53): it does not follow the PHP version, and the two may differ. The goal is the
best auth library Go has. Decisions are in [`docs/decisions.md`](docs/decisions.md), append only; the
original port plan is history in [`docs/history/port-spec.md`](docs/history/port-spec.md).

## Status

- Complete: core (52 routes), `plugins/{audit,admin,apikeys,oauth,agents,mcp,passwordless,username,
  anonymous,multisession,social,passkey,messaging,sentinel,scim,sso}`, the Go agent SDK `agent/`, the
  CLI (`cli`, `cmd/polaris`), `telemetry/otel`, EdDSA keys and JWKS. Security review (#42, #43),
  database matrix (#45), fuzzing (#42), the Go developer surface (#46–#48), API stability (#51:
  `wiring` hands plugins narrow interfaces; #70: every exported name outside `internal/` is the v1
  API and `make apicheck` guards all of it). Next milestone: `v1.0.0`; what it requires, and what is still open, is
  [`docs/v1.md`](docs/v1.md).
- Integration surface for hosts: `llms.txt` (read it first; `llms_test.go` keeps its snippets
  compiling), `plugins/<id>/README.md`, `examples/`, `polaristest`. A host imports only package
  `polaris` (+ plugin constructors, `store/sqlstore`, `polaristest`); `wiring`, `endpoint`,
  `manifest`, `event`, `token` are the plugin SDK; `API.md` is the v1 promise (everything
  exported outside `internal/`; what must stay free to change goes under `internal/`). Every new path that
  creates or deletes an account goes through `Graph.Identity().InsertUser` / `OnUserDeleted` (the
  host's hooks; `TestEveryAccountIsCreatedThroughInsertUser` guards it).

## The rules

1. **Public.** `univeros/polaris.go` is public (MIT). `main` takes changes through pull requests with
   CI green (`scripts/protect-main.sh`). A security issue is fixed first and published after.
2. **Go first.** Design every change the way the best Go library would: stdlib idioms, small
   interfaces, explicit errors, `context.Context`, `net/http`. Earlier implementations are not a
   reference and not a constraint; nothing is kept only because another implementation does it.
3. **The routes are specs.** `internal/apispec/api/<package>/**.yaml` declares every route (method,
   path, auth, input rules, output, errors, events); it is the router and the OpenAPI source. Change
   a route's spec together with its endpoint.
4. **Behaviour changes are deliberate.** The recorded contract tests in
   `internal/apispec/fixtures/` replay every route's requests and responses. A change to what a
   client sees edits or re-records the affected fixtures in the same PR and logs a decision; never
   to make a test pass by accident. Clients of a released version must keep working, or the break is
   a decision and a release note.
5. **Stored data stays readable.** Existing databases, password hashes, encrypted secrets and issued
   tokens must keep working across releases (`testdata/vectors` holds known-answer vectors; schema
   changes migrate). A format change keeps reading the old one.
6. **Security-critical code is careful** (`security`, `token`, refresh rotation, OTP, OAuth, agents,
   passkey, social, sso): no weakened check, constant-time compares, secrets never logged, fuzz
   targets kept passing. A change here gets a security review note in its decision.
7. **Tests first.** Write the failing test, then the code. `make qa` (gofmt, vet, lint,
   `go test -race -cover`) green before any commit; coverage ≥ 80%.
8. **Integration surface is for agents:** every exported thing has a doc comment and, for main uses, a
   runnable `Example`; errors at startup name their fix; `llms.txt` stays the one page a coding agent
   needs.
9. **Stdlib first.** A new dependency is a decision entry with the reason.
10. **Releases are milestones.** Merge to `main`; tag a version only for a meaningful change (a
    milestone, a breaking change, a security fix), not per pull request.

## How to work a change

1. Branch from `main`.
2. Tests first, then code; keep `make qa` green.
3. Log the decision in `docs/decisions.md` when the change is notable (behaviour, API, dependency,
   security).
4. A notable change also adds a line under `Unreleased` in `CHANGELOG.md`: what changes for a host
   or plugin author (a break marked **Breaking**). At a release, `Unreleased` becomes the
   version's section, and the tag's release workflow publishes it as the release notes.
5. The PR description lists what changed and how each part was verified.

## Commands

```
make qa                              # gofmt check, go vet, lint, go test -race -cover
make apicheck BASE=origin/main       # stable Go API unchanged, or the break recorded (#51)
make vuln                            # govulncheck
make fuzz FUZZTIME=30s               # every fuzz target (CI: weekly, .github/workflows/fuzz.yml)
scripts/test-db-matrix.sh            # the suites on PostgreSQL and MySQL
```
