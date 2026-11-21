# AGENT.md — polaris-go (Polaris for Go)

Orientation for coding agents working in this repository. Read before editing.

This repository is the Go port of `univeros/polaris-core` (PHP), without the framework adapters. The
plan, the compatibility contract and the work packages are in [`docs/port/spec.md`](docs/port/spec.md);
decisions taken while porting are in [`docs/port/decisions.md`](docs/port/decisions.md), append only.

## Status

- Ported, every upstream fixture of each package replaying against polaris-core v0.12.2: core (WP1–WP3,
  all 52 routes); `plugins/{audit,admin,apikeys,oauth,agents,mcp}` and the Go agent SDK `agent/`
  (WP4–WP5); `plugins/{passwordless,username,anonymous,multisession,social,passkey}` (WP6);
  `plugins/{messaging,sentinel,scim,sso}` (WP7); the CLI (`cli`, `cmd/polaris`); EdDSA keys and JWKS.
  WP8 done: security review (#42, #43), database matrix (#45), fuzzing (#42), re-sync (#50). WP9
  done: the Go developer surface (#46–#48). Departures are in `docs/port/decisions.md`.
- API stability done (#51): `wiring` hands plugins narrow interfaces; `scripts/api-stable.txt` and
  `make apicheck` guard the stable surface (API.md). Left: `v1.0.0`.
- Integration surface for hosts: `llms.txt` (read it first; `llms_test.go` keeps its snippets
  compiling), `plugins/<id>/README.md`, `examples/`, `polaristest`. A host imports only package
  `polaris` (+ plugin constructors, `store/sqlstore`, `polaristest`); `wiring`, `endpoint`,
  `manifest`, `event`, `token` are the plugin SDK; `API.md` says what is stable. Every new path that
  creates or deletes an account goes through `Graph.Identity().InsertUser` / `OnUserDeleted` (the
  host's hooks; `TestEveryAccountIsCreatedThroughInsertUser` guards it).

## The rules

1. **Public, like every Polaris repository.** `univeros/polaris.go` is public (MIT). The upstream
   vulnerabilities it found (decisions #38, #39, #43) are fixed in polaris-core 0.12.1 and disclosed
   (decision #50). A security issue found later follows the same rule: fix upstream (or here) first,
   publish details after. `main` takes changes through pull requests with CI green
   (`scripts/protect-main.sh`).
2. **Upstream decides observable behaviour, not design.** The PHP code at `../polaris-core` (pinned
   ref in `internal/upstream/REF`) defines what a client or a shared database sees: responses, tables, hash /
   cipher / JWT formats, event names. How the Go code achieves it is designed fresh, the way the best
   Go library would (spec G6, §3.4): read the PHP to learn the behaviour and its edge cases, then
   write Go, not translated PHP. Log notable departures in `decisions.md`. Never modify
   `../polaris-core` from here.
3. **`internal/upstream/` is generated.** Only `scripts/sync-upstream.sh` writes `internal/upstream/api` and
   `internal/upstream/fixtures`.
4. **The wire, the database and the secrets are frozen** (spec §3): same responses as the fixtures,
   same tables, same hash/cipher/JWT formats. The Go API is free; the behaviour is not.
5. **Security-critical semantics are kept exactly** (`security`, `token`, refresh rotation, OTP,
   OAuth, agents): same formats, same checks, same failure modes, no weakened check. Constant-time
   compares; secrets never logged. The code shape is still Go's.
6. **Tests first.** Port the PHP test, port the functional test so its upstream fixture replays, then
   implement. `make qa` (gofmt, vet, `go test -race -cover`) green before any commit; coverage ≥ 80%.
7. **Integration surface is for agents** (spec §4.6): every exported thing has a doc comment and,
   for main uses, a runnable `Example`; errors at startup name their fix.
8. **Stdlib first; dependencies only from spec §5.** A new one is a decision entry.
9. **No feature work beyond upstream.** New behaviour goes to polaris-core first, then is ported.

## How to work a work package

1. Read spec §8 for the WP's scope and acceptance criteria.
2. Branch `port/wpN` from `main`.
3. Port tests, then code; keep `make qa` green.
4. Log decisions in `docs/port/decisions.md`.
5. PR description lists each acceptance criterion and how it was verified.

## Commands

```
make qa                              # gofmt check, go vet, go test -race -cover
make sync REF=<polaris-core ref>     # refresh internal/upstream/ from ../polaris-core
make apicheck BASE=origin/main       # stable Go API unchanged, or the break recorded (#51)
scripts/e2e-agent-ts.sh               # @polaris-auth/agent walkthrough against a Go server
```
