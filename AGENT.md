# AGENT.md — polaris-go (Polaris for Go)

Orientation for coding agents working in this repository. Read before editing.

This repository is the Go port of `univeros/polaris-core` (PHP), without the framework adapters. The
plan, the compatibility contract and the work packages are in [`docs/port/spec.md`](docs/port/spec.md);
decisions taken while porting are in [`docs/port/decisions.md`](docs/port/decisions.md), append only.

## Status

- Core (WP1–WP3) and the agent stack (WP4–WP5) are ported: all 52 core routes (184 fixtures) plus
  `plugins/{audit,admin,apikeys,oauth,agents,mcp}` and the Go agent SDK `agent/`, every upstream
  fixture of those packages replaying. Next: WP6 (passwordless, username, anonymous, multisession,
  social, passkey), WP7 (messaging, sentinel, sso, scim), `cmd/polaris`, WP8.
- Integration surface for hosts: `llms.txt` (read it first), `examples/`, `polaristest`.

## The rules

1. **Private repository.** Never add a public remote, never push to a non-private repo (the
   `scripts/hooks/pre-push` hook enforces it; do not bypass it with `--no-verify`), never paste code,
   paths or names from here into external services. `GOPRIVATE=github.com/univeros/polaris-go`.
2. **Upstream decides observable behaviour, not design.** The PHP code at `../polaris-core` (pinned
   ref in `upstream/REF`) defines what a client or a shared database sees: responses, tables, hash /
   cipher / JWT formats, event names. How the Go code achieves it is designed fresh, the way the best
   Go library would (spec G6, §3.4): read the PHP to learn the behaviour and its edge cases, then
   write Go, not translated PHP. Log notable departures in `decisions.md`. Never modify
   `../polaris-core` from here.
3. **`upstream/` is generated.** Only `scripts/sync-upstream.sh` writes `upstream/api` and
   `upstream/fixtures`.
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
make sync REF=<polaris-core ref>     # refresh upstream/ from ../polaris-core
scripts/e2e-agent-ts.sh               # @polaris-auth/agent walkthrough against a Go server
```
