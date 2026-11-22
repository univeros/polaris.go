# Contributing to Polaris for Go

Thanks for helping. Polaris for Go is an authentication library, so the bar is "would we trust this
with our own users". [AGENT.md](AGENT.md) holds the rules every change follows (it is written for
coding agents, and applies to people the same way); this page is the short version for humans.

Found a vulnerability? Do not open an issue: follow [SECURITY.md](SECURITY.md).

## The workflow

1. **Branch from `main`.** `main` takes changes only through pull requests with CI green.
2. **Tests first.** Write the failing test, then the code. Coverage stays at or above 80%.
3. **`make qa` green** before every commit: gofmt, `go vet`, golangci-lint, `go test -race -cover`.
   The tools are fetched with `go run` at pinned versions; nothing to install but Go (the version
   in `go.mod`).
4. **Record notable decisions.** A change to behaviour, the public API, a dependency or
   security-critical code appends a numbered entry to [docs/decisions.md](docs/decisions.md)
   (append only; never edit an old entry). A breaking change says "Breaking" in its entry.
5. **Add a line to [CHANGELOG.md](CHANGELOG.md)** under `Unreleased` for anything a host developer
   would notice: what changes for them, not the internal story.
6. **Open a pull request** whose description lists what changed and how you verified each part
   (the test names, the commands you ran).

Some rules matter more here than in most projects (AGENT.md has all ten):

- **Routes are specs.** Every HTTP route is declared in `internal/apispec/api/<package>/*.yaml`
  (method, path, auth, input rules, output, errors, events). Change a route's spec together with
  its endpoint.
- **Behaviour changes are deliberate.** The contract fixtures in `internal/apispec/fixtures/`
  replay every route's recorded requests and responses. If a change alters what a client sees,
  edit or re-record the affected fixtures in the same PR and log a decision.
- **Stored data stays readable.** Existing databases, password hashes, ciphertexts and issued tokens
  keep working across releases; `testdata/vectors` holds known-answer vectors that must keep
  passing. A format change keeps reading the old format; a schema change ships its migration.
- **Security-critical code** (`security`, `token`, sessions and refresh rotation, OTP, and the oauth,
  agents, passkey, social and sso plugins): no weakened check, constant-time compares, secrets never
  logged, fuzz targets kept passing. Its decision entry carries a security review note.
- **Stdlib first.** A new dependency needs a decision entry saying why.

## Commands

```
make qa                              # gofmt check, go vet, lint, go test -race -cover
make apicheck BASE=origin/main       # the stable Go API is unchanged, or the break is recorded
make vuln                            # govulncheck: reachable vulnerabilities
make fuzz                            # every fuzz target for FUZZTIME (default 10s) each
make fuzz FUZZ=FuzzCBOR FUZZTIME=5m  # one target, longer
scripts/test-db-matrix.sh            # the suites on PostgreSQL 17 and MySQL 8.4
```

### The database matrix

`make qa` runs on memory and SQLite. `scripts/test-db-matrix.sh` also runs the suites on
PostgreSQL 17 and MySQL 8.4: with Docker available it starts both in throwaway containers, runs
`go test -race` once per database, and removes them. Pass package patterns to narrow it
(`scripts/test-db-matrix.sh ./orgs/...`), `KEEP=1` to keep the containers, or set
`POLARIS_TEST_PG_DSN` and `POLARIS_TEST_MYSQL_DSN` to use servers you already run. CI runs it on
every pull request; run it locally when you touch SQL, the schema or a repository.

### Fuzzing

Each `Fuzz*` function's seed corpus runs as an ordinary test in `make qa`. `make fuzz` (and the
weekly `fuzz` workflow) actually fuzzes. A failing input lands in the package's
`testdata/fuzz/<Target>/`: commit it with the fix, so it stays a regression test.

## API stability

[API.md](API.md) says what a host or a plugin may rely on in v0.x: the host surface (package
`polaris`, plugin constructors, `store/sqlstore`, `polaristest`, ...), the plugin SDK (`wiring`,
`endpoint`, `manifest`, `event`, `token`) and the types they name. `scripts/api-stable.txt` is the
machine-readable list. `make apicheck` (a CI job on every pull request) fails on an incompatible
change to a stable name unless `docs/decisions.md` gains an entry with a "Breaking" line. Adding a
field, a method, an option or a constant is not breaking. Anything not listed may change in a minor
release.

New exported names need a doc comment, and the main uses a runnable `Example`. If you change what a
host writes, keep [llms.txt](llms.txt) current: `llms_test.go` compiles its snippets.

## Adding a plugin

A plugin is a package under `plugins/<id>` with a `New(Config)` constructor whose result
implements `wiring.Plugin` (`ID() string`). It adds what it needs by implementing the optional interfaces in
[`wiring/plugin.go`](wiring/plugin.go): `SchemaProvider` (tables, declared with package `schema`),
`ManifestProvider` (its route specs as an `fs.FS`), `EndpointProvider` (an `endpoint.Endpoint` per
route), `Initializer`, `PermissionProvider`, `ListenerProvider` (`event` listeners),
`MiddlewareProvider`, `BearerResolverProvider`, `MFAFactorTypeProvider`, `PortsProvider`. It
reaches the core services through the narrow interfaces `wiring.Graph` hands it, never the concrete
services.

[`plugins/username`](plugins/username) is the small model to copy: `username.go` (config, schema,
manifest, endpoints), `http.go` (the endpoints), its specs in `internal/apispec/api/username/`, a
functional test replaying its fixtures, an `Example`, and a `README.md` a host can follow. Every path
that creates or deletes an account goes through `Graph.Identity().InsertUser` / `OnUserDeleted`
(`TestEveryAccountIsCreatedThroughInsertUser` checks it).

A plugin outside this repository uses the same interfaces and serves its own specs from its own
`fs.FS`. If it needs a core method the narrow interfaces do not have, open an issue: the method is
added to the interface.
