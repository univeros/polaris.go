# Benchmarks

What the hot paths cost, measured end to end through the real code: the HTTP pipeline, SQLite in a
temporary file (polaristest's database: foreign keys on, SQLite's default journal and
`synchronous`), RS256 session tokens unless stated. Numbers are the median of three runs; they move with the machine and the database, so read
them as orders of magnitude and as a baseline for regressions, not as a promise.

```
make bench                                   # every Benchmark* in the module
go test -run '^$' -bench . -benchmem -count 3 ./token/ ./internal/httpapi/ ./plugins/apikeys/ ./plugins/agents/
```

Machine: Apple M1 Pro (10 cores), 16 GiB, macOS 26.6.2, Go 1.26.11 (darwin/arm64), 2026-11-20.

| Benchmark | What it measures | ns/op | B/op | allocs/op |
|---|---|---:|---:|---:|
| `token` `BenchmarkParse/RS256` | access-token verification: signature, iss, aud, exp/nbf, typ | 37 400 | 6 544 | 86 |
| `token` `BenchmarkParse/EdDSA` | the same with Ed25519 keys | 51 900 | 4 976 | 77 |
| `internal/httpapi` `BenchmarkLogin/argon2=production` | `POST /auth/login`, `security.Argon2id{}` (64 MiB, t=4, p=1: PHP's defaults) | 195 000 000 | 67 207 776 | 860 |
| `internal/httpapi` `BenchmarkLogin/argon2=cheap` | the same with the test suite's Argon2id (1 MiB, t=1, p=1) | 3 600 000 | 1 140 553 | 813 |
| `internal/httpapi` `BenchmarkRefresh` | `POST /auth/token/refresh`, single-use rotation (consume, insert, sign) | 2 590 000 | 85 929 | 1 109 |
| `plugins/apikeys` `BenchmarkProtect/jwt` | a host route behind `Protect`, session access token | 122 000 | 28 081 | 376 |
| `plugins/apikeys` `BenchmarkProtect/api_key` | the same with an API key (hashed-secret lookup, delegated principal) | 124 000 | 36 298 | 597 |
| `plugins/agents` `BenchmarkExecute/delegated_token` | `POST /agents/execute` with an RFC 8693 exchanged token: grant, budget, schema, handler, hash-chained receipt, audit, one transaction | 3 160 000 | 152 239 | 2 304 |
| `plugins/agents` `BenchmarkExecute/private_key_jwt` | the same with a request JWT signed per call (EdDSA, htm/htu/body_hash, unique jti; signing included) | 3 040 000 | 135 408 | 2 088 |

Reading them:

- **Login is Argon2id.** With production parameters the hash is ~98% of the time and 64 MiB of
  memory per concurrent login; size the login rate limit and the instance memory for it
  (`Auth.RateLimits.Login`). The cheap parameters show the rest of the path costs ~3.6 ms.
- **Writes are the database.** Login, refresh and agent execution each commit a transaction; on
  SQLite in a file that commit dominates (milliseconds). PostgreSQL/MySQL on a network move the
  number by their round trips, not by Polaris's CPU.
- **Reads are cheap.** Verifying a token is ~40–50 µs; `Protect` adds the denylist and the
  principal's authority from the database (~120 µs on SQLite).
