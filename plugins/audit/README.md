# plugins/audit

Every Polaris event becomes a catalogued, redacted, append-only row in `polaris_audit_event`, queryable
per user and per organization, streamed to your sinks and to each organization's drains, pruned by a
retention policy and, optionally, chained by SHA-256 for tamper evidence.
Required by `plugins/admin`.

## Install

```go
import "github.com/univeros/polaris.go/plugins/audit"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_audit_event, _drain, _activity and _chain
```

## Config

Every field is optional; the zero value keeps 90 days, no chain, the database sink only.

| Field | Default | Purpose |
| --- | --- | --- |
| `Retention` | `P90D` for every name | `audit.Retention{Default: "P90D", Names: map[string]string{audit.UserDeleted: "P7Y"}}` |
| `HashChain` | off | link each row to the previous by SHA-256; `Plugin.Verify` checks it |
| `Sinks` | none | beside the database: `audit.LogSink`, `audit.FileSink`, `audit.WebhookSink`, yours (`audit.SinkFunc`) |
| `Names` | none | your own event names (`name => description`); unknown names are rejected |
| `ActivityInterval` | 5 min | how often a user's `last_active_at` is written |
| `Drains` | off | deliver the organizations' drains, to public addresses only |
| `HTTPClient` | nil | your client for drain delivery instead of the guarded default; setting it turns `Drains` on, and what it may reach is then yours to bound |
| `WebhookAttempts` | 3 | attempts per drain delivery |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/audit/me` | events where the caller is the actor or the subject |
| GET | `/audit/organization/{id}` | the active organization's events (`audit.read`) |
| GET | `/audit/types` | the catalog of event names |

Filters: `names` (comma-separated), `from`, `to` (ISO-8601), `cursor` (the previous page's
`next_cursor`), `limit` (a positive integer in digits only, default `audit.DefaultLimit`, 200 at
most). Newest first. Times are RFC 3339 in UTC (`2026-09-11T10:00:00Z`).

## Events and permissions

Records every core event and every plugin event in the catalog (`GET /audit/types`,
`Plugin.Catalog()`); a plugin adds names through `audit.NameProvider`. Emits no events of its own.
Uses core's `audit.read`.

## Problems

`https://polaris.univeros.io/problems/audit/forbidden` (403, not your active organization),
`…/audit/invalid_query` (422, bad filter).

## Host integration

- Erasing a user deletes its activity row inside the erasure's transaction (`wiring.UserEraser`);
  its events stay, the trail outlives the account.
- A row written while serving an operator's impersonation token (`plugins/admin`) carries
  `impersonated_by` (the operator's id) in its `data`, beside the user as actor.
- `audit.Of(g).Record(ctx, audit.Event{…})` writes your own events; dispatching an
  event that implements `audit.Auditable` does the same.
- Values wrapped in `audit.Sensitive` and keys like `password|secret|token|code|otp` are redacted
  (`audit.Redact`) before any sink sees them. A failing sink is logged, never fails the operation.
- `audit.FileSink` lines and `audit.WebhookSink` bodies are standard JSON (UTF-8, `/` unescaped,
  an empty object as `{}`, times in `Z`). The hash chain keeps its own canonical form: the stored
  `data` text and the hashed bytes (times as `+00:00`) are what earlier releases wrote, so chains
  already written keep verifying.
- `Plugin.Prune(ctx)` from a scheduled job (CLI `polaris audit:prune`); `Plugin.Verify(ctx)` walks
  the hash chain (`polaris audit:verify`).
- With `HashChain` on, every replica appends to one chain: each write first takes the lock row in
  `polaris_audit_chain` (a row lock on PostgreSQL and MySQL, the write lock on SQLite), so writers in
  separate processes append one at a time and never fork it, also inside your own transaction
  (`sqlstore.WithTx`), where the lock is held until you commit. Run `Migrate` after upgrading to create
  that table; until then chained writes fail with an error naming it. SQLite needs a busy timeout
  (`_pragma=busy_timeout(5000)`) for concurrent writers to wait rather than fail.
- Organizations' drains are managed through `Plugin.Drains()` and the `/admin` routes of
  `plugins/admin`. An organization's owner chooses the endpoint, so delivery is guarded: with
  `Drains: true` the client connects to public unicast addresses only, decided after DNS resolution
  (a name that resolves to a private, loopback, link-local or metadata address is refused), and
  redirects are never followed, whichever client is used. With your own `HTTPClient` the address
  guard is yours (an egress proxy, a dialer `Control`).
- A drain never holds the writer: a batch is delivered after the transaction that recorded it
  commits (never when it rolls back), on its own goroutine, within 15 s in all, at most 32 batches
  in flight (one more is dropped and logged). Under `sqlstore.WithTx`, whose commit Polaris does not
  see, it starts at once. Order between batches is not guaranteed; `occurred_at` and `id` order
  them. Call `Plugin.WaitDrains(ctx)` before the process exits.
- A drain's `last_error` is a category the organization's owner may read: `refused` (not a public
  address), `timeout`, `unreachable`, or `HTTP <status>`. The transport's own error is in your log
  ("Audit drain failed"), never in the row.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/audit`.
