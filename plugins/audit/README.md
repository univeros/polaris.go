# plugins/audit

Every Polaris event becomes a catalogued, redacted, append-only row in `polaris_audit_event`, queryable
per user and per organization, streamed to your sinks and to each organization's drains, pruned by a
retention policy and, optionally, chained by SHA-256 for tamper evidence. Port of `polaris/audit`;
required by `plugins/admin`.

## Install

```go
import "github.com/univeros/polaris.go/plugins/audit"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_audit_event, polaris_audit_drain, polaris_audit_activity
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
| `HTTPClient` | nil | enables delivery to the organizations' drains |
| `WebhookAttempts` | 3 | attempts per drain delivery |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/audit/me` | events where the caller is the actor or the subject |
| GET | `/audit/organization/{id}` | the active organization's events (`audit.read`) |
| GET | `/audit/types` | the catalog of event names |

Filters: `names` (comma-separated), `from`, `to` (ISO-8601), `cursor` (the previous page's
`next_cursor`), `limit` (default `audit.DefaultLimit`, 200 at most). Newest first.

## Events and permissions

Records every core event and every plugin event in the catalog (`GET /audit/types`,
`Plugin.Catalog()`); a plugin adds names through `audit.NameProvider`. Emits no events of its own.
Uses core's `audit.read`.

## Problems

`https://polaris.univeros.io/problems/audit/forbidden` (403, not your active organization),
`…/audit/invalid_query` (422, bad filter).

## Host integration

- `audit.Of(g).Record(ctx, audit.Event{…})` writes your own events; dispatching an
  event that implements `audit.Auditable` does the same.
- Values wrapped in `audit.Sensitive` and keys like `password|secret|token|code|otp` are redacted
  (`audit.Redact`) before any sink sees them. A failing sink is logged, never fails the operation.
- `Plugin.Prune(ctx)` from a scheduled job (CLI `polaris audit:prune`); `Plugin.Verify(ctx)` walks
  the hash chain (`polaris audit:verify`).
- Organizations' drains are managed through `Plugin.Drains()` and the `/admin` routes of
  `plugins/admin`.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/audit`.
