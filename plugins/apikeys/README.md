# plugins/apikeys

API keys owned by users and by organizations (`pk_live_…`, `pk_test_…`), each carrying a subset of its
owner's permissions, an optional rate limit of its own, an expiry, rotation with a grace window and
revocation. Presented as `Authorization: Bearer pk_…` or `x-api-key: pk_…`, a key authenticates every
Polaris route and every host route behind `p.Protect` as its owner, delegated: the gate intersects the
owner's current permissions with the key's, so a key never does more than its owner may. Port of
`polaris/api-keys`; works alone, and with `plugins/audit` registered every change is recorded.

## Install

```go
import "github.com/univeros/polaris-go/plugins/apikeys"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), apikeys.New(apikeys.Config{}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_api_key

mux.Handle("/", p.Handler())                                 // serves /api-keys
mux.Handle("GET /api/invoices", p.Protect(h, "invoices.read")) // keys pass, as their owner
// in h: who, _ := polaris.PrincipalFrom(r.Context()); who.Kind == polaris.KindAPIKey, who.KeyID, who.Permissions
```

## Config

Every field is optional; the zero value is upstream's defaults.

| Field | Default | Purpose |
| --- | --- | --- |
| `Environment` | `apikeys.EnvLive` | prefix of keys created without one (`EnvLive` or `EnvTest`) |
| `RotationGrace` | 24 h (`DefaultRotationGrace`) | how long a rotated key's predecessor keeps answering; negative: stops at once |
| `MaxPerOwner` | 50 (`DefaultMaxPerOwner`) | live keys per user or organization |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api-keys` | the caller's live keys, newest first; `organization_id` lists the organization's |
| POST | `/api-keys` | create a key; the secret is in this response only |
| GET | `/api-keys/{id}` | read a key (never the secret) |
| PATCH | `/api-keys/{id}` | change name, permissions, rate limit, expiry, metadata |
| DELETE | `/api-keys/{id}` | revoke at once |
| POST | `/api-keys/{id}/rotate` | new secret; the old one answers until the grace ends |
| POST | `/api-keys/verify` | check a key (`key` in the body) for a proxy that checks keys itself |

Create body: `name` (required, ≤ 80), `permissions` (subset of what the caller holds in the active
organization), `organization_id` (makes it the organization's key; needs `org.update`), `environment`
(`live`/`test`), `rate_limit` (`{"window": seconds, "max": requests}`), `expires_at`, `metadata`.

## Events and permissions

Emits `apikeys.Event` with `apikeys.AuditCreated` (`api_keys.created`), `AuditUpdated`, `AuditRotated`,
`AuditRevoked`; it implements `audit.Auditable` and `Plugin.AuditNames` adds the names to the catalog.
Contributes no permissions; organization keys need core's `org.update`
(`apikeys.OrganizationPermission`). Keys of an erased user or organization, and a departing member's
organization keys, are deleted by the plugin's listeners.

## Problems

`https://polaris.univeros.io/problems/api-keys/not_found` (404), `…/api-keys/forbidden` (403),
`…/api-keys/permission_not_held` (403, a permission the caller does not hold), `…/api-keys/too_many`
(409, `MaxPerOwner` reached), `…/api-keys/invalid_input` (422), `…/api-keys/not_allowed` (403, a
step-up route called with a key).

## Host integration

- In a handler: `who, _ := polaris.PrincipalFrom(r.Context())` — `who.Kind` is
  `polaris.KindAPIKey`, `who.KeyID` the key id, `who.UserID` its owner, `who.Permissions` the
  key's permissions intersected with the owner's; the AMR is `apikeys.AMR`.
- Mint, rotate, revoke from code: `apikeys.Of(g).Keys()` (`Create(ctx, apikeys.CreateParams{…})`
  returns `apikeys.Issued` with `Secret`, shown once; `Rotate`, `Revoke`, `Update`, `Authenticate`).
  Refusals match `apikeys.ErrNotFound`, `ErrTooMany`, `ErrPermissionNotHeld`, … with `errors.Is`.
- A key's own `rate_limit` sets the `X-RateLimit-*` headers over core's.
- `apikeys.Presented(r)` returns the secret a request carries (`x-api-key` first, then the bearer).
- Departure: without the audit plugin the plugin still boots (upstream refused); nothing is recorded.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris-go/plugins/apikeys`.
