# plugins/scim

A SCIM 2.0 server (RFC 7643, 7644) per organization. A directory (Okta, Entra ID, Google,
JumpCloud, …) provisions the organization's members as Users and its roles as Groups with a
connection token the organization creates and rotates itself; operators see every connection. A
SCIM User is a Polaris user with a membership in the organization (its `id` is the Polaris user id);
a Group is one of the organization's roles. `plugins/audit` and
`plugins/admin` are optional.

## Install

```go
import "github.com/univeros/polaris.go/plugins/scim"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}), scim.New(scim.Config{}))
p, err := polaris.New(cfg) // a relative BaseURL fails here
_, err = p.Migrate(ctx)    // creates polaris_scim_connection, polaris_scim_resource, polaris_scim_membership_provenance, polaris_scim_user_name
```

## Config

| Field | Default | Purpose |
| --- | --- | --- |
| `BaseURL` | `Auth.Issuer` + `Config.PathPrefix` | absolute http(s) URL where Polaris is mounted, prefix included (`"https://app.example.com/auth"`); every `meta.location` and a connection's `scim_base_url` derive from it |

## Routes

Organization admins (bearer, `org.update` in the active organization):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/orgs/{id}/scim/connections` | the organization's connections |
| POST | `/orgs/{id}/scim/connections` | create `{name, deprovision?, sso_provider_id?}`; answers the token (shown once) and `scim_base_url` |
| GET | `/orgs/{id}/scim/connections/{connectionId}` | read a connection |
| POST | `/orgs/{id}/scim/connections/{connectionId}/rotate` | new token; the previous one stops at once |
| DELETE | `/orgs/{id}/scim/connections/{connectionId}` | decommission (the users stay) |

The directory (`Authorization: Bearer <connection token>`, `application/scim+json`), under
`/scim/v2/{connectionId}`:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes` | discovery |
| GET, POST | `/Users` | list (filter) / create |
| GET, PUT, PATCH, DELETE | `/Users/{id}` | read / replace / patch / deprovision |
| GET, POST | `/Groups` | list (filter) / create |
| GET, PUT, PATCH, DELETE | `/Groups/{id}` | read / replace / patch / delete |

Operators (admin plugin principals): `GET /admin/scim/connections` (admin `read`; an
organization-scoped operator sees their organization's), `DELETE /admin/scim/connections/{id}`
(admin `own`). Without the admin plugin these answer 401.

## Events and permissions

`scim.connection_created`, `scim.connection_rotated`, `scim.connection_decommissioned`,
`scim.user_created`, `scim.user_updated`, `scim.user_deactivated`, `scim.user_reactivated`,
`scim.user_deleted`, `scim.group_created`, `scim.group_updated`, `scim.group_deleted`,
`scim.request_rejected` (`scim.Audit*` constants, each a `scim.Event`). A directory's request has the
connection as its actor. Without audit nothing is recorded, but the events still fire. Uses core's
`org.update`.

## Problems

Organization routes: `https://polaris.univeros.io/problems/scim/forbidden` (403, not your active
organization), `…/scim/not_found` (404), `…/scim/invalid_input` (422), `…/scim/conflict` (409, the
connection is decommissioned). SCIM routes answer SCIM error documents (`scim.ErrorSchema`: status,
detail, `scimType` such as `invalidFilter`, `invalidValue`, `uniqueness`, `mutability`), which also
carry `error` and `message`. Admin routes answer the admin plugin's problems.

## Host integration

- Erasing a user, by any path, deletes its directory provenance, user mappings and stored name
  parts inside the erasure's transaction (`wiring.UserEraser`).
- Tokens start with `pst_` (`scim.TokenPrefix`), carry 256 random bits and are stored as a keyed hash.
- `deprovision` is `scim.DeprovisionDeactivate` (default: the user is banned, their sessions end, the
  membership this connection created is removed) or `scim.DeprovisionDelete` (the account is
  anonymised).
- Filters accept what directories send: `attr eq|co|sw "value"` joined by `and`; anything else is
  `invalidFilter`. The value is a JSON string (RFC 7644 §3.4.2.2): JSON escapes are decoded, an
  unknown escape, a raw control character or a NUL is `invalidFilter`.
- Input follows RFC 7643/7644 strictly; a non-conforming value is a 400 `invalidValue`:
  `active` is a JSON boolean or the string `"true"`/`"false"` in any case (`"on"`, `"yes"`,
  `"1"`, `1` are refused, in POST, PUT and PATCH);
  `members` is a list of `{"value": id}` objects (not bare ids, not `{}`); `startIndex` and `count`
  are integers (decimal digits, an optional sign; below 1 reads as 1, a negative count as 0, at most
  `scim.MaxCount`); a PATCH operation without a `path` carries an object. The admin listing's `limit`
  is a positive integer (422 otherwise).
  The strings are accepted for Microsoft Entra ID, which sends `active` as `"True"`/`"False"` in
  PATCH (with `"op": "Replace"`; op names are matched in any case) unless the enterprise
  application opts into its SCIM 2.0 compliant behaviour with `?aadOptscim062020` on the Tenant
  URL. Both work.
- Timestamps (`meta.created`, `meta.lastModified`, a connection's `created_at`, `last_sync_at`,
  `decommissioned_at`) are RFC 3339 in UTC with `Z`.
- The built-in owner, admin and member roles take members but are never renamed or deleted.
- A User's `displayName` and `name.formatted` are the account's display name; `name.givenName` and
  `name.familyName` are kept per connection as the directory sent them (for accounts it manages),
  and answered back so the directory sees no difference.
- From code: `scim.Of(g).Connections()` (`Create`, `Rotate`, `Decommission`, `List`, `Delete`) and
  `scim.Of(g).BaseURL(connectionID)`.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/scim`.
