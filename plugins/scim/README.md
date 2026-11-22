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
_, err = p.Migrate(ctx)    // creates polaris_scim_connection, polaris_scim_resource, polaris_scim_membership_provenance
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

- Erasing a user, by any path, deletes its directory provenance and user mappings
  (`event.UserDeleted`).
- Tokens start with `pst_` (`scim.TokenPrefix`), carry 256 random bits and are stored as a keyed hash.
- `deprovision` is `scim.DeprovisionDeactivate` (default: the user is banned, their sessions end, the
  membership this connection created is removed) or `scim.DeprovisionDelete` (the account is
  anonymised).
- Filters accept what directories send: `attr eq|co|sw "value"` joined by `and`; anything else is
  `invalidFilter`.
- The built-in owner, admin and member roles take members but are never renamed or deleted.
- From code: `scim.Of(g).Connections()` (`Create`, `Rotate`, `Decommission`, `List`, `Delete`) and
  `scim.Of(g).BaseURL(connectionID)`.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/scim`.
