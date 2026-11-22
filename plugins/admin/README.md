# plugins/admin

The operator API under `/admin`: users, sessions, MFA, organizations, the audit trail, audit drains,
statistics, operator grants and operator API keys (`pak_…`), for a dashboard, a support tool or an
integration. Every operator action is recorded in the audit trail as `admin.<action>`. It
needs `plugins/audit` registered too (any order — `Init` fails without it).

## Install

```go
import (
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
)

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_admin_grant, polaris_admin_key (and audit's tables)

// the first operator (or CLI: polaris admin:grant <email> <role>, polaris admin:key <name> <role>)
_, err = admin.Of(p.Graph()).Grants().Grant(ctx, admin.Grant{UserID: id, Role: admin.RoleOwner})
_, secret, err := admin.Of(p.Graph()).Keys().Create(ctx, admin.Key{Name: "dashboard", Role: admin.RoleViewer})
// secret is shown once: send it as "Authorization: Bearer pak_…"
```

## Config

`admin.Config{}` has no options: the zero value is the full behaviour.

## Operators

A caller is an `admin.Principal`: a user with core's `superadmin` role (owner on the instance, no
grant), a user with a live `admin.Grant` (one per user: role, scope, optional expiry) calling with
their access token, or an `admin.Key` (`pak_`, role, scope, optional IP allowlist and expiry, stored
as a keyed hash). Scope is `admin.ScopeInstance` or one organization id; an organization-scoped
operator acts on that organization only. Roles, each including the ones before it:

| Role | Adds capability |
| --- | --- |
| `RoleViewer` | `Read`: users, sessions, MFA, organizations, audit, stats |
| `RoleSupport` | `Support`: revoke sessions |
| `RoleAdmin` | `Manage` (ban, passwords, MFA, member roles, deletions), `Impersonate` |
| `RoleOwner` | `Own`: grants, operator keys, drains, other plugins' `/admin` routes |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/users`, `/admin/users/{id}` | list (filters `email`, `status`) / read users |
| POST | `/admin/users/{id}/ban`, `/admin/users/{id}/unban` | disable / enable an account (`Manage`) |
| POST | `/admin/users/{id}/password` | set a user's password (`Manage`) |
| DELETE | `/admin/users/{id}` | delete a user (`Manage`) |
| POST | `/admin/users/{id}/impersonate` | access token for the user, no session (`Impersonate`) |
| GET, DELETE | `/admin/users/{id}/sessions` | list / revoke every session (`Support` to revoke) |
| DELETE | `/admin/users/{id}/sessions/{sessionId}` | revoke one session (`Support`) |
| GET, DELETE | `/admin/users/{id}/mfa` | list factors / reset MFA (`Manage` to reset) |
| DELETE | `/admin/users/{id}/mfa/{factorId}` | remove one factor (`Manage`) |
| GET | `/admin/organizations`, `/admin/organizations/{id}` | list / read organizations |
| DELETE | `/admin/organizations/{id}` | delete an organization (`Manage`) |
| PATCH | `/admin/organizations/{id}/members/{userId}/roles` | set a member's roles (`Manage`) |
| GET, POST | `/admin/organizations/{id}/drains` | list / create audit drains (`Own` to create) |
| DELETE | `/admin/organizations/{id}/drains/{drainId}` | delete a drain (`Own`) |
| POST | `/admin/organizations/{id}/drains/{drainId}/test` | send a test delivery (`Own`) |
| GET | `/admin/audit` | query the audit trail |
| GET | `/admin/stats` | instance statistics |
| GET, POST | `/admin/keys` | list / create operator API keys (`Own`) |
| DELETE | `/admin/keys/{id}` | delete a key, effective at once (`Own`) |
| GET, POST | `/admin/grants` | list / create operator grants (`Own`) |
| DELETE | `/admin/grants/{id}` | revoke a grant (`Own`) |

Lists are cursor-paginated: `cursor` (the previous page's `next_cursor`), `limit` (default
`admin.DefaultLimit`, at most `admin.MaxLimit`).

## Events and permissions

Records one audit name per action (`admin.AuditUserBanned` … `admin.AuditGrantDeleted`, added to the
catalog by `Plugin.AuditNames`); routes that change core state also emit core's event
(`user.disabled`, `user.deleted`, `org.deleted`, `mfa.factor_removed`, …). Contributes no core
permissions: access is the role matrix above, not RBAC.

## Problems

`https://polaris.univeros.io/problems/admin/unauthorized` (401, no operator, lapsed grant or key),
`…/admin/forbidden` (403, role or scope too small), `…/admin/impersonation_denied` (403, an
impersonation token), `…/admin/not_found` (404), `…/admin/conflict` (409),
`…/admin/invalid_input` (422, `errors` lists the fields), `…/audit/invalid_query` (422, `/admin/audit`).

## Host integration

- Erasing a user deletes its operator grants (`event.UserDeleted`).
- An impersonation token carries `amr ["impersonation"]` and the `admin.ClaimImpersonatedBy` /
  `admin.ClaimImpersonatorType` claims; it cannot be refreshed and is never an operator. A superadmin
  cannot be impersonated.
- Your own admin route: declare it with tag `admin.Tag` and `auth: public`, then start the endpoint
  with `op, res, ok := admin.Authorize(ctx, admin.Own, orgID)` and record with
  `admin.Of(g).Record(ctx, name, op, subjectID, orgID, data)`.
- Outside `/admin`: `Plugin.OperatorOf(r)`, `Plugin.IsOperator(ctx, credential)`,
  `Plugin.Resolve(ctx, bearer, ip)`. A plugin that does not import this package type-asserts
  `g.Plugin("admin")` to an interface with `AuthorizeOperator` / `OperatorID`.
- An operator's access token is checked against the denylist when enabled;
  a drain's `filter` must be a JSON list; dates are ISO 8601 only.
- One grant per user is enforced by the database (`polaris_admin_grant_user_unique` on `user_id`):
  a grant replaces the user's previous one, and of two concurrent first grants the second is
  applied as that replacement. A database from v0.4.1 or earlier may already hold two grants for one
  user (only that race made them); `Migrate` then stops with an error naming `polaris_admin_grant`
  and `user_id`. List them with
  `SELECT user_id, id, role, scope FROM polaris_admin_grant WHERE user_id IN (SELECT user_id FROM polaris_admin_grant GROUP BY user_id HAVING COUNT(*) > 1)`,
  revoke the grants you do not want (`DELETE /admin/grants/{id}` or `Grants().Revoke(ctx, id)`)
  and run `Migrate` again.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/admin`.
