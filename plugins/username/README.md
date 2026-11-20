# plugins/username

A user sets a username (`PATCH /username`) and signs in with it, or with the email
(`POST /username/sign-in`), through core's password path: lockout, timing parity, the
email-verification rule, the MFA gate and the login envelope are core's. Usernames are unique
without regard to case (the lowercased form sits under a unique index); the display form is kept as
typed. Port of `polaris/username`.

## Install

```go
import "github.com/univeros/polaris-go/plugins/username"

cfg, err := polaris.FromEnv(db, username.New(username.Config{}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_username
```

## Config

Every field is optional; the zero value is upstream's rules.

| Field | Default | Purpose |
| --- | --- | --- |
| `MinLength`, `MaxLength` | 3, 30 | length bounds in characters |
| `Pattern` | `username.DefaultPattern` (`[A-Za-z0-9_.]+`) | what a username must match whole |
| `Reserved` | `username.DefaultReserved` (admin, root, me, …) | replaces the default list when non-nil; an empty list reserves nothing |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/username/sign-in` | sign in with `username` (or the email) + `password`; core's login envelope |
| PATCH | `/username` | bearer: set or change your `username` (`display_username`: same letters, another case) |

## Events and permissions

Sign-in dispatches core's `user.logged_in`, `user.login_failed`, `user.locked`. No events of its
own; no permissions.

## Problems

`https://polaris.univeros.io/problems/username/invalid_credentials` (401),
`…/username/email_unverified` (403), `…/username/account_disabled` (403),
`…/username/invalid_input` (422, missing username or password), `…/username/invalid` (422, breaks a
rule; `errors` lists them), `…/username/taken` (409).

## Host integration

- `username.Of(p.Graph()).Usernames()` is the service: `Set(ctx, userID, username, display)`,
  `ForUser(ctx, userID)`, `UserID(ctx, username)`, `Violations(username)`. `Set` returns a
  `*username.InvalidError` (matches `username.ErrInvalid`) or `username.ErrTaken`.
- `username.Normalize` is the stored (lowercased) form; case folding is `strings.ToLower`, so it
  differs from upstream's `mb_strtolower` only on non-ASCII.
- Erasing a user leaves its username row (open, as upstream).
- Rate-limit sign-in with `plugins/sentinel`: add `username.SentinelRoutes` to
  `sentinel.Config.Routes` (alongside `sentinel.DefaultRoutes`).

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris-go/plugins/username`.
