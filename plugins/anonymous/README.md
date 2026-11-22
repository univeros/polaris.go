# plugins/anonymous

Guest sessions: a visitor gets a session before having an account (`POST /anonymous/sign-in`
creates a core user with the placeholder email `<id>@anonymous.invalid`, no password, no
organization, amr `["anonymous"]`). Once they sign up or in by any method, `POST /anonymous/convert`
records the conversion, runs your `OnConvert` hook to move what you kept under the guest's id,
disables the guest and ends its sessions, all in one transaction; its id stays. Guests nobody
converted are pruned.

Ending the sessions revokes the guest's refresh tokens at once. Its access token is refused at
once only with the denylist on (`AUTH_ACCESS_TOKEN_DENYLIST=true`); without it, the access token
is stateless and keeps answering until it expires (`AUTH_ACCESS_TOKEN_TTL`, 15 minutes by
default): `/auth/me` shows `"status": "disabled"` and the account holds no permission.

## Install

```go
import "github.com/univeros/polaris.go/plugins/anonymous"

guests := anonymous.New(anonymous.Config{
	OnConvert: func(ctx context.Context, guestID, userID string) error {
		return carts.Reassign(ctx, guestID, userID) // your data
	},
})
cfg, err := polaris.FromEnv(db, guests)
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_anonymous
```

## Config

Every field is optional; the zero value is the defaults.

| Field | Default | Purpose |
| --- | --- | --- |
| `OnConvert` | nil (nothing to move) | moves the host's data from the guest to the account; runs inside the conversion's transaction (write through `ctx`, as in `Hooks.OnUserCreated`), so an error converts nothing and the guest can retry. A write outside that transaction is not undone if a later step fails, and the retry runs the hook again: keep such a hook idempotent |
| `PruneAfter` | 30 days (`anonymous.DefaultPruneAfter`) | age past which `Prune` deletes an unconverted guest; at least a day |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/anonymous/sign-in` | create a guest and answer core's login envelope (201) |
| POST | `/anonymous/convert` | guest's bearer + `access_token` (a live session of the real account): convert the guest |

## Events and permissions

Sign-in dispatches core's `user.logged_in`. `Prune` dispatches `event.UserDeleted` (actor
`anonymous.ActorSystem`) for each deleted guest. No permissions.

## Problems

`https://polaris.univeros.io/problems/anonymous/invalid_input` (422, missing `access_token`),
`…/anonymous/token_invalid` (422, not a live session of another, real account),
`…/anonymous/not_a_guest` (403). An `OnConvert` error answers 500. Go: `anonymous.ErrNotAGuest`,
`anonymous.ErrTokenInvalid`.

## Host integration

- Prune from a scheduled job: `guests.Prune(ctx)` (CLI `polaris anonymous:prune`). It deletes the
  guest's core rows in one transaction per guest; drop your own data in an `event.UserDeleted`
  listener.
- `anonymous.Of(p.Graph()).Guests()` is the service: `SignIn`, `Convert`, `IsGuest`, `Prune`.
- Two concurrent conversions run `OnConvert` once. A conversion that fails at any step (the hook,
  disabling the guest, ending its sessions) answers 500 and leaves the guest as it was: its
  sessions live, and a retry converts it. A guest is never reported converted with live sessions.
- Erasing a user deletes its guest row (`event.UserDeleted`).
- Guard sign-in with `plugins/sentinel`: add `anonymous.SentinelRoutes` (judged as a sign-up) to
  `sentinel.Config.Routes` (alongside `sentinel.DefaultRoutes`).

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/anonymous`.
