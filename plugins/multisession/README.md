# plugins/multisession

Several accounts signed in on one device (one browser): list them, switch between them without
signing in again, sign one out, and read the device's last sign-in method so the client can
pre-select its button. Every Polaris response that opens or refreshes a session (any sign-in
method, a refresh, a switch) is recorded against a device id the server mints and answers in the
`X-Polaris-Device` header and the HttpOnly cookie `polaris_ms_device`. Port of
`polaris/multi-session` (plugin id `multi-session`).

## Install

```go
import "github.com/univeros/polaris-go/plugins/multisession"

cfg, err := polaris.FromEnv(db, multisession.New(multisession.Config{}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_multi_session_device
```

## Config

| Field | Default | Purpose |
| --- | --- | --- |
| `DisableCookie` | off (cookie set) | stop setting `polaris_ms_device`; the device travels in `X-Polaris-Device` only |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/multi-session/list` | bearer: the device's live sessions, most recent first, each with its account, method and whether it is the caller's |
| POST | `/multi-session/switch` | bearer: open a session for `session_id` (another account on the device) with the old one's amr, mfa, auth_time and organization; core's login envelope |
| DELETE | `/multi-session/{sessionId}` | bearer: sign one account out of this device |
| GET | `/multi-session/last-method` | public: `{"last_method": …}` of the device's latest sign-in (`null` for an unknown device) |

The bearer routes require the caller's own session to be on the device.

## Events and permissions

No events of its own; no permissions.

## Problems

`https://polaris.univeros.io/problems/multi-session/device_unknown` (403, no device or the
caller's session is not on it), `…/multi-session/session_not_found` (404),
`…/multi-session/invalid_input` (422, missing `session_id`).

## Host integration

- The client sends the device back in the header `multisession.Header` or the cookie
  `multisession.Cookie`. Only server-minted ids are accepted, and a sign-in joining a device that
  has accounts rotates its id (a planted id never names the victim's device).
- The tracking runs as plugin middleware on every Polaris route (`Plugin.Middleware`); nothing to
  wire. A failed device write is logged and the sign-in still answers, without the device header.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris-go/plugins/multisession`.
