# plugins/sentinel

A local risk engine in front of sign-up, sign-in, password reset and code sends. Signals score each
attempt (velocity, credential stuffing, IP rules, devices, disposable domains and, with a provider,
captcha, impossible travel and breached passwords); a policy allows, challenges or blocks. Observe
mode (the default) records without enforcing, so an instance tunes on its own decisions first. Port
of `polaris/sentinel`; requires `plugins/admin` (its routes are admin routes; the one
plugin-to-plugin import), which in turn requires `plugins/audit`.

## Install

```go
import "github.com/univeros/polaris.go/plugins/sentinel"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}),
	sentinel.New(sentinel.Config{
		Mode:    sentinel.Enforce, // default sentinel.Observe ("observe")
		Captcha: sentinel.Turnstile(os.Getenv("TURNSTILE_SECRET")),
	}))
p, err := polaris.New(cfg) // fails without the admin plugin, or a missing DisposableListFile
_, err = p.Migrate(ctx)    // creates polaris_sentinel_decision, polaris_sentinel_ip_rule, polaris_sentinel_device
```

## Config

The zero value is the defaults: observe mode, the local signals, the bundled domain list.

| Field | Default | Purpose |
| --- | --- | --- |
| `Mode` | `sentinel.Observe` | `sentinel.Enforce` answers blocks and challenges |
| `Policy` | challenge from 40, block from 80 | `sentinel.Policy{ChallengeAt, BlockAt}` over the summed score (0..100) |
| `Velocity` | `sentinel.DefaultVelocity` | `"ip"`, `"email"`, `"device"` => `sentinel.Limit{Max, Window}`; a dimension left out is not counted |
| `Captcha` | nil | `sentinel.Turnstile(secret)`, `sentinel.HCaptcha(secret)` or your `sentinel.BotVerifier` |
| `Geo` | nil (`sentinel.NoGeo`) | `sentinel.GeoResolver` for impossible travel; no geo database ships |
| `Breaches` | nil | `security.HIBP{}` enables the breached-password signal (and core's port unless `Config.Breaches`) |
| `Domains` / `DisposableDomains` / `DisposableListFile` | bundled list | replace, extend or load the disposable-domain list |
| `Counters` | `sentinel.NewCacheCounters` on the graph's cache | `sentinel.CounterStore`; plug Redis for counts exact across replicas |
| `Routes` | `sentinel.DefaultRoutes` | guarded manifest paths => attempt kind |
| `Signals` / `NoBuiltIn` | built-ins | your `sentinel.Signal`s, after (or instead of) the built-ins |
| `HTTPClient` | `http.DefaultClient` | fetches lists for `RefreshDomainList` |

## Routes

Guarded by default (middleware, before core's endpoint; all POST): `/auth/register`, `/auth/login`,
`/auth/password/forgot`, `/auth/email/verify/resend`, `/auth/mfa/challenge`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/admin/sentinel/decisions` | decisions, newest first; filters `email`, `ip`, `action`, `cursor`, `limit` (admin `read`) |
| GET | `/admin/sentinel/ip-rules` | the IP rules, in matching order (admin `read`) |
| POST | `/admin/sentinel/ip-rules` | add `{cidr, action: allow\|block, note?}` (admin `own`) |
| DELETE | `/admin/sentinel/ip-rules/{id}` | remove a rule (admin `own`) |
| POST | `/admin/sentinel/unblock` | clear the counters of `{identifier}` (an email or an IP; admin `support`) |

## Events and permissions

`sentinel.evaluated` (`sentinel.Evaluated`, whenever a signal spoke; never the password nor the
captcha token), `sentinel.ip_rule_created`, `sentinel.ip_rule_deleted`, `sentinel.unblocked`; all
in the audit catalog. Admin routes use the admin plugin's capabilities (`admin.Read`, `admin.Own`,
`admin.Support`).

## Problems

Enforce mode only: `https://polaris.univeros.io/problems/sentinel/blocked` (403) and
`…/sentinel/challenge_required` (403, `"challenge": "captcha"`, only with `Captcha` set; the client
retries the same request with `captcha_token`). Admin routes answer `…/admin/unauthorized` (401),
`…/admin/forbidden` (403), `…/admin/impersonation_denied` (403), `…/admin/invalid_input` (422),
`…/admin/not_found` (404). Failing to record a decision answers 500; a failing signal is skipped.

## Host integration

- Without a `Captcha` verifier nothing can answer a challenge: the challenge band is recorded and let
  through.
- The middleware reads JSON and form bodies and sets the `polaris_device` cookie
  (`sentinel.DeviceCookie`) when a guarded request has none.
- `sentinel.Of(g).Engine().Evaluate(ctx, sentinel.Attempt{…})` judges your own attempts;
  `Engine().Unblock`, `IPRules()` and `Decisions()` serve the same as the admin routes.
- `Plugin.RefreshDomainList(ctx, url, to)` writes a fresh disposable-domain file; it is read at the
  next start.
- With `plugins/messaging`, a recipient challenged or blocked in the last hour gets no non-essential
  email (`Plugin.QuietFor`).

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/sentinel`.
