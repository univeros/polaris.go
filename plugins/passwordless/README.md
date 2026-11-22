# plugins/passwordless

Four ways to sign in without a password, each ending in core's login envelope behind core's MFA
gate: magic links (a link valid once for 15 minutes; opening it shows a "Sign in" button, and
pressing it redirects to your app with a one-minute code traded at `/magic-link/exchange`), email codes (6 digits, 5 minutes, 5 attempts) for signing in,
verifying the address or resetting the password, SMS codes to a verified phone, and one-time tokens
that hand a live session to another device. Every send answers the same 202 for known and unknown
identifiers.

## Install

```go
import "github.com/univeros/polaris.go/plugins/passwordless"

cfg, err := polaris.FromEnv(db, passwordless.New(passwordless.Config{
	RedirectURIs: []string{"https://app.example.com/signed-in"},
}))
cfg.Mailer = mailer // notify.Mailer: templates "magic_link" {link, ttl} and notify.TemplateOTPCode {code, ttl}
cfg.SMS = sms       // notify.SMSSender, for the phone routes
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_passwordless_secret, polaris_passwordless_phone
```

## Config

Every field is optional; the zero value is the defaults.

| Field | Default | Purpose |
| --- | --- | --- |
| `RedirectURIs` | none | exact URLs a magic link may end on; the first is the default. Without any, `/magic-link/send` answers `redirect_not_allowed` |
| `BaseURL` | issuer + `polaris.Config.PathPrefix` | where the routes are mounted; the magic link points here |
| `DisableSignUp` | off (sign-up on) | stop magic links and email codes from creating an account for an unknown address |
| `SkipMFAGate` | off (gate on) | open a session even for a user with a confirmed second factor |
| `MagicLinkTTL`, `OTPTTL`, `OneTimeTokenTTL` | 15 min, 5 min, 3 min | lifetimes, whole seconds |
| `OTPLength` | 6 | digits of a code, 6 to 10 |
| `MaxAttempts` | 5 | guesses a code takes |

`DisableSignUp` and `SkipMFAGate` are phrased so the zero value is the default.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/magic-link/send` | email a magic link (`email`, `redirect_uri`); 202 |
| GET | `/magic-link/verify` | open the link (`token`): an HTML page with one "Sign in" button that posts back to the link; spends nothing |
| POST | `/magic-link/verify` | the button (`token` in the query, or the body): spend the link; 302 to the redirect URI with `code` |
| POST | `/magic-link/exchange` | trade the `code` for the login envelope |
| POST | `/email-otp/send` | email a code (`email`, `purpose`: `sign-in` default, `verify-email`, `reset-password`); 202 |
| POST | `/email-otp/verify` | sign in with `email` + `code` |
| POST | `/email-otp/verify-email` | verify the address with `email` + `code` |
| POST | `/email-otp/reset-password` | reset the password with `email` + `code` + `password` |
| POST | `/phone/send` | text a sign-in code to a verified `phone` (E.164); 202 |
| POST | `/phone/verify` | sign in with `phone` + `code` |
| POST | `/phone/add` | bearer, step-up gated: text a code to a new `phone`; 202 |
| POST | `/phone/confirm` | bearer, step-up gated: confirm `phone` + `code` |
| POST | `/one-time-token/generate` | bearer, live session only: a token valid once for 3 minutes |
| POST | `/one-time-token/verify` | trade the `token` for a session inheriting the first one's amr, mfa, auth_time, organization |

A phone never signs anyone up. A user with a confirmed factor gets core's `mfa_required` envelope
(complete it at `/auth/mfa/verify`) unless `SkipMFAGate`. A factor that sends its code where the
sign-in's code or link went (an email factor on the same address, an SMS factor on the same phone)
proves nothing more, so it is left out: the envelope lists, and its `mfa_token` accepts, only the
other factors (and recovery codes). When no other factor is left the sign-in answers 403
`passwordless/mfa_same_channel`: the user signs in with the password, or adds another factor.

An email code or magic link sign-in, and a reset code, prove the mailbox. For an account nobody
had proven (registered but never verified) that is the first proof (`Identity.ProveEmail`): the
account becomes verified and what could sign in before goes, since whoever created it may not own
the mailbox: the password (a reset then sets the new one), MFA factors, passkeys, provider links,
API keys, OAuth grants, the confirmed phone, every session. A `verify-email` code confirms the
registration instead: an account with a password is marked verified and keeps everything.

A `verify-email` or `reset-password` code is for the address it was sent to: when the account has
moved to another address since (a SCIM directory renamed it), the code answers
`passwordless/code_invalid`. A registration of an unverified address with another password than
the account has removes that password and the codes and links pending for the account (core's
`POST /auth/register`); a `verify-email` code then proves the mailbox and confirms no password.

Opening a magic link spends nothing: email security scanners follow links with GET, so the GET
answers a page (no JavaScript, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`) whose one
button posts back to the same URL, and that POST spends the link.

## Events and permissions

Dispatches core events: `user.logged_in` (sign-ins), `user.email_verified`, `user.password_changed`.
Session amr: `passwordless.AMRMagicLink`, `AMREmailOTP`, `AMRPhone`, `AMROneTimeToken`. No
permissions: routes are public or bearer.

## Problems

`https://polaris.univeros.io/problems/passwordless/invalid_input` (422),
`…/redirect_not_allowed` (422), `…/code_invalid` (422; a wrong code answers like an unknown identifier),
`…/token_invalid` (422), `…/password_invalid` (422), `…/account_disabled` (403),
`…/session_required` (403, no live session to hand off), `…/mfa_same_channel` (403, the only
second factor delivers where the sign-in did), `…/phone_taken` (409). Go errors match
`passwordless.ErrCodeInvalid` etc. with `errors.Is` (`*passwordless.Error`, `Kind`).

## Host integration

- A failed delivery is logged and still answers 202; check your Mailer/SMS logs, not the response.
- Rate-limit the send and sign-in routes with `plugins/sentinel`: add `passwordless.SentinelRoutes`
  to `sentinel.Config.Routes` (alongside `sentinel.DefaultRoutes`).
- A front end that opened the magic link with a GET and expected the 302 (v0.4 and earlier) now gets
  the page: let the browser show it, or POST to the link yourself.
- Erasing a user deletes its pending links and codes and its verified phone inside the erasure's
  transaction (`wiring.AccessEraser`).
- The secrets' `data` column is written as standard JSON (`{}` when empty); rows written by earlier
  releases (`\/`, `\uXXXX`, `[]`) still read, so links and tokens issued before an upgrade keep
  working.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/passwordless`.
