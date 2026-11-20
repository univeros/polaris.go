# plugins/passkey

WebAuthn passkeys: a signed-in user registers one from their session, then signs in with it through
a discoverable ceremony (conditional UI: the browser offers the user's passkeys, autofill included)
that ends in core's login envelope with `amr ["passkey"]`; passkeys can be listed, renamed and
removed. By default every passkey is also a confirmed core MFA factor of type `passkey`
(`passkey.FactorType`), verified through core's `/auth/mfa/verify` and `/auth/mfa/step-up` with the
assertion JSON as the code. Port of `polaris/passkey`; needs no other plugin.

## Install

```go
import "github.com/univeros/polaris-go/plugins/passkey"

cfg, err := polaris.FromEnv(db, passkey.New(passkey.Config{
	Origins: []string{"https://app.example.com"},
	RPName:  "App",
}))
p, err := polaris.New(cfg) // a bad Origins / RPID fails here
_, err = p.Migrate(ctx)    // creates polaris_passkey (challenges live in the cache)
```

## Config

`Origins` is required; every other zero value is upstream's default.

| Field | Default | Purpose |
| --- | --- | --- |
| `Origins` | required | exact origins the pages live on; plain `http` only on localhost and 127.0.0.1 |
| `RPID` | first origin's host | domain passkeys are bound to; a parent domain covers its subdomains |
| `RPName` | `"Polaris"` (`passkey.DefaultRPName`) | what the authenticator shows |
| `NoMFAFactor` | false | keep passkeys out of core's MFA |
| `UserVerification` | `passkey.UVPreferred` | or `passkey.UVRequired`, `passkey.UVDiscouraged` |
| `Attachment` | `""` (no preference) | `"platform"` or `"cross-platform"` |
| `Timeout` | 1 min (`passkey.DefaultTimeout`) | the browser's ceremony timeout |
| `ChallengeTTL` | 5 min (`passkey.DefaultChallengeTTL`) | how long a challenge waits in the cache |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/passkey/register/options` | creation options for `navigator.credentials.create()` (bearer, step-up) |
| POST | `/passkey/register/verify` | store the passkey: `{credential, name?}` (bearer, step-up) |
| POST | `/passkey/authenticate/options` | request options for `navigator.credentials.get()` (public; call on page load for autofill) |
| POST | `/passkey/authenticate/verify` | sign in: `{credential}`, answers core's login envelope (public) |
| GET | `/passkey/list` | the caller's passkeys (bearer) |
| PATCH | `/passkey/{id}` | rename a passkey (bearer) |
| DELETE | `/passkey/{id}` | remove a passkey (bearer, step-up) |

`credential` is the `PublicKeyCredential` JSON the browser produced, as an object or a string.

## Events and permissions

Emits core events only: `user.logged_in` on sign-in; `mfa.enrolled` on registration and
`mfa.factor_removed` on removal (through core's MFA, so not with `NoMFAFactor`). Listens to core:
removing the passkey's MFA factor keeps the passkey as a sign-in credential; erasing a user erases
their passkeys. No permissions.

## Problems

`https://polaris.univeros.io/problems/passkey/invalid_input` (422),
`…/passkey/challenge_invalid` (422, unknown, used or expired), `…/passkey/credential_invalid` (422),
`…/passkey/origin_mismatch` (403), `…/passkey/account_disabled` (403),
`…/passkey/email_unverified` (403), `…/passkey/user_verification_required` (403, the passkey is the
only second factor and the authenticator did not verify the user), `…/passkey/not_found` (404),
`…/passkey/last_factor` (409, enrol another factor first).

## Host integration

- Serve the pages from an origin listed in `Origins`; cross-origin ceremonies are refused.
- An assertion with user verification (UV) is two factors in one: the session carries `mfa` true and
  core's MFA gate is skipped; without UV the gate applies.
- WebAuthn is implemented in-package (CBOR decoder, ES256/RS256), not go-webauthn; RSA keys must be
  at least 2048 bits.
- Hosts wiring their own store: `passkey.Models()` declares `polaris_passkey`
  (`passkey.TablePasskeys`).

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris-go/plugins/passkey`.
