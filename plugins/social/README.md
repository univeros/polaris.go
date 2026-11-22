# plugins/social

OAuth 2.0 and OpenID Connect sign-in and sign-up through 19 catalog providers or any other OAuth 2
server; account linking under a policy; Google One Tap; provider tokens on the user's behalf (stored
encrypted, refreshed when expiring); and an OAuth proxy so preview and local origins sign in through
the stable origin registered at the providers. A sign-in ends in core's login envelope (amr
`["social:<provider>"]`) or core's `mfa_required` ticket.

## Install

```go
import "github.com/univeros/polaris.go/plugins/social"

cfg, err := polaris.FromEnv(db, social.New(social.Config{
	BaseURL:      "https://app.example.com/auth", // where Polaris is mounted, prefix included
	RedirectURIs: []string{"https://app.example.com/signed-in"},
	Providers: map[string]social.Provider{
		"google": {ClientID: os.Getenv("GOOGLE_CLIENT_ID"), ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET")},
		"github": {ClientID: os.Getenv("GITHUB_CLIENT_ID"), ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET")},
	},
}))
p, err := polaris.New(cfg) // configuration errors (missing client id, unknown provider, bad Apple key) fail here
_, err = p.Migrate(ctx)    // creates polaris_social_account; the OAuth state lives in the cache
```

Register `BaseURL + "/social/<provider>/callback"` at each provider.

## Providers

`social.Catalog`: `google`, `apple`, `microsoft`, `github`, `gitlab`, `discord`, `facebook`, `x`,
`linkedin`, `slack`, `twitch`, `spotify`, `zoom`, `notion`, `dropbox`, `reddit`, `kick`, `tiktok`,
`huggingface` — each needs only `social.Provider{ClientID, ClientSecret}`, except:

- `apple`: `ClientID` plus `TeamID`, `KeyID`, `PrivateKey` (the .p8 PEM) instead of `ClientSecret`.
- `microsoft`: optional `Tenant` (`common` default, `organizations`, `consumers`, a tenant id).
- Any OpenID Connect server: any id with `Issuer` (discovered at first use), optional `Name`, `Scopes`.
- Any other OAuth 2 server: `Definition: &social.Definition{AuthorizationURL, TokenURL, UserinfoURL,
  Profile, …}`; `social.OIDCProfile` maps standard claims.

## Config

`BaseURL`, at least one provider and `RedirectURIs` are required; other zero values are the defaults.

| Field | Default | Purpose |
| --- | --- | --- |
| `TrustedProviders` | nil = google, apple | a verified email from these links to the existing user with that email; empty non-nil list trusts none. Never list a provider whose profile counts any returned email as verified (facebook, x, notion, kick, or such a custom Definition): it would let anyone take over an account by email |
| `AllowDifferentEmails` | none | providers that may be linked with an email other than the account's |
| `DisableSignUp` | off (sign-up on) | refuse a sign-in that matches no user |
| `SkipMFA` | off (gate on) | let a social sign-in past core's MFA gate |
| `Proxy` | none | stable origin registered at the providers when this deployment is mounted elsewhere; both share `APP_KEY` |
| `StateTTL` | 10 min | how long a started sign-in waits for its callback |
| `HTTPClient` | 10-second timeout | talks to the providers; redirects are never followed |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/social/{provider}/start` | authorization `url` + `state` (`redirect_uri`, `scopes` optional) |
| GET | `/social/{provider}/callback` | provider callback; 302 to `redirect_uri?code=&state=` |
| POST | `/social/{provider}/callback` | same, `response_mode=form_post` (Apple) |
| POST | `/social/exchange` | trade the one-minute `code` for the login envelope (or `{status: linked, account}` after a link) |
| POST | `/social/google/one-tap` | sign in with a One Tap `credential` (needs `google` configured) |
| GET | `/social/accounts` | bearer: your linked provider accounts |
| POST | `/social/{provider}/link` | bearer, step-up gated: start linking a provider to your account |
| DELETE | `/social/{provider}` | bearer, step-up gated: unlink (refused if it is your last credential) |
| POST | `/social/{provider}/token` | bearer, step-up gated: the provider access token, refreshed first if expiring |

Compare the returned `state` with the one `start` answered before exchanging the code.

## Events and permissions

Dispatches `social.Event` named `social.EventSignedIn`, `EventSignedUp`, `EventLinked`,
`EventUnlinked`, `EventTokenRefreshed`, `EventRejected` (`social.*`), plus core's `user.logged_in`.
With `plugins/audit` registered they become audit rows (`Plugin.AuditNames`). No permissions.

## Problems

`https://polaris.univeros.io/problems/social/` + `provider_not_found` (404), `redirect_not_allowed`,
`state_invalid`, `token_invalid`, `email_required`, `code_invalid`, `invalid_input` (422),
`provider_error`, `account_disabled`, `email_unverified` (403), `account_exists`, `account_linked`,
`email_mismatch`, `last_credential`, `no_refresh` (409), `not_linked` (404).

## Host integration

- Social works without audit. A `event.UserDeleted` erases the user's provider accounts (email,
  profile, tokens) through the plugin's listener.
- Unlinking checks for the last credential and deletes in one transaction with the user's row
  locked, so concurrent unlinks cannot leave an account without a way to sign in. A flow
  completes only in the browser that started it (a binding cookie, decision 39).

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/social`.
