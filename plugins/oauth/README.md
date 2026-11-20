# plugins/oauth

Polaris as an OAuth 2.1 and OpenID Connect provider: authorization code with PKCE (S256 only) and
consent, rotating refresh tokens, client credentials, the device flow (RFC 8628), backchannel
authentication (OpenID CIBA, poll mode), token exchange (RFC 8693, with `act`), DPoP (RFC 9449),
dynamic registration (RFC 7591, off by default), client ID metadata documents, introspection,
revocation, userinfo and discovery. A scope is a permission name: its access tokens (`at+jwt`, signed
with core's key) authenticate on every Polaris route and behind `p.Protect`, delegated to the
intersection of the user's permissions and the token's scopes. Port of `polaris/oauth-provider`
(plugin id `oauth`); required by `plugins/agents`; uses `plugins/admin` for its `/admin` routes when present.

## Install

```go
import "github.com/univeros/polaris-go/plugins/oauth"

cfg, err := polaris.FromEnv(db, oauth.New(oauth.Config{ConsentURL: "https://app.example.com/consent"}))
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // creates polaris_oauth_client, _consent, _code, _token, _device_code, _ciba_request
```

## Config

Every field is optional; the zero value is DPoP optional, metadata documents accepted, registration
off, no device flow.

| Field | Default | Purpose |
| --- | --- | --- |
| `BaseURL` | issuer + path prefix | where Polaris is mounted; discovery documents derive from it |
| `ConsentURL` | none | your consent page (`?request=<id>`); empty: `/oauth2/authorize` answers JSON only |
| `DeviceURL` | none | your device page (`verification_uri`); empty turns the device flow off |
| `HTTPClient` | public addresses only, 10 s | fetches metadata documents and `jwks_uri`; redirects never followed |
| `AccessTokenTTL`, `RefreshTokenTTL` | 1 h, 30 days | token lifetimes |
| `CodeTTL`, `DeviceCodeTTL`, `CIBATTL` | 10 min, 30 min, 10 min | pending-request lifetimes |
| `PollInterval` | 5 s | device / CIBA poll interval; negative disables the throttle |
| `DynamicRegistration` | off | open `POST /oauth2/register` to anyone |
| `DisableClientIDMetadata` | off | refuse `https` client ids |
| `DPoP` | `oauth.DPoPOptional` | `DPoPOff`, `DPoPOptional`, `DPoPRequired` |
| `Scopes` | none | extra scopes (`name → description`) beyond permissions and OpenID |
| `TrustedClients` | none | client ids whose users are never asked for consent |
| `Operators` | superadmin = owner | who calls `/admin/oauth`; with `plugins/admin` its operators are used |
| `Audiences` | none | further `aud` values accepted (e.g. `<BaseURL>/mcp` of `plugins/mcp`) |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | discovery (under the mount) |
| GET | `/oauth2/authorize` | start an authorization request (redirects to `ConsentURL`) |
| POST | `/oauth2/authorize/decision` | the signed-in user approves or refuses |
| POST | `/oauth2/token` | every grant: code, refresh, client credentials, device, CIBA, token exchange |
| POST | `/oauth2/introspect`, `/oauth2/revoke` | introspect / revoke a token |
| GET, POST | `/oauth2/userinfo` | the user's OpenID claims |
| POST | `/oauth2/device/code` | start the device flow |
| GET | `/oauth2/device/verify` | read the device behind a user code |
| POST | `/oauth2/device/approve` | approve or refuse a device |
| POST | `/oauth2/ciba` | backchannel authentication request |
| GET | `/oauth2/ciba/pending` | the user's pending backchannel requests |
| POST | `/oauth2/ciba/{id}/decide` | approve or refuse one |
| GET | `/oauth2/consents` | the user's consents |
| DELETE | `/oauth2/consents/{clientId}` | revoke a consent and the client's tokens for the user |
| POST | `/oauth2/register` | dynamic registration (when `DynamicRegistration`) |
| GET, POST | `/orgs/{id}/oauth/clients` | list / register the organization's clients (`org.update`) |
| GET, PATCH, DELETE | `/orgs/{id}/oauth/clients/{clientId}` | read / update / delete one (`org.update`) |
| GET, POST | `/admin/oauth/clients` | operators: every client / register one, `trusted` allowed |
| DELETE | `/admin/oauth/clients/{id}` | operators: delete a client |

## Events and permissions

Emits `oauth.Event` with `EventClientCreated`, `EventClientUpdated`, `EventClientDeleted`,
`EventConsentGranted`, `EventConsentDenied`, `EventConsentRevoked`, `EventTokenIssued`,
`EventTokenRefused`, `EventTokenRevoked`, `EventRefreshReused`, `EventDeviceDecided`,
`EventCIBARequested`, `EventCIBADecided` (`oauth.*`); it implements `audit.Auditable` and
`Plugin.AuditNames` adds them to the catalog. Contributes no permissions; organization clients need
core's `org.update`; `/admin/oauth` needs the admin capability `read` to list, `own` to create or delete.

## Problems

A refused OAuth request is a problem `https://polaris.univeros.io/problems/oauth/<code>` that also
carries RFC 6749's `error` and `error_description`; the codes are the `oauth.Code*` constants
(`invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `access_denied`,
`authorization_pending`, `slow_down`, `expired_token`, `invalid_dpop_proof`,
`invalid_client_metadata`, `registration_disabled`, …). Also `…/oauth/forbidden` (403, not your
active organization) and `…/oauth/not_found` (404). In Go, match `*oauth.Error` with `errors.As`.

## Host integration

- In a handler behind `p.Protect`: `who, _ := polaris.PrincipalFrom(r.Context())` — `who.Kind` is
  `polaris.KindOAuthClient` (`KindAgent` for an agent's token), `who.ClientID` the client,
  `who.UserID` the user it acts for (`""` for client credentials), `who.Permissions` the scopes
  intersected with the user's authority; `who.Claims[oauth.ClaimScope]`, `who.Claims[oauth.ClaimAct]`;
  the AMR is `oauth.AMR`.
- From code: `p.Graph().Plugin(oauth.ID).(*oauth.Plugin)` — `CreateClient`, `UpdateClient`,
  `DeleteClient`, `IssueTokens`, `Exchange`, `RevokeClientTokens`, `VerifyDPoP`.
- Schedule `Plugin.Prune(ctx)` (expired codes, device and CIBA requests, dead tokens) beside
  `maintenance.PruneExpired`.
- Outbound fetches (metadata documents, `jwks_uri`) refuse non-public addresses at connect time even
  with your `HTTPClient`; DPoP and client-assertion `jti` replay relies on `polaris.Config.Cache` being
  shared across replicas.
- Listen to `oauth.EventCIBARequested` to notify the user of a backchannel request.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris-go/plugins/oauth`.
