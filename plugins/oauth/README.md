# plugins/oauth

Polaris as an OAuth 2.1 and OpenID Connect provider: authorization code with PKCE (S256 only) and
consent, rotating refresh tokens, client credentials, the device flow (RFC 8628), backchannel
authentication (OpenID CIBA, poll mode), token exchange (RFC 8693, with `act`), DPoP (RFC 9449),
dynamic registration (RFC 7591, off by default), client ID metadata documents, introspection,
revocation, userinfo and discovery. A scope is a permission name: its access tokens (`at+jwt`, signed
with core's key) authenticate on every Polaris route and behind `p.Protect`, delegated to the
intersection of the user's permissions and the token's scopes. Plugin id `oauth`; required by
`plugins/agents`; uses `plugins/admin` for its `/admin` routes when present.

## Install

```go
import "github.com/univeros/polaris.go/plugins/oauth"

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
| `TrustedClients` | none | client ids you trust like a client registered `trusted` (see "Trusted clients") |
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
| GET, POST | `/admin/oauth/clients` | operators: every client / register one; `trusted` and the CIBA grant take an owner of the instance |
| DELETE | `/admin/oauth/clients/{id}` | operators: delete a client |

## Events and permissions

Emits `oauth.Event` with `EventClientCreated`, `EventClientUpdated`, `EventClientDeleted`,
`EventConsentGranted`, `EventConsentDenied`, `EventConsentRevoked`, `EventTokenIssued`,
`EventTokenRefused`, `EventTokenRevoked`, `EventRefreshReused`, `EventDeviceDecided`,
`EventCIBARequested`, `EventCIBADecided` (`oauth.*`); it implements `audit.Auditable` and
`Plugin.AuditNames` adds them to the catalog. Contributes no permissions; organization clients need
core's `org.update`; `/admin/oauth` needs the admin capability `read` to list, `own` to create or delete.

## Scopes a token carries

A token may carry fewer scopes than the client asked for; the token response's `scope` is what was
granted (RFC 6749 §3.3). A permission scope (`org.read`, one of your `Config.Permissions`) is put in
an access token only if the token's subject holds that permission when the token is minted, at the
first issue, on every refresh and on a token exchange:

- a user: what their roles grant in the token's organization (nothing without an organization);
- a client acting as itself (`client_credentials`): nothing, unless an operator registered it
  `trusted` with the permission in its `scopes` (`POST /admin/oauth/clients`; an organization
  cannot change a trusted client, see below), or a plugin that owns the client vouches for it
  (`oauth.ClientAuthority`: `plugins/agents` answers an agent's live grants that its owner holds).

The refresh token keeps the scopes that were consented, so a permission the user gains back
returns at the next refresh. Other scopes (`openid`, `profile`, `email`, `offline_access`,
`Config.Scopes`) are granted as asked: they describe what the client requested, not what anyone may
do. A service that checks tokens without this database (`verify`, `mcp.Protect`) should require
permission scopes to authorize.

A plugin that grants its clients permissions for a time implements `oauth.ClientGrantWindows`
beside `ClientAuthority` (`plugins/agents`: a grant with `expires_at`). A token of such a client,
its own or one a user delegated to it, carries a permission scope only while a grant covers it,
and expires no later than that grant: `expires_in` can be shorter than `AccessTokenTTL`.

## Trusted clients

An operator trusts a client by registering it `trusted` (`POST /admin/oauth/clients`,
`CreateClient` with `mayTrust`) or by listing its id in `Config.TrustedClients`. A trusted client:

- gets its code without a consent screen;
- may exchange and introspect tokens issued to other clients (a gateway or a resource server);
- registered `trusted`, holds the permission scopes the operator listed for `client_credentials`.

So what it is belongs to the operator. Its organization (`PATCH /orgs/{id}/oauth/clients/{clientId}`)
changes `name`, `logo_uri`, `policy_uri`, `tos_uri` and `disabled`, and nothing else: a different
`type`, `redirect_uris`, `grant_types`, `scopes`, `token_endpoint_auth_method`, `jwks`, `jwks_uri`,
`client_uri` or `dpop_bound_access_tokens` answers 400 `invalid_client_metadata`. Change those with
`UpdateClient(…, mayTrust true)`, or delete the client and register it again.

## Consent

A consent is the user's for one client in one organization (the session's active organization
when they approved; none for a session outside any). The same client asking in another
organization shows the screen again. `GET /oauth2/consents` lists one entry per client and
organization; `DELETE /oauth2/consents/{clientId}` removes them all, revokes the client's tokens for the
user and drops its unredeemed codes and pending requests, whether or not there was a consent (a device,
a backchannel request, an exchange and a trusted client need none). `Migrate` replaces the table's unique index (`polaris_oauth_consent_unique`
by `polaris_oauth_consent_org_unique`); a consent recorded before counts for the organization it
names.

A grant outlives the session it was given in: logging out, logging out everywhere and a password reset
or change do not end it. Taking the consent back does (or `POST /oauth2/revoke` by the client, or
erasing the account). To end everything a client holds, disable or delete it, then
`RevokeClientTokens`. While an account is disabled its grants issue nothing and its tokens introspect
as inactive; enabling it restores them. A lockout (failed passwords) changes nothing.

## Token exchange and introspection

`grant_type=urn:ietf:params:oauth:grant-type:token-exchange` takes as `subject_token` (and
`actor_token`):

- the access token of a live session of the user. A session that was logged out, an operator's
  impersonation token and a session an organization's identity provider opened (`amr` `sso`) are
  refused (`invalid_grant`): the exchanged token would outlive or outreach them;
- an access token this provider issued **to the same client**, or whose `aud` is the client's id.
  Another client's token is refused (`invalid_grant`) unless the exchanging client is trusted.

A token exchanged from one of the provider's own expires no later than it. The new token's audience is
the subject's (RFC 8707). Without `resource` it is the subject's own:
a token for `https://api.example` stays one, it does not become a token for this server. With
`resource`: a subject for this server (a session, `aud` the issuer or one of `Config.Audiences`)
narrows to any resource; a subject for another resource keeps it (`invalid_target` otherwise)
unless the client is trusted, or the subject's `aud` is the authenticated client's own id and the
new resource is not this server.

`POST /oauth2/introspect` answers a client about the tokens issued to it and the tokens whose
`aud` is its client id; a trusted client reads any token. To any other client a token is
`{"active": false}` (RFC 7662 §4). A resource server that introspects other clients' tokens is
registered `trusted`, or verifies the JWT itself (`verify`).

## DPoP

A proof's `htu` is the URL of the request on this server: the origin of `Config.BaseURL` (scheme
and host; default `Auth.Issuer`) and the path the client sent. The `Host` header is not read, so
behind a proxy that rewrites it nothing changes, and a proof made for another server does not
verify here. Set `BaseURL` to the public URL clients call.

## Problems

A refused OAuth request is a problem `https://polaris.univeros.io/problems/oauth/<code>` that also
carries RFC 6749's `error` and `error_description`; the codes are the `oauth.Code*` constants
(`invalid_request`, `invalid_client`, `invalid_grant`, `invalid_scope`, `access_denied`,
`authorization_pending`, `slow_down`, `expired_token`, `invalid_dpop_proof`,
`invalid_client_metadata`, `registration_disabled`, …). Also `…/oauth/forbidden` (403, not your
active organization) and `…/oauth/not_found` (404). In Go, match `*oauth.Error` with `errors.As`.

## Host integration

- Erasing a user deletes its consents, tokens, authorization codes, device codes and CIBA
  requests inside the erasure's transaction (`wiring.AccessEraser`).
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
- A client's `jwks` (registered or at `jwks_uri`) is a JWK Set whose `keys` is an array (RFC 7517);
  a `private_key_jwt` assertion names its key by `kid`, or carries no `kid` when the set holds one
  key. Times are RFC 3339 in UTC (`2026-11-22T10:00:00Z`); problem titles are sentences
  (`Invalid DPoP proof`), the `error` codes are those of RFC 6749 and its extensions.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/oauth`.
