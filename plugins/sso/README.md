# plugins/sso

Single sign-on per organization: SAML 2.0 and OpenID Connect identity providers, verified domains that
route an email to its organization's provider, just-in-time users and memberships, and single logout
in both directions. Organizations configure their own providers and domains; operators see every
provider. `plugins/audit` and `plugins/admin` are optional.

## Install

```go
import "github.com/univeros/polaris.go/plugins/sso"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}), sso.New(sso.Config{}))
p, err := polaris.New(cfg) // a relative BaseURL fails here
_, err = p.Migrate(ctx)    // creates polaris_sso_provider, polaris_sso_domain
```

Short-lived state (the OIDC state, nonce and PKCE verifier, the SAML request ids, the assertion ids
seen, the hand-off codes) lives in the graph's cache, encrypted where it holds secrets: share the cache
across replicas (its `Add` must be atomic).

## Config

| Field | Default | Purpose |
| --- | --- | --- |
| `BaseURL` | `Auth.Issuer` + `Config.PathPrefix` | absolute http(s) URL where Polaris is mounted, prefix included; the SP entity id (`<BaseURL>/sso/metadata/{providerId}`), the assertion consumer and OIDC redirect URI (`/sso/callback/{providerId}`) and the single-logout URL (`/sso/slo/{providerId}`) derive from it |
| `HTTPClient` | public addresses only, no redirects | talks to the OIDC providers (discovery, token endpoint, JWKS) and fetches the domains' well-known files |
| `OIDC`, `SAML`, `Domains` | `HTTPOIDC`, `DefaultSAML`, `DNSHTTPSVerifier` | replace the protocol implementations (tests use fakes) |
| `SPCertificate`, `SPPrivateKey` | none | PEM, RSA, both or neither: sign the AuthnRequests and logout messages and are published in the SP metadata |

## The sign-in

1. `POST /sso/sign-in {email | provider_id, redirect_uri?}` answers `{url, provider_id, type}`: a
   verified domain routes the email to its provider; `redirect_uri` must be one of the provider's (the
   first by default). The application sends the browser to `url`.
2. The IdP sends the browser back: `GET /sso/callback/{providerId}?code&state` (OIDC) or
   `POST SAMLResponse, RelayState` (SAML). The user is found by email or created when the provider's
   JIT is enabled (verified, no password), joined to the organization with `JIT.Roles` (`member` by
   default), and signed in with a session scoped to the organization (`amr` `["sso"]`); the answer is
   `302 <redirect_uri>?sso_code=…`. Tokens never travel in a URL.
3. `POST /sso/exchange {code}` answers core's login envelope, once, within a minute.

An IdP signs in only the organization's members or users whose email is on one of its verified
domains.

## Routes

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/sso/sign-in` | public | start a sign-in |
| GET, POST | `/sso/callback/{providerId}` | public | the IdP's answer (OIDC code, SAML response) |
| POST | `/sso/exchange` | public | trade the hand-off code for the session |
| GET | `/sso/metadata/{providerId}` | public | the SP metadata (SAML) |
| GET, POST | `/sso/slo/{providerId}` | public | single logout from the IdP, or the IdP's answer to ours |
| POST | `/sso/logout` | bearer | end the caller's sessions; answers the IdP's logout `url` |

Organization admins (bearer, `org.update` in the active organization), under `/orgs/{id}/sso`:

| Method | Path | Purpose |
| --- | --- | --- |
| GET, POST | `/providers` | list / create |
| GET, PATCH, DELETE | `/providers/{providerId}` | read (with the SP URLs) / update / delete |
| POST | `/providers/{providerId}/test` | whether the provider is complete and reachable |
| GET, POST | `/domains` | list / add |
| POST | `/domains/{domainId}/verify` | verify through the DNS TXT record `_polaris.<domain>` or `https://<domain>/.well-known/polaris-sso.txt` |
| DELETE | `/domains/{domainId}` | delete |

The OIDC client secret is encrypted at rest and never returned (`client_secret_set`). Operators (admin
plugin principals): `GET /admin/sso/providers` (admin `read`), `DELETE /admin/sso/providers/{id}`
(admin `own`). Without the admin plugin these answer 401.

## What is checked

OIDC (`HTTPOIDC`): discovery cached an hour, the code flow with PKCE (S256) and a nonce,
`client_secret_post`, the `id_token` signed by a key of the provider's JWKS, within a minute of leeway,
its issuer, audience and nonce. SAML (`DefaultSAML`, `github.com/crewjam/saml`): exactly one
assertion, signed on the response or the assertion by the provider's certificate (read from what the
signature covers), its issuer, audience, `Destination` and `Recipient`, `InResponseTo`, the conditions
with three minutes of skew, and the assertion id kept until it expires so a replay is refused. An IdP's
`LogoutRequest` must be signed. Outbound requests (OIDC, the domain's well-known file) connect to
public addresses only and never follow redirects, because an organization admin names those hosts.

## Events and permissions

`sso.provider_created`, `sso.provider_updated`, `sso.provider_deleted`, `sso.domain_added`,
`sso.domain_verified`, `sso.domain_deleted`, `sso.signed_in`, `sso.assertion_rejected`,
`sso.slo_completed` (`sso.Audit*` constants). Without audit nothing is recorded, but the events still
fire. Uses core's `org.update`.

## Problems

`https://polaris.univeros.io/problems/sso/provider_not_found` (404), `…/sso/provider_disabled` (403),
`…/sso/assertion_invalid` (403, a rejected assertion or token: the detail is generic, the reason is
`Event.Data["reason"]` of `sso.assertion_rejected`), `…/sso/user_unknown` (403, no account and JIT
off), `…/sso/account_disabled` (403), `…/sso/membership_suspended` (403), `…/sso/code_invalid` (422),
`…/sso/invalid_input` (422). Organization routes add `…/sso/forbidden` (403, not your active
organization), `…/sso/not_found` (404), `…/sso/conflict` (409, the domain is already claimed) and
`…/sso/domain_unverified` (422). Admin routes answer the admin plugin's problems.

## Host integration

- From code: `sso.Of(g)` (`Start`, `Exchange`, `Logout`, `Providers()`, `Domains()`, `SP()`).
- Other plugins check a domain with `sso.Of(g).DomainVerified(ctx, organizationID, domain)`: a SCIM
  directory links an existing account to its organization only when the account's email is on a
  verified domain.
- A host's own `OIDC` or `SAML` implementation returns an `*sso.Error` with `sso.ReasonAssertionInvalid`
  for a refused token; any other error is treated the same way.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/sso`.
