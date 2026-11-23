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
   first by default). The application sends the browser to `url`. The response also sets a cookie
   that binds the sign-in to this browser (below), so call the route from the browser that will
   follow `url` (`fetch` with `credentials: "include"` when Polaris is on another origin), not from
   your server.
2. The IdP sends the browser back: `GET /sso/callback/{providerId}?code&state` (OIDC) or
   `POST SAMLResponse, RelayState` (SAML). The user is found by email or created when the provider's
   JIT is enabled (no password; verified only when the email is on a domain the organization
   verified), joined to the organization with `JIT.Roles` (`member` by default), and signed in with
   a session scoped to the organization (`amr` `["sso"]`); the answer is
   `302 <redirect_uri>?sso_code=…`. Tokens never travel in a URL.
3. `POST /sso/exchange {code}` answers core's login envelope, once, within a minute. Its
   `user.email_verified` is the account's own: false for an account the provider created outside
   the organization's verified domains.

### The browser that started it

A sign-in completes only in the browser that started it; otherwise someone could start a sign-in as
themselves and have another person's browser finish it, leaving that person in the wrong account
(login CSRF). `POST /sso/sign-in` sets a cookie named after the state
(`__Host-polaris_sso_<16 hex>`, `HttpOnly; Secure; SameSite=None; Path=/`, ten minutes; without the
`__Host-` prefix and `SameSite=Lax` when `Config.BaseURL` is plain http), and the callback refuses a
state whose cookie is missing or different (`sso/assertion_invalid`, reason "the sign-in was started
in another browser"). The scheme is `Config.BaseURL`'s, not the connection's, so it holds behind a
TLS-terminating proxy. From code, `Start` returns `Started.State` and `Started.Binding`, and
`CompleteOIDC` / `CompleteSAML` take the binding the browser presents. A SAML response without a
RelayState (IdP-initiated, accepted only with the provider's `idp_initiated`) has no browser that
started it and so no binding: leave the flag off unless the IdP needs it.

The exchange is not bound: `redirect_uri` receives a code, not a proof of which browser started the
sign-in. Someone who completes their own sign-in can send that URL to another person, who would then
be signed in to the sender's account. Before exchanging a code, check in your application that this
browser started a sign-in (a short-lived cookie or session entry your page set when it called
`/sso/sign-in`), and tell the user which account they are in.

### Whose accounts an IdP signs in

Whoever runs an organization's IdP can assert any email, and any user can create an organization and
configure one. So a provider signs in an **existing** account only when the organization owns it:

- one of its providers created it just in time (recorded in `polaris_sso_account`), or
- one of its SCIM directories created it (`plugins/scim`), or
- the account's email is on a domain the organization verified.

Being a member is not enough: joining an organization does not hand it the account. Anything else
answers `sso/user_unknown`. An unverified account on a verified domain becomes verified by the
sign-in, as the mailbox's first proof (`Identity.ProveEmail`: what could sign in before goes). A platform
superadmin never signs in through an organization's IdP.

A provider vouches for a mailbox only on a domain its organization verified. An account it creates
anywhere else is **unverified** and stays so however often the provider signs it in. When the
mailbox's owner proves it (a password reset, an email code or magic link), the account is theirs:
the first proof removes the provisioning record (`sso` implements `wiring.AccessEraser`), and the
provider answers `sso/user_unknown` from then on. A sign-in in flight when that happens opens no
session. So an IdP cannot mint a verified account for an
address its organization does not control, nor keep one.

### Who configures single sign-on

Whoever runs an organization's IdP signs in as any member the organization owns, with the roles that
member holds, the owners' included. So creating, changing (disabling included) or deleting a provider,
and adding, verifying or deleting a domain, takes every permission the organization's roles grant (the
escalation rule of role changes and invitations, 403 `sso/forbidden`): in practice an owner. Others
holding `org.update` read providers and domains and test a provider. `Providers()` and `Domains()`
from code are the host's and are not checked.

Upgrading from v0.7.0 or earlier: a provider or domain configured by someone who was not an owner
stays as it is. Review them: `created_by` names who created a provider, the audit trail's
`sso.provider_updated` and `sso.domain_*` who changed it since.

`jit.roles` are role slugs of the organization (an unknown one is a 422; a PATCH that does not send
`jit` is not checked).

### Domains

A verified domain belongs to one organization. A claim nobody verified reserves nothing: when
another organization claims the domain, the unverified claim is replaced (it disappears from the
first organization's list). An organization's verification token for a domain is the same on every
claim, so one whose claim was replaced claims again and verifies with the DNS record or file it
already published. `409 sso/conflict` means the domain is verified elsewhere, or already claimed
by the caller's organization.

A verification does not expire, and the HTTPS method proves control of the domain's web root, not of
its mail. When a domain changes hands, its former organization should delete it (or an operator the
provider). To accept DNS only, set `Config.Domains` to `sso.DNSHTTPSVerifier{}`, which has no HTTP
client.

### OIDC checks

The discovery document's `issuer` must be the configured issuer (OpenID Connect Discovery §4.3;
a trailing slash aside), and the ID token must carry `exp`. A provider failing either is refused
with `sso/assertion_invalid`.

Upgrading from v0.5.0 or earlier: accounts a provider created before the record existed sign in
again once the organization verifies their email domain. Where it cannot (contractors on public
mail domains), record them from code, only for accounts the organization's IdP created:

```go
err := sso.Of(p.Graph()).MarkProvisioned(ctx, organizationID, userID)
```

### What an SSO session may do

The session is bound to the provider's organization (`amr` holds `"sso"`, `Principal.OrganizationBound`
is true), because the IdP's operator is not the account holder:

- `POST /auth/switch-org` to another organization answers 403;
- every route that needs no permission and writes, destroys or is a step-up route answers 403: the
  password, MFA factors and recovery codes, passkeys, API keys, provider links, phone numbers,
  agents and OAuth consent, creating or joining an organization, the profile, deleting the account,
  logout-everywhere, the MFA step-up;
- it reads (`/auth/me`, lists), logs out (`/auth/logout`, `/sso/logout`), refreshes, and does what
  its roles in the organization allow, step-up routes with a permission included (the IdP sign-in
  is the recent authentication there);
- it never carries the superadmin override.

A user who needs those routes signs in to the account itself (password, passkey, email code). A
host route behind `p.Protect` that acts on the user's account, or on data outside the
organization, should refuse `Principal.OrganizationBound` too.

The binding is the `amr` value, wherever the session comes from: a host that opens a session
itself with `p.Sessions().Issue(ctx, polaris.SignIn{…})` and passes an `AMR` containing `"sso"` gets an
organization-bound session with all of the above. Pass `"sso"` when your own code signed the user
in on an organization IdP's word, and leave it out otherwise.

Disabling or deleting a provider or a domain stops new sign-ins and leaves the sessions it opened: they
end with their refresh tokens, with the membership, or when you revoke them
(`p.Sessions().RevokeAll`, `DELETE /admin/users/{id}/sessions`).

An IdP's LogoutRequest ends the sessions of the accounts the organization owns (the rule above).

## Routes

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| POST | `/sso/sign-in` | public | start a sign-in |
| GET, POST | `/sso/callback/{providerId}` | public | the IdP's answer (OIDC code, SAML response) |
| POST | `/sso/exchange` | public | trade the hand-off code for the session |
| GET | `/sso/metadata/{providerId}` | public | the SP metadata (SAML) |
| GET, POST | `/sso/slo/{providerId}` | public | single logout from the IdP, or the IdP's answer to ours |
| POST | `/sso/logout` | bearer | end the caller's sessions; answers the IdP's logout `url` |

Organization admins (bearer, `org.update` in the active organization; every route that writes also
needs every permission the organization's roles grant, above), under `/orgs/{id}/sso`:

| Method | Path | Purpose |
| --- | --- | --- |
| GET, POST | `/providers` | list / create |
| GET, PATCH, DELETE | `/providers/{providerId}` | read (with the SP URLs) / update / delete |
| POST | `/providers/{providerId}/test` | whether the provider is complete and reachable |
| GET, POST | `/domains` | list / add |
| POST | `/domains/{domainId}/verify` | verify through the DNS TXT record `_polaris.<domain>` or `https://<domain>/.well-known/polaris-sso.txt` |
| DELETE | `/domains/{domainId}` | delete |

A provider's body is strict JSON: `config`, `attributes` and `jit` are objects, `redirect_uris` a
list, `enabled` and `jit.enabled` booleans; every URL (`sso_url`, `slo_url`, `slo_response_url`,
the redirect URIs) is an absolute `http(s)` URL with a host, in printable ASCII. `limit` on the
operators' list is a decimal integer. Timestamps are RFC 3339 in UTC (`2026-11-20T18:32:59Z`).

The OIDC client secret is encrypted at rest and never returned (`client_secret_set`). Operators (admin
plugin principals): `GET /admin/sso/providers` (admin `read`), `DELETE /admin/sso/providers/{id}`
(admin `own`). Without the admin plugin these answer 401.

## What is checked

OIDC (`HTTPOIDC`): discovery cached an hour, the code flow with PKCE (S256) and a nonce,
`client_secret_post`, the `id_token` signed by the key of the provider's JWKS its `kid` names (the
JWKS `keys` is an array, RFC 7517), within a minute of leeway, its issuer, audience and nonce. The
key's `alg` must be the token's; a key without `alg` verifies the algorithm its type implies (RSA
RS256, EC P-256 ES256, OKP Ed25519 EdDSA) and any other key without `alg` verifies nothing. SAML
(`DefaultSAML`, `github.com/crewjam/saml`): exactly one assertion, signed on the response or the
assertion by the provider's certificate (read from what the signature covers), its issuer, audience,
`Destination` and `Recipient`, `InResponseTo`, the conditions with three minutes of skew, and the
assertion id kept until it expires so a replay is refused. An IdP's `LogoutRequest` must be signed.
The certificate's validity dates are not checked: it only carries the key the organization
configured, which is the trust anchor (as in most SAML service providers); an IdP rotating its key is
a configuration change. Outbound requests (OIDC, the domain's well-known file) connect to
public addresses only and never follow redirects, because an organization admin names those hosts.

## Events and permissions

`sso.provider_created`, `sso.provider_updated`, `sso.provider_deleted`, `sso.domain_added`,
`sso.domain_verified`, `sso.domain_deleted`, `sso.signed_in`, `sso.assertion_rejected`,
`sso.slo_completed` (`sso.Audit*` constants). Without audit nothing is recorded, but the events still
fire. Uses core's `org.update`.

## Problems

`https://polaris.univeros.io/problems/sso/provider_not_found` (404), `…/sso/provider_disabled` (403),
`…/sso/assertion_invalid` (403, a rejected assertion or token: the detail is generic, the reason is
`Event.Data["reason"]` of `sso.assertion_rejected`), `…/sso/user_unknown` (403: no account and JIT
off, or an existing account the organization does not own), `…/sso/account_disabled` (403), `…/sso/membership_suspended` (403), `…/sso/code_invalid` (422),
`…/sso/invalid_input` (422). Organization routes add `…/sso/forbidden` (403, not your active
organization, or configuring single sign-on without every permission its roles grant), `…/sso/not_found` (404), `…/sso/conflict` (409, the domain is already claimed) and
`…/sso/domain_unverified` (422). Admin routes answer the admin plugin's problems.

## Host integration

- From code: `sso.Of(g)` (`Start`, `CompleteOIDC`, `CompleteSAML`, `Exchange`, `Logout`,
  `Providers()`, `Domains()`, `SP()`).
- Other plugins check a domain with `sso.Of(g).DomainVerified(ctx, organizationID, domain)`: a SCIM
  directory links an existing account to its organization only when the account's email is on a
  verified domain.
- A host's own `OIDC` or `SAML` implementation returns an `*sso.Error` with `sso.ReasonAssertionInvalid`
  for a refused token; any other error is treated the same way.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/sso`.
