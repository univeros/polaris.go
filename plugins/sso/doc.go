// Package sso is the SSO plugin (port of polaris/sso): per-organization SAML 2.0 and OpenID Connect
// identity providers, verified domains that route an email to its organization's provider,
// just-in-time users and memberships, single logout in both directions, the organization's own
// self-service routes and the operators' view.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}), sso.New(sso.Config{})},
//	})
//
// Config.BaseURL (default: the issuer followed by the path prefix) is where Polaris is mounted; the
// SP entity id (<BaseURL>/sso/metadata/{providerId}), the assertion consumer and OIDC redirect URI
// (/sso/callback/{providerId}) and the single-logout URL (/sso/slo/{providerId}) derive from it.
// The audit and admin plugins are optional: without audit nothing is recorded (events still fire),
// without admin the /admin/sso routes answer 401. Short-lived state (the OIDC state, nonce and PKCE
// verifier, the SAML request ids, the assertion ids seen, the hand-off codes) lives in the graph's
// cache, encrypted where it holds secrets: share the cache across replicas (its Add must be atomic).
//
// # The sign-in
//
//  1. POST /sso/sign-in {email | provider_id, redirect_uri?} answers {url, provider_id, type}: a
//     verified domain routes the email to its provider; redirect_uri must be one of the
//     provider's (the first by default). The application sends the browser to url.
//  2. The IdP sends the browser back: GET /sso/callback/{providerId}?code&state (OIDC) or POST
//     SAMLResponse, RelayState (SAML). The user is found by email or created when the provider's
//     JIT is enabled (verified, no password), joined to the organization with JIT.Roles ("member"
//     by default), and signed in with a session scoped to the organization (amr ["sso"]); the
//     answer is 302 <redirect_uri>?sso_code=…. Tokens never travel in a URL.
//  3. POST /sso/exchange {code} answers core's login envelope, once, within a minute.
//
// A rejected assertion or token answers 403 sso/assertion_invalid with a generic detail; the
// reason is the sso.assertion_rejected event (Event.Data["reason"]).
//
// # What is checked
//
// OIDC (HTTPOIDC): discovery cached an hour, the code flow with PKCE (S256) and a nonce,
// client_secret_post, the id_token signed by a key of the provider's JWKS, within a minute of
// leeway, its issuer, audience and nonce. SAML (DefaultSAML, github.com/crewjam/saml): exactly one
// assertion, signed on the response or the assertion by the provider's certificate (read from what
// the signature covers), its issuer, audience, Destination and Recipient, InResponseTo, the
// conditions with three minutes of skew, and the assertion id kept until it expires so a replay is
// refused. An IdP's LogoutRequest must be signed. Outbound requests (OIDC, the domain's
// well-known file) connect to public addresses only and never follow redirects, because an
// organization admin names those hosts.
//
// # Organizations and operators
//
// Under /orgs/{id}/sso (org.update in the active organization): providers (list, create, read
// with the SP URLs, update, delete, test) and domains (list, add, verify through a DNS TXT record
// _polaris.<domain> or https://<domain>/.well-known/polaris-sso.txt, delete). The OIDC client secret
// is encrypted at rest and never returned (client_secret_set). Operators: GET /admin/sso/providers
// (read) and DELETE /admin/sso/providers/{id} (own). Other plugins check a domain with
// DomainVerified.
package sso
