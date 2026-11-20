package sso

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"time"
)

// SP is the service provider side: the URLs a provider's IdP talks to, derived from where Polaris
// is mounted (prefix included), and the optional key pair that signs AuthnRequests and logout
// messages, decrypts encrypted assertions and is published in the metadata.
type SP struct {
	BaseURL     string // no trailing slash
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
}

// EntityID is the SP entity id for a provider: its metadata URL.
func (sp SP) EntityID(providerID string) string { return sp.MetadataURL(providerID) }

// MetadataURL serves the SP metadata (GET /sso/metadata/{providerId}).
func (sp SP) MetadataURL(providerID string) string { return sp.BaseURL + "/sso/metadata/" + providerID }

// ACSURL is the assertion consumer (SAML) and the redirect URI (OIDC): /sso/callback/{providerId}.
func (sp SP) ACSURL(providerID string) string { return sp.BaseURL + "/sso/callback/" + providerID }

// SLOURL is the single-logout endpoint: /sso/slo/{providerId}.
func (sp SP) SLOURL(providerID string) string { return sp.BaseURL + "/sso/slo/" + providerID }

// Identity is who the identity provider asserted.
type Identity struct {
	Subject    string
	Email      string // lower case, trimmed
	Name       string // "" when none
	Attributes map[string]any
	// SAML only: the assertion id (the replay key), until when it is valid (zero when unknown),
	// and the IdP session.
	AssertionID  string
	NotOnOrAfter time.Time
	SessionIndex string
}

// OIDC is OpenID Connect against a provider. The default talks to the provider over HTTP
// (discovery, PKCE, client_secret_post, the id_token checked against its JWKS); a host or a test
// passes its own in Config.OIDC.
type OIDC interface {
	// AuthorizationURL is where the browser goes to sign in.
	AuthorizationURL(ctx context.Context, p Provider, redirectURI, state, nonce, codeChallenge string) (string, error)
	// Exchange trades the code for a verified identity; an error refuses the sign-in.
	Exchange(ctx context.Context, p Provider, clientSecret, code, redirectURI, codeVerifier, nonce string) (Identity, error)
	// EndSessionURL is the provider's logout for the browser, "" when it has none.
	EndSessionURL(ctx context.Context, p Provider, postLogoutRedirectURI string) string
	// Check lists what is wrong with the provider; empty when it is reachable and complete.
	Check(ctx context.Context, p Provider) []string
}

// SAML is SAML 2.0 against a provider. The default (crewjam/saml) sends the AuthnRequest with the
// redirect binding, consumes the Response with the POST binding and checks it strictly; a host or
// a test passes its own in Config.SAML.
type SAML interface {
	// AuthnRequest is the request id (InResponseTo) and where to send the browser.
	AuthnRequest(p Provider, sp SP, relayState string) (id, url string, err error)
	// Consume validates a base64 SAMLResponse; requestID is the AuthnRequest it must answer, ""
	// for an IdP-initiated response.
	Consume(p Provider, sp SP, samlResponse, requestID string) (Identity, error)
	// Metadata is the SP metadata XML.
	Metadata(p Provider, sp SP) ([]byte, error)
	// LogoutURL is the IdP's single logout carrying a LogoutRequest for nameID, "" when the
	// provider has none.
	LogoutURL(p Provider, sp SP, nameID, sessionIndex, relayState string) (string, error)
	// ConsumeLogoutRequest validates an IdP's LogoutRequest, which must be signed (the redirect
	// binding's query signature or an enveloped signature).
	ConsumeLogoutRequest(p Provider, sp SP, m LogoutMessage) (LogoutRequest, error)
	// LogoutResponseURL is the IdP's single logout carrying the LogoutResponse, "" when the
	// provider has none.
	LogoutResponseURL(p Provider, sp SP, inResponseTo, relayState string) (string, error)
	// Check lists what is wrong with the provider's configuration; empty when it is complete.
	Check(p Provider, sp SP) []string
}

// LogoutMessage is an IdP's LogoutRequest as received at /sso/slo/{providerId}.
type LogoutMessage struct {
	SAMLRequest, RelayState, SigAlg, Signature string
	// Redirect is the redirect binding (GET, deflated); RawQuery is then the query string as
	// received, which the query signature covers.
	Redirect bool
	RawQuery string
}

// LogoutRequest is a validated IdP LogoutRequest.
type LogoutRequest struct {
	ID             string
	NameID         string
	SessionIndexes []string
}
