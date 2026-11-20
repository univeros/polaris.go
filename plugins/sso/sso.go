package sso

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/univeros/polaris-go/internal/netguard"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/internal/upstream"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/wiring"
)

// ID is the plugin id; its routes read polaris.sso.*.
const ID = "sso"

var absoluteURL = regexp.MustCompile(`^https?://[^/]+`)

// Config configures the plugin; the zero value works.
type Config struct {
	// BaseURL is where Polaris is mounted, prefix included ("https://app.example.com/auth"): the
	// SP entity id, the assertion consumer, single-logout and metadata URLs and the OIDC redirect
	// URI derive from it. Default: the issuer (Auth.Issuer) followed by the path prefix.
	BaseURL string
	// HTTPClient talks to the OIDC providers (discovery, token endpoint, JWKS) and fetches the
	// domains' well-known files; redirects are never followed. Default: a client that connects
	// to public addresses only (an organization admin names those hosts).
	HTTPClient *http.Client
	// OIDC, SAML and Domains replace the protocol implementations (tests use fakes). Defaults:
	// HTTPOIDC, DefaultSAML, DNSHTTPSVerifier.
	OIDC    OIDC
	SAML    SAML
	Domains DomainVerifier
	// SPCertificate and SPPrivateKey (PEM, RSA), both or neither: sign the AuthnRequests and logout
	// messages and are published in the SP metadata.
	SPCertificate string
	SPPrivateKey  string
}

// Plugin is the SSO plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg       Config
	g         *wiring.Graph
	sp        SP
	providers *Providers
	domains   *Domains
	oidc      OIDC
	saml      SAML
	verifier  DomainVerifier
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_sso_provider and polaris_sso_domain.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's 20 routes (upstream api/sso).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(upstream.API, "api/sso")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// AuditNames adds the sso.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string { return auditNames }

// Init builds the plugin's services.
func (p *Plugin) Init(g *wiring.Graph) error {
	base := p.cfg.BaseURL
	if base == "" {
		base = strings.TrimRight(g.Auth().Issuer, "/") + "/" + strings.Trim(g.Config().PathPrefix, "/")
	}
	if !absoluteURL.MatchString(base) {
		return fmt.Errorf("sso: Config.BaseURL is %q: set it to the absolute http(s) URL where Polaris is mounted (\"https://app.example.com/auth\")", base)
	}
	sp, err := spOf(strings.TrimRight(base, "/"), p.cfg.SPCertificate, p.cfg.SPPrivateKey)
	if err != nil {
		return err
	}
	client := netguard.NoRedirects(p.cfg.HTTPClient)
	p.g, p.sp = g, sp
	p.providers = &Providers{db: g.DB(), enc: g.Encrypter(), clock: g.Clock()}
	p.domains = &Domains{db: g.DB(), clock: g.Clock()}
	p.oidc, p.saml, p.verifier = p.cfg.OIDC, p.cfg.SAML, p.cfg.Domains
	if p.oidc == nil {
		p.oidc = &HTTPOIDC{HTTP: client, Cache: g.Cache(), Clock: g.Clock()}
	}
	if p.saml == nil {
		p.saml = DefaultSAML{Clock: g.Clock()}
	}
	if p.verifier == nil {
		p.verifier = DNSHTTPSVerifier{HTTP: client}
	}
	return nil
}

// spOf parses the optional SP key pair.
func spOf(base, certPEM, keyPEM string) (SP, error) {
	sp := SP{BaseURL: base}
	if certPEM == "" && keyPEM == "" {
		return sp, nil
	}
	fix := "sso: Config.SPCertificate and Config.SPPrivateKey must both be PEM (an X.509 certificate and its RSA key): "
	cb, _ := pem.Decode([]byte(certPEM))
	kb, _ := pem.Decode([]byte(keyPEM))
	if cb == nil || kb == nil {
		return sp, errors.New(fix + "one is missing or not PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return sp, errors.New(fix + err.Error())
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		key, _ = k.(*rsa.PrivateKey)
	} else if key, err = x509.ParsePKCS1PrivateKey(kb.Bytes); err != nil {
		return sp, errors.New(fix + err.Error())
	}
	if key == nil || !key.PublicKey.Equal(cert.PublicKey) {
		return sp, errors.New(fix + "the key is not RSA or is not the certificate's")
	}
	sp.Certificate, sp.Key = cert, key
	return sp, nil
}

// SP is the service provider side: the URLs an IdP is configured with.
func (p *Plugin) SP() SP { return p.sp }

// Providers is the provider store: create and manage providers from code.
func (p *Plugin) Providers() *Providers { return p.providers }

// Domains is the domain store.
func (p *Plugin) Domains() *Domains { return p.domains }

// DomainVerified reports whether domain (case-insensitive, the exact host) is verified for the
// organization. Other plugins (scim) reach it by type-asserting g.Plugin("sso").
func (p *Plugin) DomainVerified(ctx context.Context, organizationID, domain string) (bool, error) {
	d, verified, err := p.domains.Verified(ctx, strings.ToLower(domain))
	return verified && d.OrganizationID == organizationID, err
}

// Endpoints serves the 20 sso routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Middleware refuses an organization route outside the caller's active organization before
// core's permission check.
func (*Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{activeOrganization}
}

// Of returns the sso plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}
