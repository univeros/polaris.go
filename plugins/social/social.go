// Package social is the social sign-in plugin: OAuth 2.0 and OpenID
// Connect sign-in and sign-up through Google, Apple, Microsoft, GitHub and fifteen more providers,
// or any other OAuth 2 server; account linking under a policy; Google One Tap; provider tokens on
// the user's behalf (stored encrypted, refreshed when expiring); and an OAuth proxy so preview and
// local origins sign in through the stable origin registered at the providers.
//
//	sp := social.New(social.Config{
//		BaseURL:      "https://app.example.com/auth", // where Polaris is mounted, prefix included
//		RedirectURIs: []string{"https://app.example.com/signed-in"},
//		Providers: map[string]social.Provider{
//			"google": {ClientID: "…", ClientSecret: "…"},
//			"github": {ClientID: "…", ClientSecret: "…"},
//		},
//	})
//	p, err := polaris.New(polaris.Config{…, Plugins: []polaris.Plugin{audit.New(audit.Config{}), sp}})
//
// The provider's callback is BaseURL + "/social/<provider>/callback". The sign-in: the application
// calls POST /social/{provider}/start, sends the browser to the answered url, the provider comes
// back to the callback, which redirects to the redirect URI with a one-minute code and the state;
// the application checks the state and exchanges the code at POST /social/exchange for core's login
// envelope (amr ["social:<provider>"]) or core's mfa_required ticket.
//
// With the audit plugin registered, every sign-in, link and refusal is a social.* audit event.
package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.social.*.
const ID = "social"

// Defaults.
const (
	DefaultStateTTL = 10 * time.Minute
	codeTTL         = time.Minute
	keySetTTL       = time.Hour
)

// Config configures the plugin. BaseURL, at least one provider and, for a sign-in to end
// anywhere, RedirectURIs are required; every other field's zero value is its default.
type Config struct {
	// BaseURL is where Polaris is mounted, prefix included ("https://app.example.com/auth"); the
	// callback registered at each provider is BaseURL + "/social/<provider>/callback".
	BaseURL string
	// Providers maps a provider id ("google", "github", "acme") to its credentials. An id of the
	// catalog (Catalog) needs only ClientID and ClientSecret; any other id needs Definition or Issuer.
	Providers map[string]Provider
	// RedirectURIs are the exact application URLs a sign-in may end on; the first is the default.
	RedirectURIs []string
	// TrustedProviders link a verified provider email to the existing user with that email by
	// themselves. nil means google and apple; an empty, non-nil list trusts none. Never trust a
	// provider whose profile counts any returned email as verified (facebook, x, notion, kick, or
	// a Definition whose Profile does): anyone who can put a victim's address on such an account
	// would be linked to, and sign in as, the victim's existing user.
	TrustedProviders []string
	// AllowDifferentEmails lists the providers that may be linked from a session with an email
	// other than the account's.
	AllowDifferentEmails []string
	// DisableSignUp refuses a sign-in that matches no user instead of creating one.
	DisableSignUp bool
	// SkipMFA lets a social sign-in past core's MFA gate (a user with a confirmed factor gets a
	// session at once). Off by default: the gate applies as after a password.
	SkipMFA bool
	// Proxy is the stable origin registered at the providers ("https://auth.example.com") when
	// this deployment (a preview, localhost) is mounted elsewhere; both share APP_KEY.
	Proxy string
	// StateTTL is how long a started sign-in waits for its callback; zero means 10 minutes.
	StateTTL time.Duration
	// HTTPClient talks to the providers (token, userinfo, discovery, key sets). Default: a client
	// with a 10-second timeout. Redirects are never followed, whatever the client.
	HTTPClient *http.Client
}

// Provider is one provider's credentials and, for a provider outside the catalog, what it is.
type Provider struct {
	ClientID     string
	ClientSecret string
	// Tenant is Microsoft's tenant: common (default), organizations, consumers or a tenant id.
	Tenant string
	// TeamID, KeyID and PrivateKey (PEM, the .p8 file) sign Apple's client secret.
	TeamID, KeyID, PrivateKey string
	// Issuer makes any OpenID Connect provider usable through discovery at first use.
	Issuer string
	// Name and Scopes complete a discovered provider (default scopes: openid email profile).
	Name   string
	Scopes []string
	// Definition describes any other OAuth 2 server (Better Auth's GenericOAuth).
	Definition *Definition
}

type settings struct {
	baseURL              string
	proxy                string
	redirectURIs         []string
	trusted              []string
	allowDifferentEmails []string
	signUp, respectMFA   bool
	stateTTL             time.Duration
}

var (
	absoluteURL = regexp.MustCompile(`^https?://[^/]+`)
	originOnly  = regexp.MustCompile(`^https?://[^/]+$`)
)

func (c Config) settings() (settings, error) {
	var errs []error
	if !absoluteURL.MatchString(c.BaseURL) {
		errs = append(errs, fmt.Errorf("social: Config.BaseURL is %q: pass the absolute http(s) URL Polaris is mounted at, prefix included", c.BaseURL))
	}
	proxy := strings.TrimRight(c.Proxy, "/")
	if c.Proxy != "" && !originOnly.MatchString(proxy) {
		errs = append(errs, fmt.Errorf("social: Config.Proxy is %q: pass an origin, such as https://auth.example.com", c.Proxy))
	}
	if c.StateTTL < 0 {
		errs = append(errs, errors.New("social: Config.StateTTL is negative: pass a positive duration or zero for 10 minutes"))
	}
	s := settings{
		baseURL: strings.TrimRight(c.BaseURL, "/"), proxy: proxy, redirectURIs: slices.Clone(c.RedirectURIs),
		trusted: c.TrustedProviders, allowDifferentEmails: slices.Clone(c.AllowDifferentEmails),
		signUp: !c.DisableSignUp, respectMFA: !c.SkipMFA, stateTTL: c.StateTTL,
	}
	if s.trusted == nil {
		s.trusted = []string{"google", "apple"}
	}
	if s.stateTTL == 0 {
		s.stateTTL = DefaultStateTTL
	}
	return s, errors.Join(errs...)
}

func (s settings) callbackURL(provider string) string {
	return s.baseURL + "/social/" + provider + "/callback"
}

// proxied reports whether this deployment starts its flows through the proxy.
func (s settings) proxied() bool { return s.proxy != "" && origin(s.baseURL) != s.proxy }

// origin is scheme://host[:port] of u, written as given (no case folding, no default port
// dropped); "" when u does not parse.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Plugin is the social plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg       Config
	settings  settings
	providers map[string]*provider
	out       *outbound
	g         *wiring.Graph
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_social_account.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (declared in internal/apispec/api/social).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/social")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// AuditNames adds the social.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string {
	return map[string]string{
		EventSignedIn:       "A user signed in through a provider (provider, account id, linked just now)",
		EventSignedUp:       "A provider sign-in created the user (provider, account id)",
		EventLinked:         "A provider account was linked to the user (provider, account id)",
		EventUnlinked:       "A provider account was unlinked from the user (provider, account id)",
		EventTokenRefreshed: "A provider token was refreshed for the user (provider)",
		EventRejected:       "A provider sign-in was refused (provider, reason)",
	}
}

// Init validates the configuration and builds the providers.
func (p *Plugin) Init(g *wiring.Graph) error {
	s, err := p.cfg.settings()
	if len(p.cfg.Providers) == 0 {
		err = errors.Join(err, errors.New("social: Config.Providers is empty: configure at least one provider, such as \"google\": {ClientID, ClientSecret}"))
	}
	p.g, p.settings = g, s
	p.out = &outbound{http: noRedirects(p.cfg.HTTPClient), cache: g.Cache(), clock: g.Clock()}
	p.providers = map[string]*provider{}
	for id, conf := range p.cfg.Providers {
		prov, perr := buildProvider(id, conf, p.out)
		err = errors.Join(err, perr)
		p.providers[id] = prov
	}
	return err
}

// Endpoints serves the /social routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Listeners erase an erased user's provider accounts (their email, profile and tokens).
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		if d, ok := e.(event.UserDeleted); ok {
			if err := p.unlinkAll(ctx, d.UserID); err != nil {
				p.g.Logger().ErrorContext(ctx, "social: accounts not erased", "user_id", d.UserID, "reason", err.Error())
			}
		}
	}}
}

// buildProvider resolves one configured provider: Apple and GitHub by id, then a host's
// Definition, an Issuer (discovered at first use), or the catalog.
func buildProvider(id string, c Provider, out *outbound) (*provider, error) {
	field := fmt.Sprintf("social: Config.Providers[%q]", id)
	if c.ClientID == "" {
		return nil, fmt.Errorf("%s.ClientID is required", field)
	}
	prov := &provider{id: id, clientID: c.ClientID, secret: c.ClientSecret, out: out}
	switch {
	case id == "apple":
		prov.def, _ = catalog(id, "")
		key, err := parseECKey(c.PrivateKey)
		if err != nil || c.TeamID == "" || c.KeyID == "" {
			return nil, fmt.Errorf("%s: Apple needs TeamID, KeyID and PrivateKey (the .p8 PEM of a P-256 key)", field)
		}
		prov.apple, prov.teamID, prov.keyID, prov.secret = key, c.TeamID, c.KeyID, ""
	case id == "github":
		prov.def, _ = catalog(id, "")
		prov.github = true
	case c.Definition != nil:
		d := *c.Definition
		if d.AuthorizationURL == "" || d.TokenURL == "" || d.Profile == nil {
			return nil, fmt.Errorf("%s.Definition needs AuthorizationURL, TokenURL and Profile", field)
		}
		prov.def = d
	case c.Issuer != "":
		prov.discover = &discovery{issuer: strings.TrimRight(c.Issuer, "/"), name: c.Name, scopes: c.Scopes}
	default:
		def, ok := catalog(id, c.Tenant)
		if !ok {
			return nil, fmt.Errorf("%s: %q is not in the catalog (%s): pass a Definition or an Issuer", field, id, strings.Join(Catalog, ", "))
		}
		prov.def = def
	}
	if prov.def.Name == "" && prov.discover == nil {
		prov.def.Name = id
	}
	return prov, nil
}

func parseECKey(pemText string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an EC key")
	}
	return ec, nil
}

// noRedirects returns a copy of c (or the default) that never follows a redirect: a token or
// profile request must reach the endpoint configured, never one a response names.
func noRedirects(c *http.Client) *http.Client {
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}
