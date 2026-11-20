package oauth

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// DPoPMode says whether access tokens may, must or cannot be bound to a client key (RFC 9449).
type DPoPMode string

// The DPoP modes; the zero value is DPoPOptional.
const (
	DPoPOff      DPoPMode = "off"
	DPoPOptional DPoPMode = "optional"
	DPoPRequired DPoPMode = "required"
)

// Config configures the provider. Every field is optional; the zero value is upstream's default
// configuration (DPoP optional, metadata documents accepted, registration off, no device flow).
type Config struct {
	// BaseURL is where Polaris is mounted, prefix included ("https://app.example/auth"): the
	// endpoints the discovery documents advertise derive from it. Default: Auth.Issuer followed by
	// the graph's PathPrefix.
	BaseURL string
	// ConsentURL is the host's consent page; browsers are sent there with ?request=<id>. Empty: the
	// authorization endpoint answers JSON only.
	ConsentURL string
	// DeviceURL is the host's device page (verification_uri). Empty turns the device flow off.
	DeviceURL string
	// HTTPClient fetches client ID metadata documents and jwks_uri key sets. Default: a client that
	// refuses to connect to non-public addresses, 10 s timeout, no proxy. Redirects are never
	// followed, whichever client is used.
	HTTPClient *http.Client

	AccessTokenTTL  time.Duration // default 1 h
	RefreshTokenTTL time.Duration // default 30 days
	CodeTTL         time.Duration // authorization codes; default 10 min
	DeviceCodeTTL   time.Duration // default 30 min
	CIBATTL         time.Duration // backchannel requests; default 10 min
	// PollInterval is the advertised and enforced interval between device or backchannel polls;
	// default 5 s. Negative turns the throttle off (interval 0).
	PollInterval time.Duration

	// DynamicRegistration turns on POST /oauth2/register (RFC 7591) for anyone.
	DynamicRegistration bool
	// DisableClientIDMetadata refuses https client ids (client ID metadata documents).
	DisableClientIDMetadata bool
	// DPoP is off, optional (default) or required.
	DPoP DPoPMode
	// Scopes are extra scopes (name → description) beyond the permission catalog and the OpenID ones.
	Scopes map[string]string
	// TrustedClients are client ids whose users are not asked for consent.
	TrustedClients []string
	// Operators resolves who calls the /admin/oauth routes (the admin plugin's grants and API
	// keys): nil, nil for nobody. Default: a session whose user holds the superadmin role is an
	// instance-wide owner.
	Operators func(r *http.Request) (*Operator, error)
	// Audiences are further aud values that name this server (the "<BaseURL>/mcp" resource of
	// polaris/mcp), accepted by the bearer resolver as the issuer is.
	Audiences []string
}

// settings is the validated configuration, lifetimes in whole seconds as upstream stores them.
type settings struct {
	baseURL, consentURL, deviceURL                     string
	accessTTL, refreshTTL, codeTTL, deviceTTL, cibaTTL int
	pollInterval                                       int
	dynamicRegistration, clientIDMetadata              bool
	dpop                                               DPoPMode
	scopes                                             map[string]string
	trustedClients, audiences                          []string
	httpClient                                         *http.Client
	operators                                          func(r *http.Request) (*Operator, error)
}

var (
	baseURLPattern  = regexp.MustCompile(`^https?://[^/\s]+`)
	pageURLPattern  = regexp.MustCompile(`^https?://[^\s?]+$`)
	scopeNameFormat = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
)

// resolve validates cfg and fills the defaults; every problem is reported at once, naming the fix.
func (cfg Config) resolve() (settings, error) {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf("oauth: "+format, args...)) }
	s := settings{
		baseURL:             strings.TrimRight(cfg.BaseURL, "/"),
		consentURL:          strings.TrimRight(cfg.ConsentURL, "/"),
		deviceURL:           strings.TrimRight(cfg.DeviceURL, "/"),
		dynamicRegistration: cfg.DynamicRegistration,
		clientIDMetadata:    !cfg.DisableClientIDMetadata,
		dpop:                cfg.DPoP,
		scopes:              cfg.Scopes,
		trustedClients:      cfg.TrustedClients,
		audiences:           cfg.Audiences,
		httpClient:          noRedirects(cfg.HTTPClient),
		operators:           cfg.Operators,
	}
	if cfg.BaseURL != "" && !baseURLPattern.MatchString(cfg.BaseURL) {
		bad("Config.BaseURL %q must be an absolute http(s) URL, where Polaris is mounted", cfg.BaseURL)
	}
	for name, u := range map[string]string{"ConsentURL": cfg.ConsentURL, "DeviceURL": cfg.DeviceURL} {
		if u != "" && !pageURLPattern.MatchString(u) {
			bad("Config.%s %q must be an absolute http(s) URL without a query", name, u)
		}
	}
	if s.dpop == "" {
		s.dpop = DPoPOptional
	}
	if s.dpop != DPoPOff && s.dpop != DPoPOptional && s.dpop != DPoPRequired {
		bad("Config.DPoP must be oauth.DPoPOff, DPoPOptional or DPoPRequired, got %q", cfg.DPoP)
	}
	lifetimes := []struct {
		name string
		got  time.Duration
		def  time.Duration
		dst  *int
	}{
		{"AccessTokenTTL", cfg.AccessTokenTTL, time.Hour, &s.accessTTL},
		{"RefreshTokenTTL", cfg.RefreshTokenTTL, 30 * 24 * time.Hour, &s.refreshTTL},
		{"CodeTTL", cfg.CodeTTL, 10 * time.Minute, &s.codeTTL},
		{"DeviceCodeTTL", cfg.DeviceCodeTTL, 30 * time.Minute, &s.deviceTTL},
		{"CIBATTL", cfg.CIBATTL, 10 * time.Minute, &s.cibaTTL},
	}
	for _, l := range lifetimes {
		d := l.got
		if d == 0 {
			d = l.def
		}
		if d < time.Second || d%time.Second != 0 {
			bad("Config.%s must be a whole number of seconds, at least one, got %s", l.name, l.got)
		}
		*l.dst = int(d / time.Second)
	}
	switch {
	case cfg.PollInterval == 0:
		s.pollInterval = 5
	case cfg.PollInterval < 0:
		s.pollInterval = 0
	case cfg.PollInterval%time.Second != 0:
		bad("Config.PollInterval must be a whole number of seconds, got %s", cfg.PollInterval)
	default:
		s.pollInterval = int(cfg.PollInterval / time.Second)
	}
	for name := range cfg.Scopes {
		if !scopeNameFormat.MatchString(name) {
			bad("Config.Scopes: %q is not a scope name (printable characters without a space, a quote or a backslash, RFC 6749 §3.3)", name)
		}
	}
	return s, errors.Join(errs...)
}

// noRedirects returns a copy of c (or the guarded default) that never follows a redirect: a
// redirect would lead a validated public URL to a host the validation never saw.
func noRedirects(c *http.Client) *http.Client {
	if c == nil {
		c = guardedClient()
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}
