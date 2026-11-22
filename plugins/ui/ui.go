// Package ui is the pages plugin: server-rendered sign-in, two-step verification, sign-up, email
// verification, forgot and reset password, sign-out and, with plugins/oauth, the OAuth consent and
// device pages. Plain HTML forms (html/template, one embedded stylesheet, no JavaScript), served
// under /auth/ui by p.Handler():
//
//	web := ui.New(ui.Config{AppName: "Acme", AfterSignIn: "/dashboard"})
//	cfg, err := polaris.FromEnv(db, web)
//	p, err := polaris.New(cfg)
//	mux.Handle("/", p.Handler())                                       // GET /auth/ui/sign-in, …
//	mux.Handle("GET /dashboard", web.RequireSignIn(p.Protect(dashboard))) // signed-out browsers go to sign-in
//
// Every form posts to a page that runs the matching JSON route in process, through the same
// pipeline as p.Handler() (rate limits, sentinel, MFA gate, events, audit, anti-enumeration
// answers). A sign-in keeps core's session in two HttpOnly cookies: the access token, which
// p.Protect and every bearer route accept from a browser, and the refresh token, which only the
// pages read.
package ui

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id.
const ID = "ui"

// Prefix is where the pages are served, under polaris.Config.PathPrefix.
const Prefix = "/auth/ui"

// Config themes the pages and says where a browser goes after signing in and out. Every field is
// optional.
type Config struct {
	// AppName is shown in the header and the page titles; default "Account".
	AppName string
	// LogoURL is an image shown beside AppName: a same-origin path ("/static/logo.svg") or an
	// https URL (its origin joins the pages' img-src).
	LogoURL string
	// PrimaryColor colours buttons, links and focus rings ("#rrggbb" or "#rgb"); PrimaryColorDark
	// replaces it in dark mode (default PrimaryColor when set, else the built-in shades).
	PrimaryColor, PrimaryColorDark string
	// TermsURL and PrivacyURL are linked in the footer when set.
	TermsURL, PrivacyURL string
	// AfterSignIn is where a sign-in without return_to ends; default "/".
	AfterSignIn string
	// AfterSignOut is where a sign-out ends; default the sign-in page.
	AfterSignOut string
	// RedirectOrigins are origins besides the request's own ("https://app.example.com") a
	// return_to, AfterSignIn or AfterSignOut may point at. Anything else falls back to AfterSignIn.
	RedirectOrigins []string
	// BaseURL is the public URL browsers use for Polaris, prefix included
	// ("https://app.example.com/api"). Its origin is the pages' only origin: a form is accepted
	// only when the browser's Origin header names it (the Host header and r.TLS are never read,
	// so a TLS-terminating proxy needs nothing), sessions are issued only when it is https (or
	// loopback http in development), and the email links and OAuth pages derive from it.
	// Default: AUTH_ISSUER + Config.PathPrefix.
	BaseURL string
	// Templates overrides files by name: "layout.html", "sign-in.html", "mfa.html",
	// "sign-up.html", "check-email.html", "verify.html", "forgot.html", "reset.html",
	// "sign-out.html", "consent.html", "device.html", "message.html" and "style.css". A page
	// defines {{define "content"}}; the layout renders it. Files it lacks keep the built-in ones.
	Templates fs.FS
	// Messages overrides the texts per locale ("en", "pt", "pt-br"): key to text, the keys of
	// English. A locale is picked from Accept-Language; a key it lacks keeps the English text.
	Messages map[string]map[string]string
}

// Plugin is the pages plugin. Its pages exist once polaris.New has run.
type Plugin struct {
	cfg Config
	g   *wiring.Graph

	base     string // the pages' URL path: PathPrefix + Prefix
	origin   string // the pages' one origin, from BaseURL: what Origin headers must say
	secure   bool   // sessions may be issued on origin (https, or loopback http)
	pages    map[string]*template.Template
	css      []byte
	catalogs map[string]map[string]string
	origins  []string // RedirectOrigins, normalised
	imgSrc   string   // the logo's CSP source

	once     sync.Once
	inner    http.Handler
	innerErr error
}

var (
	_ wiring.Initializer            = (*Plugin)(nil)
	_ wiring.HandlerProvider        = (*Plugin)(nil)
	_ wiring.BearerResolverProvider = (*Plugin)(nil)
)

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

var (
	colorPattern  = regexp.MustCompile(`^#(?:[0-9a-fA-F]{3}){1,2}$`)
	originPattern = regexp.MustCompile(`^https?://[a-z0-9.-]+(?::[0-9]{1,5})?$`)
	// schemePattern is a native app's private-use redirect scheme ("com.example.app"); never a
	// scheme that runs or embeds content.
	schemePattern = regexp.MustCompile(`^(?:[a-z][a-z0-9+-]*\.)+[a-z0-9+-]+$`)
)

// Init validates the configuration and parses the templates.
func (p *Plugin) Init(g *wiring.Graph) error {
	p.g = g
	p.base = strings.TrimRight(g.Config().PathPrefix, "/") + Prefix
	if p.cfg.AppName == "" {
		p.cfg.AppName = "Account"
	}
	if p.origin = originOf(p.baseURL(g)); p.origin == "" {
		return fmt.Errorf(`ui: the pages' base URL %q is not an absolute http(s) URL: set ui.Config.BaseURL (or AUTH_ISSUER) to the public URL browsers use, "https://app.example.com"`, p.baseURL(g))
	}
	if p.secure = mayIssue(p.origin); !p.secure {
		g.Logger().Warn("ui: the pages' origin is plain http and not loopback: they will refuse every form; set ui.Config.BaseURL to the https URL browsers use", "origin", p.origin)
	}
	for _, o := range p.cfg.RedirectOrigins {
		if !originPattern.MatchString(o) {
			return fmt.Errorf(`ui: Config.RedirectOrigins holds %q; each must be an origin in lower case, "https://host[:port]", no path`, o)
		}
		p.origins = append(p.origins, o)
	}
	if p.cfg.AfterSignIn == "" {
		p.cfg.AfterSignIn = "/"
	}
	if p.cfg.AfterSignOut == "" {
		p.cfg.AfterSignOut = p.base + "/sign-in"
	}
	for name, target := range map[string]string{"AfterSignIn": p.cfg.AfterSignIn, "AfterSignOut": p.cfg.AfterSignOut} {
		if !p.allowed(target) {
			return fmt.Errorf(`ui: Config.%s is %q; use a path ("/dashboard") or a URL on one of Config.RedirectOrigins`, name, target)
		}
	}
	for name, c := range map[string]string{"PrimaryColor": p.cfg.PrimaryColor, "PrimaryColorDark": p.cfg.PrimaryColorDark} {
		if c != "" && !colorPattern.MatchString(c) {
			return fmt.Errorf(`ui: Config.%s is %q; use a hex colour, "#3b5bdb"`, name, c)
		}
	}
	if err := p.logo(); err != nil {
		return err
	}
	for name, u := range map[string]string{"TermsURL": p.cfg.TermsURL, "PrivacyURL": p.cfg.PrivacyURL} {
		if parsed, err := url.Parse(u); u != "" && (err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http" && !isPath(u))) {
			return fmt.Errorf("ui: Config.%s is %q; use an http(s) URL or a path", name, u)
		}
	}
	p.catalogs = catalogs(p.cfg.Messages)
	return p.parse()
}

// logo validates LogoURL and derives its CSP source.
func (p *Plugin) logo() error {
	p.imgSrc = "'self'"
	switch u, err := url.Parse(p.cfg.LogoURL); {
	case p.cfg.LogoURL == "" || isPath(p.cfg.LogoURL):
	case err == nil && u.Scheme == "https" && originPattern.MatchString("https://"+strings.ToLower(u.Host)):
		p.imgSrc += " https://" + strings.ToLower(u.Host)
	default:
		return fmt.Errorf(`ui: Config.LogoURL is %q; use a path ("/logo.svg") or an https URL`, p.cfg.LogoURL)
	}
	return nil
}

// Handler implements wiring.HandlerProvider: the pages, under Prefix.
func (p *Plugin) Handler(*wiring.Graph) (string, http.Handler) { return Prefix, p.routes() }

// OAuthPages implements oauth.PageProvider: plugins/oauth sends browsers to these pages when its
// ConsentURL and DeviceURL are empty.
func (p *Plugin) OAuthPages(g *wiring.Graph) (consentURL, deviceURL string) {
	base := p.baseURL(g)
	return base + "/consent", base + "/device"
}

// baseURL is the pages' absolute URL.
func (p *Plugin) baseURL(g *wiring.Graph) string {
	if p.cfg.BaseURL != "" {
		return strings.TrimRight(p.cfg.BaseURL, "/") + Prefix
	}
	return strings.TrimRight(g.Auth().Issuer, "/") + strings.TrimRight(g.Config().PathPrefix, "/") + Prefix
}

// VerifyEmailURL is the link for a verification email: the page whose button verifies token
// (opening the link verifies nothing: mail scanners follow links). A Mailer
// builds it from the "token" of notify.TemplateVerifyEmail.
func (p *Plugin) VerifyEmailURL(token string) string {
	return p.baseURL(p.g) + "/verify?token=" + url.QueryEscape(token)
}

// ResetPasswordURL is the link for a password-reset email: the page that sets a new password
// with token. A Mailer builds it from the "token" of notify.TemplatePasswordReset.
func (p *Plugin) ResetPasswordURL(token string) string {
	return p.baseURL(p.g) + "/reset?token=" + url.QueryEscape(token)
}

// RequireSignIn sends a browser without a live session to sign in, then back: wrap a p.Protect
// handler with it. A GET or HEAD that next answers 401 becomes a 303 to the pages, which renew the
// session from its refresh cookie or ask the user to sign in, then return to the same URL. Other
// methods and statuses pass through.
func (p *Plugin) RequireSignIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(&signInRedirect{ResponseWriter: w, to: p.base + "/refresh?return_to=" + url.QueryEscape(r.URL.RequestURI())}, r)
	})
}

// signInRedirect turns a 401 into a 303 to the sign-in pages and drops its body.
type signInRedirect struct {
	http.ResponseWriter
	to         string
	redirected bool
}

func (w *signInRedirect) WriteHeader(code int) {
	if code != http.StatusUnauthorized {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.redirected = true
	h := w.Header()
	h.Del("Content-Type")
	h.Del("WWW-Authenticate")
	h.Set("Location", w.to)
	h.Set("Cache-Control", "no-store")
	w.ResponseWriter.WriteHeader(http.StatusSeeOther)
}

func (w *signInRedirect) Write(b []byte) (int, error) {
	if w.redirected {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
