package ui

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// The cookies. Every one is HttpOnly and Secure; the __Host- ones are Path=/ and bound to this
// exact origin (a sibling subdomain cannot set them).
const (
	// sessionCookie carries the access token to p.Protect and the bearer routes (SameSite=Lax:
	// a link from an email opens a signed-in page).
	sessionCookie = "__Host-polaris_session"
	// refreshCookie carries the refresh token to the pages only (Path=<pages>).
	refreshCookie = "__Secure-polaris_ui_refresh"
	// mfaCookie holds the login_mfa ticket between the password and the code (Path=<pages>).
	mfaCookie = "__Secure-polaris_ui_mfa"
	// csrfCookie is the random half of the signed double-submit token (SameSite=Strict).
	csrfCookie = "__Host-polaris_csrf"
)

// csrfContext keys the CSRF token's HMAC (core's pepper, derived from APP_KEY).
const csrfContext = "ui.csrf"

// maxRedirect bounds a return_to.
const maxRedirect = 2048

func (p *Plugin) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration, sameSite http.SameSite) {
	path := "/"
	if !strings.HasPrefix(name, "__Host-") {
		path = p.base
	}
	c := &http.Cookie{Name: name, Value: value, Path: path, MaxAge: int(maxAge.Seconds()), HttpOnly: true, Secure: true, SameSite: sameSite} //nolint:gosec // Secure and HttpOnly always; SameSite is Lax or Strict per cookie (G124)
	if maxAge < 0 {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func (p *Plugin) clearCookie(w http.ResponseWriter, name string) {
	p.setCookie(w, name, "", -1, http.SameSiteLaxMode)
}

func cookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// csrfToken is the token the forms of this response carry: the HMAC of the CSRF cookie's nonce,
// set now when the browser has none.
func (p *Plugin) csrfToken(w http.ResponseWriter, r *http.Request) string {
	nonce := cookie(r, csrfCookie)
	if len(nonce) != 64 || !isHex(nonce) {
		b := make([]byte, 32)
		_, _ = rand.Read(b) // never fails (crypto/rand)
		nonce = hex.EncodeToString(b)
		p.setCookie(w, csrfCookie, nonce, 0, http.SameSiteStrictMode)
	}
	return p.g.Pepper().Hash(csrfContext, nonce)
}

// csrfOK is the check of every form post: the browser says it comes from this origin (when it says
// anything), and the form's token is the HMAC of the cookie's nonce, compared in constant time.
func (p *Plugin) csrfOK(r *http.Request) bool {
	nonce := cookie(r, csrfCookie)
	return p.sameOrigin(r, false) && nonce != "" && p.g.Pepper().Matches(csrfContext, nonce, r.PostFormValue("csrf"))
}

// sameOrigin reports whether Origin (or, without one, Sec-Fetch-Site) names this origin. Without
// either header it answers !strict.
func (p *Plugin) sameOrigin(r *http.Request, strict bool) bool {
	if values := r.Header.Values("Origin"); len(values) > 0 {
		return len(values) == 1 && strings.ToLower(values[0]) == requestOrigin(r)
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	return !strict
}

// requestOrigin is scheme://host[:port] of r, the port omitted when it is the scheme's default.
// The scheme is https exactly when r.TLS is set, as in core's cookie delivery.
func requestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := strings.ToLower(r.Host)
	if h, port, err := net.SplitHostPort(host); err == nil && (scheme == "https" && port == "443" || scheme == "http" && port == "80") {
		host = h
		if strings.Contains(h, ":") {
			host = "[" + h + "]"
		}
	}
	return scheme + "://" + host
}

// secureTransport reports whether a session may be issued over r: TLS, or a loopback host in
// development (browsers keep Secure cookies for http://localhost).
func secureTransport(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
}

// isPath reports whether s is a same-origin absolute path: "/x", never "//host" or "/\host".
func isPath(s string) bool {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.ContainsAny(s, "\\") || hasControl(s) {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil
}

func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f })
}

// allowed reports whether a redirect may go to target: a same-origin path, or an http(s) URL on
// origin or one of Config.RedirectOrigins.
func (p *Plugin) allowed(target, origin string) bool {
	if target == "" || len(target) > maxRedirect {
		return false
	}
	if isPath(target) {
		return true
	}
	u, err := url.Parse(target)
	if err != nil || u.User != nil || hasControl(target) || strings.ContainsAny(target, "\\") || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}
	o := u.Scheme + "://" + strings.ToLower(u.Host)
	return o == origin || slices.Contains(p.origins, o)
}

// target is where a flow ends: return_to when allowed, else Config.AfterSignIn.
func (p *Plugin) target(r *http.Request, returnTo string) string {
	if p.allowed(returnTo, requestOrigin(r)) {
		return returnTo
	}
	return p.cfg.AfterSignIn
}

// headers are set on every page: no caching, a strict CSP without inline script or style, no
// framing, no referrer (reset tokens ride in URLs). formTargets are origins a form on the page may
// end on through a redirect (the OAuth client's redirect URI).
func (p *Plugin) headers(w http.ResponseWriter, formTargets ...string) {
	forms := append(append([]string{"'self'"}, p.origins...), formTargets...)
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src "+p.imgSrc+
		"; form-action "+strings.Join(forms, " ")+"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
}

// cspSource is the CSP source of an OAuth redirect URI: its origin, or "scheme:" for a native
// app's private-use scheme; "" when it cannot be written safely.
func cspSource(raw string) string {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return ""
	case u.Scheme == "https" || u.Scheme == "http":
		o := u.Scheme + "://" + strings.ToLower(u.Host)
		if originPattern.MatchString(o) {
			return o
		}
	case schemePattern.MatchString(u.Scheme):
		return u.Scheme + ":"
	}
	return ""
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// BearerResolvers implements wiring.BearerResolverProvider: the session cookie authenticates a
// browser on p.Protect and every bearer route, as an Authorization header would.
func (p *Plugin) BearerResolvers(*wiring.Graph) []pipeline.BearerResolver {
	return []pipeline.BearerResolver{cookieResolver{p}}
}

type cookieResolver struct{ p *Plugin }

// Resolve reads the session cookie when the request carries no other credential. A request with
// side effects must say it comes from this origin (Origin or Sec-Fetch-Site), so a cross-site
// form cannot ride the cookie: the host's own POST routes behind p.Protect are covered too. An
// unusable cookie is no credential (401 follows, as without one).
func (c cookieResolver) Resolve(r *http.Request) (*token.Token, error) {
	if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" {
		return nil, nil
	}
	raw := cookie(r, sessionCookie)
	if raw == "" {
		return nil, nil
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && !c.p.sameOrigin(r, true) {
		return nil, nil
	}
	tok, err := c.p.g.Tokens().Parse(raw)
	if err != nil {
		return nil, nil //nolint:nilerr // an expired or foreign cookie is no credential, not a failure
	}
	return tok, nil
}

// session is the browser's access token when its cookie still verifies, else "".
func (p *Plugin) session(r *http.Request) string {
	raw := cookie(r, sessionCookie)
	if raw == "" {
		return ""
	}
	if _, err := p.g.Tokens().Parse(raw); err != nil {
		return ""
	}
	return raw
}
