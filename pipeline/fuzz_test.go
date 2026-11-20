package pipeline

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// FuzzCookieCSRF drives cookie mode's CSRF guard and refresh-cookie injection with hostile
// headers and bodies. Nothing may panic; a request with an Origin passes only from this origin or
// a trusted one; the cookie's token is injected only when the request carries none.
func FuzzCookieCSRF(f *testing.F) {
	f.Add("1", "https://auth.polaris.test", "", "auth.polaris.test", []byte(`{"a":1}`), "application/json", "c")
	f.Add("1", "", "same-origin", "auth.polaris.test:443", []byte(`refresh_token=x`), "application/x-www-form-urlencoded", "c")
	f.Add("1", "null", "cross-site", "[::1]:8443", []byte(`{"refresh_token":null}`), "", "c%20d")
	f.Add("1, 1", "HTTPS://AUTH.POLARIS.TEST", "", "auth.polaris.test", []byte(`[`), "text/plain", "")
	p := &Pipeline{}
	p.opts.Auth.Flows.CookieTrustedOrigins = []string{"https://app.polaris.test"}
	f.Fuzz(func(t *testing.T, csrf, origin, fetchSite, host string, body []byte, contentType, cookie string) {
		r := httptest.NewRequest(http.MethodPost, "https://auth.polaris.test/auth/token/refresh", strings.NewReader(string(body)))
		r.TLS = &tls.ConnectionState{}
		r.Host = host
		r.Header.Set(CSRFHeader, csrf)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if fetchSite != "" {
			r.Header.Set("Sec-Fetch-Site", fetchSite)
		}
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Cookie", RefreshCookie+"="+cookie)
		if p.sameOrigin(r) {
			o := strings.ToLower(origin)
			if csrf != "1" || (origin != "" && o != requestOrigin(r) && o != "https://app.polaris.test") {
				t.Fatalf("CSRF passed: csrf %q origin %q host %q", csrf, origin, host)
			}
		}
		c, err := r.Cookie(RefreshCookie)
		r2, fromCookie := withCookieToken(r)
		if !fromCookie {
			return
		}
		if err != nil || c.Value == "" {
			t.Fatal("injected without a cookie")
		}
		raw, _ := io.ReadAll(r2.Body)
		if isForm(r2) {
			v, _ := url.ParseQuery(string(raw))
			if v.Get("refresh_token") != c.Value {
				t.Fatalf("form token %q", v.Get("refresh_token"))
			}
			return
		}
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil || m["refresh_token"] != c.Value {
			t.Fatalf("json body %s", raw)
		}
	})
}
