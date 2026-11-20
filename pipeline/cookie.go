package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
)

const (
	// RefreshCookie is the cookie that carries the refresh token in cookie token delivery.
	RefreshCookie = "__Secure-polaris_refresh"
	// CSRFHeader must be "1" on the requests that issue or refresh a session in cookie delivery.
	CSRFHeader = "X-Polaris-CSRF"
)

// refreshCookie is cookie token delivery (upstream docs/cookie-mode/spec.md): on the routes the
// manifest marks with a session, the refresh token travels in an HttpOnly cookie instead of the
// JSON body.
//
//   - issue and refresh: refused over plaintext and without the CSRF guard; a 200 or 201 carrying
//     data.refresh_token loses it to the cookie.
//   - refresh: when neither the body nor the query carries refresh_token, the cookie's value is put
//     in the body; a 401 clears the cookie when the cookie was the credential.
//   - end: a 2xx clears the cookie.
//
// The request is https exactly when r.TLS is set: behind a TLS-terminating proxy, the host's
// trusted-proxy layer must set r.TLS for requests the proxy received over TLS.
func (p *Pipeline) refreshCookie(next http.Handler) http.Handler {
	path := strings.TrimRight(p.opts.PathPrefix, "/") + "/auth/token/refresh"
	cleared := cookieHeader(path, "", 0)
	maxAge := int(p.opts.Auth.RefreshToken.TTL.Seconds())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := endpoint.Route(r.Context())
		if rt == nil || rt.Session == "" {
			next.ServeHTTP(w, r)
			return
		}
		buf := &bufferedResponse{header: w.Header()}
		if rt.Session == manifest.SessionEnd {
			next.ServeHTTP(buf, r)
			if buf.code()/100 == 2 {
				buf.header.Add("Set-Cookie", cleared)
			}
			buf.flush(w)
			return
		}
		if scheme(r) != "https" {
			refuse(w, rt, "insecure_transport", "Insecure transport", "Sessions are only issued over HTTPS.")
			return
		}
		if !p.sameOrigin(r) {
			refuse(w, rt, "csrf_failed", "CSRF check failed", "The request did not pass the CSRF check.")
			return
		}
		fromCookie := false
		if rt.Session == manifest.SessionRefresh {
			r, fromCookie = withCookieToken(r)
		}
		next.ServeHTTP(buf, r)
		switch status := buf.code(); {
		case status == http.StatusOK || status == http.StatusCreated:
			if secret, ok := buf.takeRefreshToken(); ok {
				buf.header.Add("Set-Cookie", cookieHeader(path, rawURLEncode(secret), maxAge))
			}
		case status == http.StatusUnauthorized && fromCookie:
			buf.header.Add("Set-Cookie", cleared)
		}
		buf.flush(w)
	})
}

func cookieHeader(path, value string, maxAge int) string {
	return fmt.Sprintf("%s=%s; Path=%s; Max-Age=%d; HttpOnly; Secure; SameSite=Strict", RefreshCookie, value, path, maxAge)
}

// rawURLEncode is PHP's rawurlencode: every byte but A-Z a-z 0-9 - _ . ~ percent-encoded.
func rawURLEncode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// scheme is https exactly when the connection is TLS. r.URL.Scheme is not trusted: a plaintext
// client can send an absolute-form https:// request target.
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// sameOrigin is the CSRF guard: the custom header (a cross-origin page cannot send it without a
// preflight Polaris never answers), then the Origin (or, without one, Sec-Fetch-Site) must be this
// origin or a trusted one.
func (p *Pipeline) sameOrigin(r *http.Request) bool {
	if headerLine(r, CSRFHeader) != "1" {
		return false
	}
	if len(r.Header.Values("Origin")) > 0 {
		origin := strings.ToLower(headerLine(r, "Origin"))
		return origin == requestOrigin(r) || slices.Contains(p.opts.Auth.Flows.CookieTrustedOrigins, origin)
	}
	if len(r.Header.Values("Sec-Fetch-Site")) > 0 {
		return headerLine(r, "Sec-Fetch-Site") == "same-origin"
	}
	return true
}

func headerLine(r *http.Request, name string) string {
	return strings.Join(r.Header.Values(name), ", ")
}

// requestOrigin is scheme://host[:port], the port omitted when it is the scheme's default.
func requestOrigin(r *http.Request) string {
	s := scheme(r)
	u := url.URL{Host: r.Host}
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := strings.ToLower(s + "://" + host)
	if port := u.Port(); port != "" && !(s == "https" && port == "443") && !(s == "http" && port == "80") {
		origin += ":" + port
	}
	return origin
}

// withCookieToken puts the refresh cookie's value in the body as refresh_token, unless the body or
// the query already carries one (the body's wins, the query's would override it anyway).
func withCookieToken(r *http.Request) (*http.Request, bool) {
	c, err := r.Cookie(RefreshCookie)
	if err != nil || c.Value == "" || r.URL.Query().Has("refresh_token") {
		return r, false
	}
	var raw []byte
	if r.Body != nil {
		raw, _ = io.ReadAll(r.Body) // an unreadable body counts as empty, as Input reads it
		_ = r.Body.Close()
	}
	r2 := r.Clone(r.Context())
	if isForm(r) {
		values, _ := url.ParseQuery(string(raw))
		if values.Has("refresh_token") {
			return withBody(r2, raw), false
		}
		values.Set("refresh_token", c.Value)
		return withBody(r2, []byte(values.Encode())), true
	}
	body := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&body) != nil || body == nil {
		body = map[string]any{}
	}
	if body["refresh_token"] != nil {
		return withBody(r2, raw), false
	}
	body["refresh_token"] = c.Value
	encoded, _ := json.Marshal(body) // decoded JSON always re-encodes
	r2.Header.Set("Content-Type", "application/json")
	return withBody(r2, encoded), true
}

func isForm(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded")
}

func withBody(r *http.Request, body []byte) *http.Request {
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return r
}

// refuse answers 403 in the envelope of the refused route: core's {"error", "message"}, or the
// problem document of plugin routes, with the same error code.
func refuse(w http.ResponseWriter, rt *manifest.Route, code, title, message string) {
	if rt.Plugin == "" {
		endpoint.Write(w, endpoint.Error(http.StatusForbidden, code, message))
		return
	}
	endpoint.Write(w, endpoint.Problem(http.StatusForbidden, "cookie/"+code, title, message, map[string]any{"error": code}))
}

// bufferedResponse holds an inner response so it can be rewritten. Headers go straight to the
// real writer's map (nothing is sent before flush).
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.WriteHeader(http.StatusOK)
	return b.body.Write(p)
}

func (b *bufferedResponse) code() int {
	if b.status == 0 {
		return http.StatusOK
	}
	return b.status
}

// takeRefreshToken removes data.refresh_token from a JSON body. A body without a string
// data.refresh_token (an MFA ticket, an error) is left unchanged.
func (b *bufferedResponse) takeRefreshToken() (string, bool) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(b.body.Bytes()))
	dec.UseNumber()
	if dec.Decode(&doc) != nil {
		return "", false
	}
	data, _ := doc["data"].(map[string]any)
	secret, ok := data["refresh_token"].(string)
	if !ok {
		return "", false
	}
	delete(data, "refresh_token")
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if enc.Encode(doc) != nil {
		return "", false
	}
	b.body.Reset()
	b.body.Write(bytes.TrimSuffix(out.Bytes(), []byte("\n")))
	b.header.Del("Content-Length")
	return secret, true
}

func (b *bufferedResponse) flush(w http.ResponseWriter) {
	w.WriteHeader(b.code())
	if b.body.Len() > 0 {
		_, _ = w.Write(b.body.Bytes())
	}
}
