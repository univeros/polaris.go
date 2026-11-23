package agents

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// normalizeURL is the form a capability location, a request URL and a JWT's aud are compared in
// (RFC 3986 §6.2.2): lower-case scheme and host, no default port, percent-encoded unreserved
// characters decoded (others upper-cased), dot segments resolved, empty segments and a trailing
// slash dropped, no query or fragment. A URL without a scheme or host is returned as given.
func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return raw
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, _ := strconv.Atoi(port)
		if !(scheme == "https" && n == 443) && !(scheme == "http" && n == 80) {
			host += ":" + strconv.Itoa(n)
		}
	}
	return scheme + "://" + host + normalizePath(u.EscapedPath())
}

// routeOf is the normalised URL without its scheme (host[:port]/path): what a request is matched
// against a location by, so the http:// a TLS-terminating proxy hands over is still guarded (and
// then fails the aud check).
func routeOf(raw string) string {
	n := normalizeURL(raw)
	if _, rest, ok := strings.Cut(n, "://"); ok {
		return rest
	}
	return n
}

func normalizePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '%' && i+2 < len(p) && isHex(p[i+1]) && isHex(p[i+2]) {
			c := unhex(p[i+1])<<4 | unhex(p[i+2])
			if unreserved(c) {
				b.WriteByte(c)
			} else {
				b.WriteString("%" + strings.ToUpper(p[i+1:i+3]))
			}
			i += 2
			continue
		}
		b.WriteByte(p[i])
	}
	var segments []string
	for _, s := range strings.Split(b.String(), "/") {
		switch s {
		case "", ".":
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, s)
		}
	}
	return "/" + strings.Join(segments, "/")
}

// decodedPath is an escaped path as the most lenient router reads it: every escape decoded, then empty
// and dot segments resolved. A path that does not decode is taken as it is.
func decodedPath(escaped string) string {
	p, err := url.PathUnescape(escaped)
	if err != nil {
		p = escaped
	}
	return path.Clean("/" + p)
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c <= '9':
		return c - '0'
	case c <= 'F':
		return c - 'A' + 10
	}
	return c - 'a' + 10
}

func unreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~'
}

// requestURL is the URL the client called on a host route (Protect, Guard), without its query:
// what a request JWT's aud names there. The scheme and host are the request's own, so behind a
// TLS-terminating proxy the host must set r.TLS for the scheme to read https, and the host routes
// must be served only under the names the application answers to.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return scheme + "://" + host + requestPath(r)
}

// ownURL is the URL of one of the plugin's own routes as an agent names it in aud: the path
// called on the configured base URL's origin. The Host header and r.TLS play no part, so a
// forged or forwarded Host cannot make a JWT signed for another server read as one for this one,
// and a TLS-terminating proxy changes nothing.
func ownURL(baseURL string, r *http.Request) string {
	origin := baseURL
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		origin = u.Scheme + "://" + u.Host
	}
	return origin + requestPath(r)
}

// requestPath is the path the client sent: RequestURI's, before a host's http.StripPrefix rewrote
// URL.Path.
func requestPath(r *http.Request) string {
	if u, err := url.ParseRequestURI(r.RequestURI); err == nil && r.RequestURI != "" {
		return u.EscapedPath()
	}
	return r.URL.EscapedPath()
}
