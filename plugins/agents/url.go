package agents

import (
	"net/http"
	"net/url"
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

// requestURL is the URL the client called, without its query: what a request JWT's aud names.
// Behind a TLS-terminating proxy the host must set r.TLS for the scheme to read https.
func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	path := r.URL.EscapedPath()
	// RequestURI is the target the client sent, before a host's http.StripPrefix rewrote URL.Path.
	if u, err := url.ParseRequestURI(r.RequestURI); err == nil && r.RequestURI != "" {
		path = u.EscapedPath()
	}
	return scheme + "://" + host + path
}
