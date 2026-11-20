package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/manifest"
)

// router matches a request against the manifest as upstream does: routes in load order, the first
// whose path and method match wins, a {param} segment binds [^/]+ of the raw (escaped) path.
type router struct {
	prefix string
	routes []compiled
}

type compiled struct {
	route   *manifest.Route
	pattern *regexp.Regexp
}

var placeholder = regexp.MustCompile(`\{(\w+)\}`)

// ponytail: linear regexp scan over every route; a segment trie if routing ever shows in profiles.
func newRouter(m *manifest.Manifest, prefix string) *router {
	rt := &router{prefix: strings.TrimRight(prefix, "/")}
	for _, r := range m.Routes() {
		var b strings.Builder
		b.WriteString("^")
		last := 0
		for _, loc := range placeholder.FindAllStringSubmatchIndex(r.Path, -1) {
			b.WriteString(regexp.QuoteMeta(r.Path[last:loc[0]]))
			b.WriteString("(?P<" + r.Path[loc[2]:loc[3]] + ">[^/]+)")
			last = loc[1]
		}
		b.WriteString(regexp.QuoteMeta(r.Path[last:]) + "$")
		rt.routes = append(rt.routes, compiled{route: r, pattern: regexp.MustCompile(b.String())})
	}
	return rt
}

// match returns the route and its parameters, or nil and the methods the path allows (none for an
// unknown path).
func (rt *router) match(method, path string) (*manifest.Route, map[string]string, []string) {
	if rt.prefix != "" && strings.HasPrefix(path, rt.prefix) {
		path = path[len(rt.prefix):]
	}
	if path == "" {
		path = "/"
	}
	method = strings.ToUpper(method)
	var allowed []string
	for _, c := range rt.routes {
		m := c.pattern.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		if c.route.Method != method {
			allowed = append(allowed, c.route.Method)
			continue
		}
		params := map[string]string{}
		for i, name := range c.pattern.SubexpNames() {
			if name != "" {
				params[name] = m[i]
			}
		}
		return c.route, params, nil
	}
	return nil, nil, allowed
}

type paramsKey struct{}

// route is the first middleware: it records the matched route and its parameters, or answers 404 /
// 405 in core's envelope.
func (p *Pipeline) route(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route, params, allowed := p.router.match(r.Method, r.URL.EscapedPath())
		if route == nil {
			notRouted(w, allowed)
			return
		}
		ctx := context.WithValue(endpoint.WithRoute(r.Context(), route), paramsKey{}, params)
		r, ok := p.bufferBody(w, r.WithContext(ctx), route)
		if !ok {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// DefaultMaxBodyBytes is the request body limit when Options.MaxBodyBytes is 0: 1 MiB.
const DefaultMaxBodyBytes = 1 << 20

// bufferBody reads the body of a routed request into memory, at most Options.MaxBodyBytes, so no
// middleware or endpoint ever reads an unbounded body. A larger one is answered 413 in the route's
// envelope; ok is then false. An unreadable body counts as empty, as Input reads it. r is not
// modified.
func (p *Pipeline) bufferBody(w http.ResponseWriter, r *http.Request, rt *manifest.Route) (_ *http.Request, ok bool) {
	limit := p.opts.MaxBodyBytes
	if limit == 0 {
		limit = DefaultMaxBodyBytes
	}
	if limit < 0 || r.Body == nil || r.Body == http.NoBody {
		return r, true
	}
	var raw []byte
	var err error
	if r.ContentLength <= limit {
		raw, err = io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	}
	var tooLarge *http.MaxBytesError
	if r.ContentLength > limit || errors.As(err, &tooLarge) {
		detail := fmt.Sprintf("The request body exceeds the limit of %d bytes.", limit)
		if rt.Plugin == "" {
			endpoint.Write(w, endpoint.Error(http.StatusRequestEntityTooLarge, "payload_too_large", detail))
		} else {
			endpoint.Write(w, endpoint.Problem(http.StatusRequestEntityTooLarge, "payload_too_large", "Payload too large", detail, nil))
		}
		return r, false
	}
	r2 := r.Clone(r.Context())
	r2.Body = http.NoBody
	if err == nil && len(raw) > 0 {
		r2.Body = io.NopCloser(bytes.NewReader(raw))
	}
	return r2, true
}

func notRouted(w http.ResponseWriter, allowed []string) {
	if len(allowed) == 0 {
		endpoint.Write(w, endpoint.NotFound("No such endpoint."))
		return
	}
	endpoint.Write(w, endpoint.Error(http.StatusMethodNotAllowed, "method_not_allowed", "The method is not allowed for this endpoint.").
		WithHeader("Allow", strings.Join(allowed, ", ")))
}

// dispatch runs the routed endpoint.
func (p *Pipeline) dispatch(w http.ResponseWriter, r *http.Request) {
	route := endpoint.Route(r.Context())
	params, _ := r.Context().Value(paramsKey{}).(map[string]string)
	if route == nil {
		var allowed []string
		if route, params, allowed = p.router.match(r.Method, r.URL.EscapedPath()); route == nil {
			notRouted(w, allowed)
			return
		}
		var ok bool
		if r, ok = p.bufferBody(w, r.WithContext(endpoint.WithRoute(r.Context(), route)), route); !ok {
			return
		}
	}
	ep := p.opts.Endpoints[route.Name]
	endpoint.Write(w, ep.Serve(r.Context(), endpoint.NewInput(r, params)))
}
