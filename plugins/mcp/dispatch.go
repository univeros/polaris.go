package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/internal/httpapi"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/pipeline"
	"github.com/univeros/polaris-go/wiring"
)

const tagAdmin = "admin"

// dispatcher builds, once, the pipeline tool calls run through: every endpoint (core's and the
// plugins') behind the whole middleware stack, in body token delivery whatever the host's (a tool
// call has no cookie jar, upstream docs/cookie-mode/spec.md §2.11). It also returns the plugins'
// bearer resolvers, which resolve the MCP caller as the pipeline would.
func (p *Plugin) dispatcher() (http.Handler, []pipeline.BearerResolver, error) {
	p.once.Do(func() {
		endpoints, err := p.g.PluginEndpoints()
		if err != nil {
			p.innerErr = err
			return
		}
		for name, e := range httpapi.Endpoints(p.g) {
			endpoints[name] = e
		}
		pl, err := p.g.Pipeline(endpoints, wiring.WithBodyDelivery())
		if err != nil {
			p.innerErr = err
			return
		}
		p.inner = pl.Handler()
		for _, plugin := range p.g.Plugins() {
			if bp, ok := plugin.(wiring.BearerResolverProvider); ok && plugin != wiring.Plugin(p) {
				p.resolvers = append(p.resolvers, bp.BearerResolvers(p.g)...)
			}
		}
	})
	return p.inner, p.resolvers, p.innerErr
}

// call runs a tool call as the HTTP route would run: an in-process request to the route's URL
// (path parameters substituted, the rest as the query or the JSON body) through the whole
// pipeline, so it answers exactly what the route answers. The principal rides in the context; only
// admin routes, which authenticate from the header alone, get the credential re-sent. The caller's
// client context (IP, user agent) is kept, so per-IP rate limits stay per client.
func (p *Plugin) call(ctx context.Context, rt *manifest.Route, args map[string]any, c caller) (wiring.ToolResult, error) {
	handler, _, err := p.dispatcher()
	if err != nil {
		return wiring.ToolResult{}, err
	}
	rest := make(map[string]any, len(args))
	for k, v := range args {
		rest[k] = v
	}
	path := pathParam.ReplaceAllStringFunc(rt.Path, func(m string) string {
		name := m[1 : len(m)-1]
		v := scalar(rest[name])
		delete(rest, name)
		return strings.ReplaceAll(url.QueryEscape(v), "+", "%20") // PHP's rawurlencode
	})
	u, _ := url.Parse(strings.TrimRight(p.cfg.BaseURL, "/"))
	u.Path = strings.TrimRight(p.g.Config().PathPrefix, "/") + path
	var body []byte
	switch rt.Input.Source {
	case manifest.SourceQuery:
		q := url.Values{}
		for k, v := range rest {
			q.Set(k, scalar(v))
		}
		u.RawQuery = q.Encode()
	case manifest.SourceBody:
		if len(rest) > 0 {
			body, _ = json.Marshal(rest)
		}
	}
	inner, cancel := context.WithCancel(context.Background()) // fresh values: never the /mcp route's
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()
	inner = endpoint.WithClient(inner, endpoint.Client(ctx))
	if c.token != nil {
		inner = context.WithValue(inner, principalKey{}, c.token)
	}
	r, err := http.NewRequestWithContext(inner, rt.Method, u.String(), bytes.NewReader(body)) //nolint:gosec,contextcheck // served in process by Polaris's own handler below, never over the network (G704); fresh context values on purpose, cancellation linked above
	if err != nil {
		return wiring.ToolResult{}, err
	}
	r.RemoteAddr = ""
	if u.Scheme == "https" {
		r.TLS = &tls.ConnectionState{}
	}
	r.Header.Set("Accept", "application/json")
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.credential != "" && slices.Contains(rt.Tags, tagAdmin) {
		r.Header.Set("Authorization", "Bearer "+c.credential)
	}
	rec := &recorder{header: http.Header{}}
	handler.ServeHTTP(rec, r)
	return wiring.ToolResult{Status: rec.code(), Body: decoded(rec.buf.Bytes())}, nil
}

// decoded is the response body as JSON, the raw text when it is not, nil when empty.
func decoded(raw []byte) any {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() || v == nil {
		return string(raw)
	}
	return v
}

// scalar is PHP's (string) cast of a JSON scalar; "" for anything else.
func scalar(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case json.Number:
		return s.String()
	case float64:
		return fmt.Sprint(s)
	case bool:
		if s {
			return "1"
		}
	}
	return ""
}
