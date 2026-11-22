package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/httpapi"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/wiring"
)

const tagAdmin = "admin"

// dispatcher builds, once, the pipeline tool calls run through: every endpoint (core's and the
// plugins') behind the whole middleware stack, in body token delivery whatever the host's: a tool
// call has no cookie jar, so its tokens travel in the response body. It also returns the plugins'
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
	path, escaped, err := fillPath(rt.Path, rest)
	if err != nil {
		return wiring.ToolResult{}, err
	}
	u, _ := url.Parse(strings.TrimRight(p.cfg.BaseURL, "/"))
	prefix := strings.TrimRight(p.g.Config().PathPrefix, "/")
	u.Path, u.RawPath = prefix+path, prefix+escaped
	var body []byte
	switch rt.Input.Source {
	case manifest.SourceQuery:
		q := url.Values{}
		for k, v := range rest {
			if v == nil {
				continue
			}
			s, ok := scalar(v)
			if !ok {
				return wiring.ToolResult{}, invalidArgument(k)
			}
			q.Set(k, s)
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

// scalar is a JSON string, number or boolean as the text a path or query carries: a string as
// is, a number in decimal, a boolean as "true" or "false"; ok is false for anything else.
func scalar(v any) (string, bool) {
	switch s := v.(type) {
	case string:
		return s, true
	case json.Number:
		return s.String(), true
	case float64:
		return strconv.FormatFloat(s, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(s), true
	}
	return "", false
}

// fillPath substitutes the route's {parameters} with the arguments of the same name, removing
// them from args: path is the decoded path, escaped the same path with each value escaped as one
// segment (RFC 3986 §3.3). A parameter without a string, number or boolean value is invalid
// params.
func fillPath(pattern string, args map[string]any) (path, escaped string, err error) {
	var p, e strings.Builder
	last := 0
	for _, m := range pathParam.FindAllStringSubmatchIndex(pattern, -1) {
		name := pattern[m[2]:m[3]]
		v, ok := scalar(args[name])
		if !ok {
			return "", "", invalidArgument(name)
		}
		delete(args, name)
		p.WriteString(pattern[last:m[0]] + v)
		e.WriteString(pattern[last:m[0]] + url.PathEscape(v))
		last = m[1]
	}
	p.WriteString(pattern[last:])
	e.WriteString(pattern[last:])
	return p.String(), e.String(), nil
}

func invalidArgument(name string) *rpcError {
	return newError(codeInvalidParams, http.StatusBadRequest, "Invalid argument %q: a string, a number or a boolean is required.", name)
}
