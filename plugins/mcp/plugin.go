package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.mcp.*.
const ID = "mcp"

// Path is where the MCP server answers, under the mount.
const Path = "/mcp"

// Route names of the plugin's two routes.
const (
	routeMCP      = "polaris.mcp.mcp"
	routeMetadata = "polaris.mcp.protected-resource"
	tagMCP        = "mcp"
)

// Config configures the plugin.
type Config struct {
	// BaseURL is where Polaris is mounted, prefix included ("https://app.example.com/auth"); required.
	// The MCP resource is BaseURL+"/mcp", the URL a token must name (register the oauth plugin with
	// Audiences: []string{BaseURL + "/mcp"} so its tokens resolve on every route).
	BaseURL string
	// Scopes must be held by a token to reach /mcp at all; each tool call is then checked by its route.
	Scopes []string
	// ServerName is the MCP server's name and the metadata's resource_name; default "Polaris".
	ServerName string
	// Schema returns the DDL polaris://schema serves (cmd/polaris passes its schema:export); nil
	// leaves the resource out, so this package does not link the SQL drivers.
	Schema func(ctx context.Context) (string, error)
}

// Plugin serves Polaris as an MCP server: POST /mcp (the 2026-07-28 stateless profile, protected
// as an OAuth resource by [ProtectedResource]) and [ServeStdio]; every route the caller may call is
// a tool, dispatched in-process through the same pipeline so it answers what the route answers.
type Plugin struct {
	cfg       Config
	resource  string
	g         *wiring.Graph
	protected *ProtectedResource
	schemas   func() map[string]toolSchema

	once      sync.Once
	inner     http.Handler
	resolvers []pipeline.BearerResolver
	innerErr  error
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Manifest returns the plugin's routes (upstream api/mcp): POST /mcp and its RFC 9728 metadata.
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/mcp")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// Init validates the configuration and builds the protected resource over the graph's keys.
func (p *Plugin) Init(g *wiring.Graph) error {
	base := strings.TrimRight(p.cfg.BaseURL, "/")
	if originPattern.FindString(base) == "" {
		return fmt.Errorf("mcp: Config.BaseURL %q must be the absolute http(s) URL where Polaris is mounted, prefix included, e.g. \"https://app.example.com/auth\"", p.cfg.BaseURL)
	}
	if p.cfg.ServerName == "" {
		p.cfg.ServerName = "Polaris"
	}
	p.g, p.resource = g, base+Path
	supported := slices.Clone(p.cfg.Scopes)
	for _, perm := range g.Catalog().Permissions() {
		if !slices.Contains(supported, perm.Key) {
			supported = append(supported, perm.Key)
		}
	}
	pr, err := NewProtectedResource(ProtectConfig{
		Resource:        p.resource,
		Graph:           g,
		Audiences:       []string{g.Auth().Issuer},
		Scopes:          p.cfg.Scopes,
		ScopesSupported: supported,
		MetadataURL:     base + WellKnown + Path,
		ResourceName:    p.cfg.ServerName,
		Logger:          g.Logger(),
	})
	if err != nil {
		return err
	}
	p.protected = pr
	p.schemas = sync.OnceValue(func() map[string]toolSchema { return schemasOf(g.Manifest()) })
	return nil
}

// Resource is the MCP server's URL, the aud a token must name.
func (p *Plugin) Resource() string { return p.resource }

// ProtectedResource guards /mcp; its MetadataURL is where clients are sent.
func (p *Plugin) ProtectedResource() *ProtectedResource { return p.protected }

// Endpoints serves POST /mcp and the metadata route.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return map[string]endpoint.Endpoint{
		routeMCP: endpoint.Func(p.serveHTTP),
		routeMetadata: endpoint.Func(func(context.Context, *endpoint.Input) endpoint.Result {
			return endpoint.Result{Status: http.StatusOK, Body: p.protected.Metadata(),
				Header: http.Header{"Cache-Control": {"public, max-age=3600"}}}
		}),
	}, nil
}

type principalKey struct{}

// BearerResolvers authenticate the in-process requests a tool call dispatches: the principal
// resolved once at /mcp (or by ServeStdio) travels in the request context, never as a header, so
// a DPoP-bound token proven for /mcp serves every inner call and nothing on the wire can set it.
func (p *Plugin) BearerResolvers(*wiring.Graph) []pipeline.BearerResolver {
	return []pipeline.BearerResolver{resolverFunc(func(r *http.Request) (*token.Token, error) {
		t, _ := r.Context().Value(principalKey{}).(*token.Token)
		return t, nil
	})}
}

type resolverFunc func(*http.Request) (*token.Token, error)

func (f resolverFunc) Resolve(r *http.Request) (*token.Token, error) { return f(r) }

type bodyKey struct{}

// Middleware keeps the raw body of the mcp routes for the endpoint: the transport needs the
// JSON-RPC message as sent, not the parsed input.
func (p *Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rt := endpoint.Route(r.Context())
			if rt == nil || !slices.Contains(rt.Tags, tagMCP) || r.Body == nil {
				next.ServeHTTP(w, r)
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), bodyKey{}, body)))
		})
	}}
}

// Of returns the mcp plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// serveHTTP is POST /mcp: the protected resource, then the principal behind the token, then the
// JSON-RPC message.
func (p *Plugin) serveHTTP(ctx context.Context, in *endpoint.Input) endpoint.Result {
	body, _ := ctx.Value(bodyKey{}).([]byte)
	r := in.Request.WithContext(ctx)
	r.Body = io.NopCloser(bytes.NewReader(body))
	rec := &recorder{header: http.Header{}}
	p.protected.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := p.callerOf(r, credentialOf(r))
		if err != nil {
			ref := p.protected.invalidToken("")
			ref.detail = err.Error()
			ref.write(w)
			return
		}
		status, out := p.stateless(r.Context(), body, r.Header, c)
		if out != nil {
			w.Header().Set("Content-Type", "application/json")
		}
		w.WriteHeader(status)
		_, _ = w.Write(out) //nolint:gosec // G705: a JSON-RPC body served as application/json
	})).ServeHTTP(rec, r)
	return endpoint.Result{Status: rec.code(), Header: rec.header, Raw: rec.buf.Bytes()}
}

func credentialOf(r *http.Request) string {
	if m := authorizationPattern.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		return m[2]
	}
	return ""
}

// caller is who calls the MCP server: the principal the credential resolved to (nil without
// one), the credential (re-sent only to admin routes, which authenticate from the header), and
// whether the admin plugin knows it as an operator's.
type caller struct {
	token      *token.Token
	credential string
	operator   bool
}

var errCredential = errors.New("The credential does not authenticate.")

// callerOf resolves a credential as the pipeline does: the plugins' bearer resolvers on r, then
// core's access token; the admin plugin says whether it is an operator's. A credential nothing
// accepts is refused; none is the anonymous caller.
func (p *Plugin) callerOf(r *http.Request, credential string) (caller, error) {
	if credential == "" {
		return caller{}, nil
	}
	if _, resolvers, err := p.dispatcher(); err == nil {
		for _, res := range resolvers {
			if tok, err := res.Resolve(r); err != nil || tok != nil {
				return p.withOperator(r.Context(), caller{token: tok, credential: credential}, err)
			}
		}
	}
	tok, err := p.g.Tokens().Parse(credential)
	return p.withOperator(r.Context(), caller{token: tok, credential: credential}, err)
}

type operators interface {
	IsOperator(ctx context.Context, credential string) (bool, error)
}

func (p *Plugin) withOperator(ctx context.Context, c caller, tokenErr error) (caller, error) {
	if tokenErr != nil {
		c.token = nil
	}
	if ops, ok := p.g.Plugin("admin").(operators); ok {
		op, err := ops.IsOperator(ctx, c.credential)
		if err != nil {
			return caller{}, err
		}
		c.operator = op
	}
	if c.token == nil && !c.operator {
		return caller{}, errCredential
	}
	return c, nil
}

// recorder captures a handler's response in memory.
type recorder struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.buf.Write(b)
}

func (r *recorder) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
