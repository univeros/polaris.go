package polaris

import (
	"context"
	"net/http"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/httpapi"
	"github.com/univeros/polaris-go/pipeline"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/wiring"
)

// Config is everything a host decides; see wiring.Config. Secrets, Auth and DB are required.
type Config = wiring.Config

// Plugin extends Polaris; see wiring.Plugin and its optional interfaces.
type Plugin = wiring.Plugin

// Polaris is a running instance: the service graph and the HTTP pipeline over it. Safe for
// concurrent use.
type Polaris struct {
	graph    *wiring.Graph
	pipeline *pipeline.Pipeline
}

// New validates cfg, builds every service and the HTTP pipeline. Errors name what to fix.
//
//	p, err := polaris.New(polaris.Config{Secrets: secrets, Auth: auth, DB: db})
//	mux.Handle("/", p.Handler())
func New(cfg Config) (*Polaris, error) {
	g, err := wiring.New(cfg)
	if err != nil {
		return nil, err
	}
	endpoints, err := g.PluginEndpoints()
	if err != nil {
		return nil, err
	}
	for name, e := range httpapi.Endpoints(g) {
		endpoints[name] = e
	}
	pl, err := g.Pipeline(endpoints)
	if err != nil {
		return nil, err
	}
	return &Polaris{graph: g, pipeline: pl}, nil
}

// Handler serves every Polaris route (core and plugins) under Config.PathPrefix.
func (p *Polaris) Handler() http.Handler { return p.pipeline.Handler() }

// Protect guards a host handler with Polaris principals (session JWTs, and API keys, OAuth tokens
// or agent requests when those plugins are installed). With permissions, the caller's authority in
// the active organization must hold every one (403 otherwise); without, any authenticated principal
// passes. Read the principal in next with Principal.
func (p *Polaris) Protect(next http.Handler, permissions ...string) http.Handler {
	return p.pipeline.Protect(next, permissions...)
}

// Graph exposes every service, for plugins, CLIs and advanced hosts.
func (p *Polaris) Graph() *wiring.Graph { return p.graph }

// Principal is the authenticated principal of a request Protect or Handler let through: Subject()
// is the user id, Organization() the active organization; Delegation() reports an API key, OAuth
// client or agent acting with a subset of the owner's permissions.
func Principal(ctx context.Context) *token.Token { return endpoint.Token(ctx) }

// Authority is the caller's resolved roles and permissions, when the route or Protect checked
// permissions.
func Authority(ctx context.Context) (authz.Authority, bool) { return wiring.Authority(ctx) }
