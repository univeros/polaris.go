package polaris

import (
	"net/http"

	"github.com/univeros/polaris-go/internal/httpapi"
	"github.com/univeros/polaris-go/pipeline"
	"github.com/univeros/polaris-go/wiring"
)

// Config is everything a host decides; see wiring.Config. Secrets, Auth and DB are required;
// FromEnv fills them.
type Config = wiring.Config

// Plugin extends Polaris; see wiring.Plugin and its optional interfaces.
type Plugin = wiring.Plugin

// Polaris is a running instance: the service graph and the HTTP pipeline over it. Safe for
// concurrent use.
type Polaris struct {
	graph    *wiring.Graph
	pipeline *pipeline.Pipeline
	handler  http.Handler
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
	p := &Polaris{graph: g, pipeline: pl}
	p.handler = p.wrap(pl.Handler())
	return p, nil
}

// wrap applies Config.Middleware, Middleware[0] outermost.
func (p *Polaris) wrap(h http.Handler) http.Handler {
	mw := p.graph.Config().Middleware
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// Handler serves every Polaris route (core and plugins) under Config.PathPrefix.
func (p *Polaris) Handler() http.Handler { return p.handler }

// Protect guards a host handler with Polaris principals (session JWTs, and API keys, OAuth tokens
// or agent requests when those plugins are installed): 401 without one. With permissions, the
// caller's authority in the active organization must hold every one (403 otherwise); without, any
// authenticated principal passes and no authority is resolved until next calls PrincipalFrom
// (then once per request). next reads the complete principal with PrincipalFrom.
func (p *Polaris) Protect(next http.Handler, permissions ...string) http.Handler {
	return p.wrap(p.pipeline.Protect(next, permissions...))
}

// Graph exposes every service read-only: the plugin SDK, for plugins, CLIs and advanced hosts.
// An application needs only the methods of Polaris.
func (p *Polaris) Graph() *wiring.Graph { return p.graph }
