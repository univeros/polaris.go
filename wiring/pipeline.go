package wiring

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/token"
)

// Caller is the authz.Caller of a principal: its user, active organization and, for a principal a
// plugin resolver built, the delegated permissions.
func Caller(t *token.Token) authz.Caller {
	c := authz.Caller{UserID: t.Subject(), OrganizationID: t.Organization()}
	if perms, ok := t.Delegation(); ok {
		c.Delegated, c.DelegatedPermissions = true, perms
	}
	return c
}

// Authority returns the authority the authorization step resolved for the request, ok false when
// the route needed none.
func Authority(ctx context.Context) (authz.Authority, bool) {
	a, ok := endpoint.Authority(ctx).(authz.Authority)
	return a, ok
}

type gateAdapter struct{ gate *authz.Gate }

func (a gateAdapter) Authority(ctx context.Context, t *token.Token) (pipeline.Authority, error) {
	return a.gate.Authority(ctx, Caller(t))
}

type ticketAdapter struct{ g *Graph }

func (a ticketAdapter) Authenticate(_ context.Context, ticket string) (string, error) {
	return a.g.tickets.Authenticate(ticket)
}

func (a ticketAdapter) AuthenticateFactors(_ context.Context, ticket string) (string, []string, error) {
	return a.g.tickets.AuthenticateFactors(ticket)
}

type denylistAdapter struct{ g *Graph }

func (a denylistAdapter) Revoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	return a.g.denylist.IsRevoked(ctx, userID, issuedAt)
}

// PipelineOption adjusts the options of one pipeline Graph.Pipeline builds, after they are filled
// from the graph.
type PipelineOption func(*pipeline.Options)

// WithBodyDelivery builds a pipeline that delivers tokens in the response body whatever
// Auth.Flows.TokenDelivery says: for in-process callers with no cookie jar (MCP tool calls).
func WithBodyDelivery() PipelineOption {
	return func(o *pipeline.Options) { o.Auth.Flows.TokenDelivery = config.DeliveryBody }
}

// Pipeline builds the request pipeline over the graph for the given endpoints (core's and the
// plugins', keyed by route name), with the plugins' bearer resolvers and middleware.
func (g *Graph) Pipeline(endpoints map[string]endpoint.Endpoint, opts ...PipelineOption) (*pipeline.Pipeline, error) {
	var resolvers []pipeline.BearerResolver
	var middleware []func(http.Handler) http.Handler
	for _, p := range g.plugins {
		if bp, ok := p.(BearerResolverProvider); ok {
			resolvers = append(resolvers, bp.BearerResolvers(g)...)
		}
		if mp, ok := p.(MiddlewareProvider); ok {
			middleware = append(middleware, mp.Middleware(g)...)
		}
	}
	o := pipeline.Options{
		Manifest:         g.manifest,
		PathPrefix:       g.config.PathPrefix,
		Endpoints:        endpoints,
		Auth:             g.auth,
		Tokens:           g.tokens,
		BearerResolvers:  resolvers,
		MFATickets:       ticketAdapter{g},
		StepUp:           g.mfa,
		Denylist:         denylistAdapter{g},
		Gate:             gateAdapter{g.gate},
		RateStore:        g.rateStore,
		PluginMiddleware: middleware,
		Clock:            g.clock,
		Logger:           g.logger,
		MaxBodyBytes:     g.config.MaxBodyBytes,
	}
	for _, opt := range opts {
		opt(&o)
	}
	pl, err := pipeline.New(o)
	if err != nil {
		return nil, fmt.Errorf("polaris: %w", err)
	}
	return pl, nil
}

// PluginEndpoints collects every plugin's endpoints; a route name served twice is an error.
func (g *Graph) PluginEndpoints() (map[string]endpoint.Endpoint, error) {
	out := map[string]endpoint.Endpoint{}
	for _, p := range g.plugins {
		ep, ok := p.(EndpointProvider)
		if !ok {
			continue
		}
		m, err := ep.Endpoints(g)
		if err != nil {
			return nil, fmt.Errorf("polaris: plugin %q endpoints: %w", p.ID(), err)
		}
		for name, e := range m {
			if _, dup := out[name]; dup {
				return nil, fmt.Errorf("polaris: route %q served by two plugins", name)
			}
			out[name] = e
		}
	}
	return out, nil
}
