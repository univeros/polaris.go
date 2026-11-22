package wiring

import (
	"io/fs"
	"net/http"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
)

// Plugin extends Polaris from the outside: its own tables, routes, services, listeners and
// permissions, wired by polaris.New. Only ID is required; a plugin implements the optional
// interfaces below for the parts it has (the io.WriterTo pattern: no base type to embed).
//
// Order of calls at New: Schema, Permissions, Manifest and MFAFactorTypes while the core graph is
// built, then Init (plugins in order), then Endpoints, Listeners, Middleware, BearerResolvers.
type Plugin interface {
	// ID names the plugin ("agents", "oauth"); it must match the first segment of its route files
	// (api/<id>/…) so route names read polaris.<id>.…
	ID() string
}

// SchemaProvider declares the plugin's tables. Redefining a core or another plugin's table fails New.
type SchemaProvider interface{ Schema() []schema.Model }

// PermissionProvider contributes permission keys and descriptions to the catalog.
type PermissionProvider interface{ Permissions() map[string]string }

// ManifestProvider returns the directory holding the plugin's route specs (its <id>/ subtree
// inside). A route already declared elsewhere fails New.
type ManifestProvider interface{ Manifest() fs.FS }

// Initializer builds the plugin's services from the graph; it runs once, after the core graph
// and before every other plugin hook. Another plugin is reachable with g.Plugin(id).
type Initializer interface{ Init(g *Graph) error }

// EndpointProvider serves the plugin's routes, keyed by route name.
type EndpointProvider interface {
	Endpoints(g *Graph) (map[string]endpoint.Endpoint, error)
}

// ListenerProvider subscribes to domain events. Its listeners run when an event is raised, inside
// the transaction that raised it, so their store writes (an audit row, an erased user's rows)
// commit or roll back with the action; wrap one whose effect leaves the database (a webhook) with
// Graph.Deferred so it runs only after the commit.
type ListenerProvider interface {
	Listeners(g *Graph) []event.Listener
}

// MiddlewareProvider adds middleware run on every Polaris route right after bearer
// authentication, before step-up, denylist and authorization.
type MiddlewareProvider interface {
	Middleware(g *Graph) []func(http.Handler) http.Handler
}

// BearerResolverProvider turns credentials that are not Polaris JWTs (API keys, OAuth access
// tokens, agent request JWTs) into principals; resolvers run before the JWT parse.
type BearerResolverProvider interface {
	BearerResolvers(g *Graph) []pipeline.BearerResolver
}

// MFAFactorTypeProvider adds MFA factor types (passkeys) verified through core's MFA routes. It is
// called before the MFA service exists, so it takes no graph: a factor type reaches the plugin's
// services through the plugin itself, whose Init has run by the time any request verifies a code.
type MFAFactorTypeProvider interface {
	MFAFactorTypes() []mfa.FactorType
}

// Ports are core ports a plugin serves; a nil field is not provided.
type Ports struct {
	Mailer   notify.Mailer
	SMS      notify.SMSSender
	Breaches security.BreachedPasswordCheck
}

// PortsProvider serves core ports the host left nil in Config (Config's own always win; among
// plugins the first in registration order providing a port wins). Called once, after plugin
// registration and before core services are built, so before Init: a returned port must work once
// Init has run (no request arrives earlier). The messaging plugin serves Mailer and SMS this way.
type PortsProvider interface{ Ports() Ports }

// HandlerProvider serves requests the route manifest does not describe, under one path prefix the
// plugin owns: HTML pages and forms a browser reads (plugins/ui), which the JSON route specs and
// the OpenAPI export do not model. prefix is relative to Config.PathPrefix ("/auth/ui"); every
// request at or under it reaches h instead of the pipeline, inside Config.Middleware like every
// Polaris route. h brings its own security (CSRF, headers, rate limits through the pipeline's
// routes). A prefix that overlaps a manifest route or another plugin's fails polaris.New.
type HandlerProvider interface {
	Handler(g *Graph) (prefix string, h http.Handler)
}
