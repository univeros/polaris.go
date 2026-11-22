package oauth

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id: its routes are polaris.oauth.*, its problems oauth/*.
const ID = "oauth"

// Plugin is the OAuth provider. Build it with New and pass it to polaris.Config.Plugins; after
// polaris.New its methods are safe for concurrent use.
type Plugin struct {
	settings  settings
	configErr error

	graph         *wiring.Graph
	issuer        string
	scopes        *scopes
	clients       *clients
	tokens        *tokens
	codes         *codes
	consents      *consents
	authorization *authorization
	devices       *devices
	ciba          *ciba
	dpop          *dpop
}

var (
	_ wiring.SchemaProvider         = (*Plugin)(nil)
	_ wiring.ManifestProvider       = (*Plugin)(nil)
	_ wiring.Initializer            = (*Plugin)(nil)
	_ wiring.EndpointProvider       = (*Plugin)(nil)
	_ wiring.ListenerProvider       = (*Plugin)(nil)
	_ wiring.BearerResolverProvider = (*Plugin)(nil)
)

// New returns the provider for cfg. A configuration problem is reported by polaris.New, with the
// field to fix.
func New(cfg Config) *Plugin {
	s, err := cfg.resolve()
	return &Plugin{settings: s, configErr: err}
}

// ID implements wiring.Plugin.
func (p *Plugin) ID() string { return ID }

// Schema declares the plugin's six tables.
func (p *Plugin) Schema() []schema.Model { return models() }

// Manifest is the plugin's route specs, mirrored from upstream.
func (p *Plugin) Manifest() fs.FS {
	dir, err := fs.Sub(apispec.API, "api/oauth-provider")
	if err != nil {
		panic(err) // the embedded mirror always has it
	}
	return dir
}

// Init builds the provider's services over the graph.
func (p *Plugin) Init(g *wiring.Graph) error {
	if p.configErr != nil {
		return p.configErr
	}
	if g.Tokens() == nil { // core services are built with the codec
		return errors.New("oauth: the graph has no token codec or pepper; build the plugin through polaris.New")
	}
	if p.settings.baseURL == "" {
		prefix := strings.TrimRight(g.Config().PathPrefix, "/")
		p.settings.baseURL = strings.TrimRight(g.Auth().Issuer, "/") + prefix
	}
	if !baseURLPattern.MatchString(p.settings.baseURL) {
		return fmt.Errorf("oauth: the base URL %q is not an absolute http(s) URL: set oauth.Config.BaseURL", p.settings.baseURL)
	}
	p.usePages(g)
	once := &onceGuard{cache: g.Cache()}
	p.graph, p.issuer = g, g.Auth().Issuer
	p.scopes = newScopes(g.Catalog(), p.settings.scopes)
	p.clients = &clients{db: g.DB(), pepper: g.Pepper(), scopes: p.scopes, settings: p.settings, cache: g.Cache(), once: once, clock: g.Clock(), log: g.Logger()}
	p.tokens = &tokens{db: g.DB(), pepper: g.Pepper(), codec: g.Tokens(), repos: g.Repos(), issuer: p.issuer, settings: p.settings, clock: g.Clock()}
	p.codes = &codes{db: g.DB(), pepper: g.Pepper(), ttl: time.Duration(p.settings.codeTTL) * time.Second, clock: g.Clock()}
	p.consents = &consents{db: g.DB(), clock: g.Clock()}
	p.authorization = &authorization{clients: p.clients, scopes: p.scopes, codes: p.codes, consents: p.consents,
		settings: p.settings, issuer: p.issuer, cache: g.Cache(), clock: g.Clock()}
	p.devices = &devices{poller: poller{db: g.DB(), table: TableDeviceCodes, interval: p.settings.pollInterval, clock: g.Clock(), what: "device code"},
		pepper: g.Pepper(), deviceURL: p.settings.deviceURL, ttl: p.settings.deviceTTL}
	p.ciba = &ciba{poller: poller{db: g.DB(), table: TableCIBARequests, interval: p.settings.pollInterval, clock: g.Clock(), what: "request"},
		repos: g.Repos(), ttl: p.settings.cibaTTL}
	p.dpop = &dpop{once: once, clock: g.Clock()}
	return nil
}

// PageProvider is a plugin serving a consent page and a device page (plugins/ui implements it):
// when one is registered, its pages fill the ConsentURL and DeviceURL the host left empty.
type PageProvider interface {
	OAuthPages(g *wiring.Graph) (consentURL, deviceURL string)
}

func (p *Plugin) usePages(g *wiring.Graph) {
	for _, plugin := range g.Plugins() {
		pages, ok := plugin.(PageProvider)
		if !ok {
			continue
		}
		consent, device := pages.OAuthPages(g)
		if p.settings.consentURL == "" {
			p.settings.consentURL = consent
		}
		if p.settings.deviceURL == "" {
			p.settings.deviceURL = device
		}
		return
	}
}

// Endpoints serves the 26 oauth routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// BearerResolvers makes the provider's access tokens principals on every Polaris route.
func (p *Plugin) BearerResolvers(*wiring.Graph) []pipeline.BearerResolver {
	return []pipeline.BearerResolver{resolverFunc(p.ResolveBearer)}
}

// Listeners erase what an erased user or organization leaves behind: a user's consents and
// tokens, an organization's clients and their tokens.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		var err error
		switch e := e.(type) {
		case event.UserDeleted:
			err = errors.Join(
				deleteWhere(ctx, p.graph.DB(), TableConsents, store.Criteria{"user_id": e.UserID}),
				p.tokens.deleteWhere(ctx, store.Criteria{"user_id": e.UserID}))
		case event.OrganizationDeleted:
			err = p.eraseOrganization(ctx, e.OrganizationID)
		}
		if err != nil {
			p.graph.Logger().ErrorContext(ctx, "oauth: erasing after "+e.EventName()+" failed", "error", err)
		}
	}}
}

func (p *Plugin) eraseOrganization(ctx context.Context, organizationID string) error {
	owned, err := p.clients.list(ctx, store.Criteria{"organization_id": organizationID})
	if err != nil {
		return err
	}
	for _, c := range owned {
		if err := p.tokens.deleteWhere(ctx, store.Criteria{"client_id": c.ClientID}); err != nil {
			return err
		}
	}
	return deleteWhere(ctx, p.graph.DB(), TableClients, store.Criteria{"organization_id": organizationID})
}

func deleteWhere(ctx context.Context, db store.Adapter, table string, c store.Criteria) error {
	_, err := db.Delete(ctx, table, c)
	return err
}

// resolverFunc adapts a function to pipeline.BearerResolver.
type resolverFunc func(r *http.Request) (*token.Token, error)

// Resolve implements pipeline.BearerResolver.
func (f resolverFunc) Resolve(r *http.Request) (*token.Token, error) { return f(r) }
