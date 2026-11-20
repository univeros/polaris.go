package agents

import (
	"context"
	"errors"
	"io/fs"
	"net/http"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/plugins/oauth"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/upstream"
	"github.com/univeros/polaris-go/wiring"
)

// ID is the plugin id: its routes are polaris.agents.*, its problems agents/*.
const ID = "agents"

// Plugin is the agents plugin. Build it with New and pass it to polaris.Config.Plugins (with
// oauth.New: agents are its clients); after polaris.New its methods are safe for concurrent use.
type Plugin struct {
	settings  settings
	caps      *capabilities
	configErr error

	s      *service
	issuer string
	mcp    bool
}

var (
	_ wiring.SchemaProvider     = (*Plugin)(nil)
	_ wiring.ManifestProvider   = (*Plugin)(nil)
	_ wiring.PermissionProvider = (*Plugin)(nil)
	_ wiring.Initializer        = (*Plugin)(nil)
	_ wiring.EndpointProvider   = (*Plugin)(nil)
	_ wiring.ListenerProvider   = (*Plugin)(nil)
	_ wiring.MiddlewareProvider = (*Plugin)(nil)
	_ wiring.ToolProvider       = (*Plugin)(nil)
)

// New returns the plugin for cfg. A configuration problem (a bad capability, an unknown risk
// tier) is reported by polaris.New, naming the field to fix.
func New(cfg Config) *Plugin {
	s, caps, err := cfg.resolve()
	return &Plugin{settings: s, caps: caps, configErr: err}
}

// Of returns the agents plugin registered on g, nil when there is none.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares the plugin's five tables.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest is the plugin's 23 route specs, mirrored from upstream.
func (*Plugin) Manifest() fs.FS {
	dir, err := fs.Sub(upstream.API, "api/agents")
	if err != nil {
		panic(err) // the embedded mirror always has it
	}
	return dir
}

// Permissions are the capabilities' permissions core's catalog lacks, so they can be attached to
// roles and asked for as OAuth scopes.
func (p *Plugin) Permissions() map[string]string {
	out := p.caps.permissions()
	for _, core := range authz.NewCatalog().Permissions() {
		delete(out, core.Key)
	}
	return out
}

// AuditNames adds the agent.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string { return auditNames }

// Init builds the plugin's services; it needs the oauth plugin.
func (p *Plugin) Init(g *wiring.Graph) error {
	if p.configErr != nil {
		return p.configErr
	}
	op, _ := g.Plugin(oauth.ID).(*oauth.Plugin)
	if op == nil {
		return errors.New(`agents: the oauth plugin is required (every agent is an OAuth client): add oauth.New(oauth.Config{}) to Config.Plugins`)
	}
	if g.Tokens == nil || g.Pepper == nil || g.MFA == nil {
		return errors.New("agents: the graph has no token codec, pepper or MFA service; build the plugin through polaris.New")
	}
	settings := p.settings
	if settings.baseURL == "" {
		settings.baseURL = op.BaseURL()
	}
	if settings.operators == nil {
		if admin, ok := g.Plugin("admin").(interface {
			AuthorizeOperator(ctx context.Context, capability, organizationID string) (string, endpoint.Result, bool)
		}); ok {
			settings.operators = admin.AuthorizeOperator
		}
	}
	p.issuer, p.mcp = g.Auth.Issuer, g.Plugin("mcp") != nil
	p.s = &service{
		db: g.DB, clock: g.Clock, events: g.Events, log: g.Logger, oauth: op, resolver: g.Resolver, gate: g.Gate,
		pepper: g.Pepper, codec: g.Tokens, mfa: g.MFA, stepUpMaxAge: g.Auth.StepUpMaxAge, settings: settings, caps: p.caps,
		jwts: &requestJWTs{cache: g.Cache, clock: g.Clock, maxAge: settings.maxAge},
	}
	return nil
}

// operators authorizes an operator route.
func (p *Plugin) operators(ctx context.Context, capability, organizationID string) (string, endpoint.Result, bool) {
	if p.s.settings.operators == nil {
		return "", endpoint.Problem(http.StatusUnauthorized, "admin/unauthorized", "Unauthorized", "An admin user or an API key is required.", nil), false
	}
	return p.s.settings.operators(ctx, capability, organizationID)
}

// Endpoints serves the 23 agents routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Middleware recognises an agent's OAuth token on every Polaris route (and behind
// polaris.Protect): the agent must be active and the token's subject the agent or the user it acts
// for; the principal becomes the agent principal (delegated within its live grants).
func (p *Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{p.middleware}
}

// Listeners erase an erased user's or organization's agents and hosts, and revoke the
// organization's agents and hosts a leaving member registered.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		var err error
		switch e := e.(type) {
		case event.UserDeleted:
			err = errors.Join(
				p.s.eraseWhere(ctx, store.Criteria{"owner_type": OwnerUser, "owner_id": e.UserID}, store.Criteria{"created_by": e.UserID}),
				deleteHosts(ctx, p.s.db, store.Criteria{"owner_type": OwnerUser, "owner_id": e.UserID}),
				deleteHosts(ctx, p.s.db, store.Criteria{"created_by": e.UserID}))
		case event.OrganizationDeleted:
			err = errors.Join(
				p.s.eraseWhere(ctx, store.Criteria{"organization_id": e.OrganizationID}),
				deleteHosts(ctx, p.s.db, store.Criteria{"organization_id": e.OrganizationID}))
		case event.MemberRemoved:
			err = errors.Join(
				p.s.revokeForMember(ctx, e.OrganizationID, e.UserID),
				p.s.revokeHosts(ctx, store.Criteria{"owner_type": OwnerOrganization, "owner_id": e.OrganizationID, "created_by": e.UserID}))
		}
		if err != nil {
			p.s.log.ErrorContext(ctx, "agents: cleaning up after "+e.EventName()+" failed", "error", err)
		}
	}}
}

func deleteHosts(ctx context.Context, db store.Adapter, c store.Criteria) error {
	_, err := db.Delete(ctx, TableHosts, c)
	return err
}

// MCPTools lists one MCP tool per capability with a handler the calling agent holds a live grant
// for, named "agents.<capability>"; a call is an execution with the same checks, budget and
// receipt. Nothing for a principal that is not an agent.
func (p *Plugin) MCPTools(ctx context.Context, caller *token.Token) ([]wiring.Tool, error) {
	if caller == nil {
		return nil, nil
	}
	pr, err := p.s.fromToken(ctx, caller)
	if err != nil || pr == nil {
		if _, refused := asError(err); refused {
			return nil, nil
		}
		return nil, err
	}
	live, err := p.s.liveGrants(ctx, pr.agent)
	if err != nil {
		return nil, err
	}
	var tools []wiring.Tool
	for _, g := range live {
		c := p.caps.find(g.Capability)
		if c == nil || c.Handler == nil {
			continue
		}
		name, who := c.Name, *pr
		tools = append(tools, wiring.Tool{
			Name: "agents." + c.Name, Description: c.Description, InputSchema: c.Input, Destructive: c.Risk == RiskHigh,
			Call: func(ctx context.Context, args map[string]any) (wiring.ToolResult, error) {
				done, err := p.s.execute(ctx, who, name, args, clientOf(ctx))
				if e, ok := asError(err); ok {
					return wiring.ToolResult{Status: e.Status(), Body: e.problem()}, nil
				}
				if err != nil {
					return wiring.ToolResult{}, err
				}
				return wiring.ToolResult{Status: http.StatusOK, Body: done.view()}, nil
			},
		})
	}
	return tools, nil
}
