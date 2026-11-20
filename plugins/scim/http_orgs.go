package scim

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// Route names of the organization's and the operators' routes.
const (
	RouteConnectionsList         = "polaris.scim.connections-list"
	RouteConnectionsCreate       = "polaris.scim.connections-create"
	RouteConnectionsRead         = "polaris.scim.connections-read"
	RouteConnectionsRotate       = "polaris.scim.connections-rotate"
	RouteConnectionsDecommission = "polaris.scim.connections-decommission"
	RouteAdminConnectionsList    = "polaris.scim.admin-connections-list"
	RouteAdminConnectionsDelete  = "polaris.scim.admin-connections-delete"
)

// ssoProviders is the sso plugin's table a connection may be paired with.
const ssoProviders = "polaris_sso_provider"

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	out := p.scimEndpoints()
	maps.Copy(out, map[string]endpoint.Endpoint{
		RouteConnectionsList:         p.orgRoute(p.listConnections),
		RouteConnectionsCreate:       p.orgRoute(p.createConnection),
		RouteConnectionsRead:         p.orgRoute(p.readConnection),
		RouteConnectionsRotate:       p.orgRoute(p.rotateConnection),
		RouteConnectionsDecommission: p.orgRoute(p.decommissionConnection),
		RouteAdminConnectionsList:    endpoint.Func(p.adminList),
		RouteAdminConnectionsDelete:  endpoint.Func(p.adminDelete),
	})
	return out
}

// orgRoute is an /orgs/{id}/scim route: core checked the bearer and org.update; the path's
// organization must be the token's active one (a superadmin excepted).
func (p *Plugin) orgRoute(f func(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result) endpoint.Endpoint {
	return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
		tok := endpoint.Token(ctx)
		if tok == nil {
			return endpoint.Unauthorized()
		}
		orgID := in.String("id")
		if outside, _ := ctx.Value(outsideKey{}).(bool); outside || orgID == "" || deniesActiveOrg(ctx, tok, orgID) {
			return orgProblem(http.StatusForbidden, "forbidden", "Forbidden", "That organization is not your active organization.")
		}
		return f(ctx, in, tok, orgID)
	})
}

// orgRoutes are the organization's self-service routes.
var orgRoutes = []string{RouteConnectionsList, RouteConnectionsCreate, RouteConnectionsRead, RouteConnectionsRotate, RouteConnectionsDecommission}

type outsideKey struct{}

// activeOrganization orders the organization routes' checks as upstream: a caller outside the
// path's organization reads scim/forbidden (not core's org.update 403), with the rate-limit
// headers every route carries. Such a request goes on without the route's permission
// requirement, marked so that the endpoint refuses it whatever it reads; a caller in the
// organization goes on unchanged and core enforces org.update (upstream never checked it).
func activeOrganization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rt, tok := endpoint.Route(ctx), endpoint.Token(ctx)
		if rt == nil || tok == nil || !slices.Contains(orgRoutes, rt.Name) {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.EscapedPath()
		orgID, _, _ := strings.Cut(path[strings.LastIndex(path, "/orgs/")+len("/orgs/"):], "/")
		if orgID != "" && !deniesActiveOrg(ctx, tok, orgID) {
			next.ServeHTTP(w, r)
			return
		}
		refused := *rt
		refused.RequiresPermissions = nil
		ctx = context.WithValue(endpoint.WithRoute(ctx, &refused), outsideKey{}, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// deniesActiveOrg: orgID is not the token's active organization and the caller is no superadmin
// (by the authority the authorization step resolved, else the token's roles claim).
func deniesActiveOrg(ctx context.Context, tok *token.Token, orgID string) bool {
	if a, ok := wiring.Authority(ctx); ok {
		if a.IsSuperadmin() {
			return false
		}
	} else if roles, ok := tok.Claim("roles").([]any); ok && slices.Contains(roles, any(authz.RoleSuperadmin)) {
		return false
	}
	return orgID != tok.Organization()
}

func orgProblem(status int, name, title, detail string) endpoint.Result {
	return endpoint.Problem(status, "scim/"+name, title, detail, nil)
}

func (p *Plugin) failed(ctx context.Context, err error) endpoint.Result {
	p.g.Logger().ErrorContext(ctx, "polaris scim: operation failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// connection is the organization's connection {connectionId}.
func (p *Plugin) connection(ctx context.Context, in *endpoint.Input, orgID string) (Connection, *endpoint.Result) {
	conn, found, err := p.conns.Find(ctx, in.String("connectionId"))
	if err != nil {
		r := p.failed(ctx, err)
		return conn, &r
	}
	if !found || conn.OrganizationID != orgID {
		r := orgProblem(http.StatusNotFound, "not_found", "Not found", "The connection does not exist in this organization.")
		return conn, &r
	}
	return conn, nil
}

// state is the connection with its sync state, plus extra members.
func (p *Plugin) state(ctx context.Context, conn Connection, extra map[string]any) (map[string]any, error) {
	sync, err := p.dir.resources.sync(ctx, conn)
	if err != nil {
		return nil, err
	}
	out := conn.Map()
	out["sync"] = sync
	maps.Copy(out, extra)
	return out, nil
}

func (p *Plugin) respond(ctx context.Context, status int, conn Connection, extra map[string]any) endpoint.Result {
	s, err := p.state(ctx, conn, extra)
	if err != nil {
		return p.failed(ctx, err)
	}
	return endpoint.Data(status, s)
}

// recordUser dispatches an organization member's action on a connection.
func (p *Plugin) recordUser(ctx context.Context, name, userID string, conn Connection, data map[string]any) {
	c := endpoint.Client(ctx)
	merged := map[string]any{"connection_name": conn.Name}
	maps.Copy(merged, data)
	p.g.Events().Dispatch(ctx, Event{Name: name, ActorType: audit.ActorUser, ActorID: userID, SubjectID: conn.ID,
		OrganizationID: conn.OrganizationID, Data: merged, IP: c.IP, UserAgent: c.UserAgent})
}

// listConnections answers GET /orgs/{id}/scim/connections: never the tokens.
func (p *Plugin) listConnections(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	conns, err := p.conns.ForOrganization(ctx, orgID)
	if err != nil {
		return p.failed(ctx, err)
	}
	data := make([]map[string]any, 0, len(conns))
	for _, conn := range conns {
		s, err := p.state(ctx, conn, nil)
		if err != nil {
			return p.failed(ctx, err)
		}
		data = append(data, s)
	}
	return endpoint.Data(http.StatusOK, data)
}

// createConnection answers POST /orgs/{id}/scim/connections: the token is in this response only.
func (p *Plugin) createConnection(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	invalidInput := func(detail string) endpoint.Result {
		return orgProblem(http.StatusUnprocessableEntity, "invalid_input", "Invalid input", detail)
	}
	name := phpTrim(in.String("name"))
	if name == "" || utf8.RuneCountInString(name) > 120 {
		return invalidInput("name must be 1 to 120 characters.")
	}
	deprovision := DeprovisionDeactivate
	if v := in.Value("deprovision"); v != nil {
		if v != DeprovisionDeactivate && v != DeprovisionDelete {
			return invalidInput("deprovision must be deactivate or delete.")
		}
		deprovision = v.(string)
	}
	providerID := in.String("sso_provider_id")
	if providerID != "" {
		paired, err := p.ssoProviderOf(ctx, providerID, orgID)
		if err != nil {
			return p.failed(ctx, err)
		}
		if !paired {
			return invalidInput("sso_provider_id must be one of the organization's providers.")
		}
	}
	conn, secret, err := p.conns.Create(ctx, orgID, name, deprovision, providerID, tok.Subject())
	if err != nil {
		return p.failed(ctx, err)
	}
	p.recordUser(ctx, AuditConnectionCreated, tok.Subject(), conn, map[string]any{"deprovision": deprovision})
	return p.respond(ctx, http.StatusCreated, conn, map[string]any{"token": secret, "scim_base_url": p.BaseURL(conn.ID)})
}

// ssoProviderOf reports whether providerID is one of the organization's SSO providers; always
// false without the sso plugin.
func (p *Plugin) ssoProviderOf(ctx context.Context, providerID, orgID string) (bool, error) {
	if p.g.Plugin("sso") == nil {
		return false, nil
	}
	row, err := p.g.DB().FindOne(ctx, ssoProviders, store.Criteria{"id": providerID, "organization_id": orgID})
	return row != nil, err
}

// readConnection answers GET /orgs/{id}/scim/connections/{connectionId}.
func (p *Plugin) readConnection(ctx context.Context, in *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	conn, refused := p.connection(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	return p.respond(ctx, http.StatusOK, conn, map[string]any{"scim_base_url": p.BaseURL(conn.ID)})
}

// rotateConnection answers POST .../rotate: a new token in this response only; the previous one
// stops at once.
func (p *Plugin) rotateConnection(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	conn, refused := p.connection(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	if !conn.Active() {
		return orgProblem(http.StatusConflict, "conflict", "Conflict", "The connection is decommissioned.")
	}
	conn, secret, err := p.conns.Rotate(ctx, conn)
	if err != nil {
		return p.failed(ctx, err)
	}
	p.recordUser(ctx, AuditConnectionRotated, tok.Subject(), conn, nil)
	return p.respond(ctx, http.StatusOK, conn, map[string]any{"token": secret})
}

// decommissionConnection answers DELETE .../{connectionId}: the token stops, the provisioned
// users stay. Idempotent.
func (p *Plugin) decommissionConnection(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	conn, refused := p.connection(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	if conn.Active() {
		var err error
		if conn, err = p.conns.Decommission(ctx, conn); err != nil {
			return p.failed(ctx, err)
		}
		p.recordUser(ctx, AuditConnectionDecommissioned, tok.Subject(), conn, nil)
	}
	return p.respond(ctx, http.StatusOK, conn, nil)
}

// adminList answers GET /admin/scim/connections: oldest first, cursor-paginated; an
// organization-scoped operator sees their organization's.
func (p *Plugin) adminList(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := phpTrim(in.String("organization_id"))
	if op, ok := admin.Operator(ctx); ok && orgID == "" && op.Scope != admin.ScopeInstance {
		orgID = op.Scope
	}
	if _, refusal, ok := admin.Authorize(ctx, admin.Read, orgID); !ok {
		return refusal
	}
	limit, ok := positiveInt(in.Value("limit"), DefaultLimit)
	if !ok {
		return admin.Invalid("limit must be a positive integer.")
	}
	conns, next, err := p.conns.List(ctx, orgID, phpTrim(in.String("cursor")), limit)
	if err != nil {
		return p.failed(ctx, err)
	}
	data := make([]map[string]any, len(conns))
	for i, conn := range conns {
		data[i] = conn.Map()
	}
	return endpoint.JSON(http.StatusOK, map[string]any{"data": data, "next_cursor": nullable(next)})
}

// adminDelete answers DELETE /admin/scim/connections/{id}: the connection, its external ids and
// provenance removed; the users stay. Needs own.
func (p *Plugin) adminDelete(ctx context.Context, in *endpoint.Input) endpoint.Result {
	conn, found, err := p.conns.Find(ctx, in.String("id"))
	if err != nil {
		return p.failed(ctx, err)
	}
	op, refusal, ok := admin.Authorize(ctx, admin.Own, conn.OrganizationID)
	if !ok {
		return refusal
	}
	if !found {
		return admin.NotFound("The connection does not exist.")
	}
	if _, err := p.conns.Delete(ctx, conn.ID); err != nil {
		return p.failed(ctx, err)
	}
	actorType := audit.ActorAdmin
	if op.Type == admin.TypeAPIKey {
		actorType = audit.ActorAPIKey
	}
	c := endpoint.Client(ctx)
	p.g.Events().Dispatch(ctx, Event{Name: AuditConnectionDecommissioned, ActorType: actorType, ActorID: op.ID, SubjectID: conn.ID,
		OrganizationID: conn.OrganizationID, IP: c.IP, UserAgent: c.UserAgent,
		Data: map[string]any{"connection_name": conn.Name, "deleted": true, "actor_role": string(op.Role)}})
	return endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"})
}

// positiveInt is upstream's limit reading: a numeric value (truncated) of at least 1, def when
// absent or "".
func positiveInt(v any, def int) (int, bool) {
	if v == nil || v == "" {
		return def, true
	}
	n, ok := numeric(v)
	return n, ok && n >= 1
}
