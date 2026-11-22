package oauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// impersonationClaim marks an admin impersonation token: it never calls an admin route.
const impersonationClaim = "impersonated_by"

// orgScope is the organization of a self-service client route: the path's, which must be the
// caller's active one (a superadmin excepted). The route itself requires org.update.
func (p *Plugin) orgScope(ctx context.Context, in *endpoint.Input) (*token.Token, string, *endpoint.Result) {
	tok := endpoint.Token(ctx)
	if tok == nil {
		r := endpoint.Unauthorized()
		return nil, "", &r
	}
	orgID := in.String("id")
	if orgID == "" || deniesActiveOrg(ctx, tok, orgID) {
		r := endpoint.Problem(http.StatusForbidden, "oauth/forbidden", "Forbidden", "That organization is not your active organization.", nil)
		return nil, "", &r
	}
	return tok, orgID, nil
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

// orgClient is the client {clientId} of the organization.
func (p *Plugin) orgClient(ctx context.Context, in *endpoint.Input, orgID string) (*Client, *endpoint.Result) {
	c, err := p.clients.findByID(ctx, in.String("clientId"))
	if err != nil {
		r := p.fail(ctx, err)
		return nil, &r
	}
	if c == nil || c.OrganizationID != orgID {
		r := endpoint.Problem(http.StatusNotFound, "oauth/not_found", "Not found", "The client does not exist in this organization.", nil)
		return nil, &r
	}
	return c, nil
}

func clientWithSecret(issued IssuedClient) map[string]any {
	v := issued.Client.view()
	v["client_secret"] = null(issued.Secret)
	return v
}

func (p *Plugin) serveOrgClientsList(ctx context.Context, in *endpoint.Input) endpoint.Result {
	_, orgID, refused := p.orgScope(ctx, in)
	if refused != nil {
		return *refused
	}
	return p.clientList(ctx, func(Client) bool { return true }, orgID)
}

// clientList answers the clients of orgID ("" for every one) that keep passes.
func (p *Plugin) clientList(ctx context.Context, keep func(Client) bool, orgID string) endpoint.Result {
	criteria := map[string]any{}
	if orgID != "" {
		criteria["organization_id"] = orgID
	}
	all, err := p.clients.list(ctx, criteria)
	if err != nil {
		return p.fail(ctx, err)
	}
	data := []map[string]any{}
	for _, c := range all {
		if keep(c) {
			data = append(data, c.view())
		}
	}
	return endpoint.Data(http.StatusOK, data)
}

func (p *Plugin) serveOrgClientsCreate(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok, orgID, refused := p.orgScope(ctx, in)
	if refused != nil {
		return *refused
	}
	issued, err := p.clients.create(ctx, ClientFields(in.All()), orgID, tok.Subject(), false)
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventClientCreated, tok.Subject(), issued.Client.ClientID, orgID, map[string]any{"name": issued.Client.Name, "how": "organization"})
	return endpoint.Data(http.StatusCreated, clientWithSecret(issued))
}

func (p *Plugin) serveOrgClientsRead(ctx context.Context, in *endpoint.Input) endpoint.Result {
	_, orgID, refused := p.orgScope(ctx, in)
	if refused != nil {
		return *refused
	}
	c, refused := p.orgClient(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	return endpoint.Data(http.StatusOK, c.view())
}

func (p *Plugin) serveOrgClientsUpdate(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok, orgID, refused := p.orgScope(ctx, in)
	if refused != nil {
		return *refused
	}
	c, refused := p.orgClient(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	fields := ClientFields(in.All())
	delete(fields, "id")
	delete(fields, "clientId")
	updated, changes, err := p.clients.update(ctx, *c, fields, false)
	if err != nil {
		return p.fail(ctx, err)
	}
	if len(changes) > 0 {
		p.emit(ctx, EventClientUpdated, tok.Subject(), c.ClientID, orgID, map[string]any{"changes": changes})
	}
	return endpoint.Data(http.StatusOK, updated.view())
}

func (p *Plugin) serveOrgClientsDelete(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok, orgID, refused := p.orgScope(ctx, in)
	if refused != nil {
		return *refused
	}
	c, refused := p.orgClient(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	if err := p.DeleteClient(ctx, *c); err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventClientDeleted, tok.Subject(), c.ClientID, orgID, map[string]any{"name": c.Name})
	return endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"})
}

// Operator is who calls an /admin/oauth route: an operator user or an admin API key, with a role
// (viewer, support, admin, owner) and a scope (ScopeInstance or one organization id).
type Operator struct {
	ID     string
	APIKey bool
	Role   string
	Scope  string
}

// ScopeInstance is the scope of an operator who sees every organization.
const ScopeInstance = "instance"

func (o Operator) covers(organizationID string) bool {
	return o.Scope == ScopeInstance || (organizationID != "" && o.Scope == organizationID)
}

// actor is the user an operator's events name ("" for an API key).
func (o Operator) actor() string {
	if o.APIKey {
		return ""
	}
	return o.ID
}

// errImpersonation refuses an admin impersonation token on the admin routes.
var errImpersonation = errors.New("oauth: an impersonation token cannot call the admin routes")

// superadmins is the default Config.Operators: a Polaris session whose user holds the superadmin
// role is an instance-wide owner. It applies when the admin plugin (grants and API keys) is not
// installed.
func (p *Plugin) superadmins(r *http.Request) (*Operator, error) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		return nil, nil
	}
	tok, err := p.graph.Tokens().Parse(bearer)
	if err != nil {
		return nil, nil
	}
	if tok.Claim(impersonationClaim) != nil {
		return nil, errImpersonation
	}
	user, err := p.graph.Repos().Users.Get(r.Context(), tok.Subject())
	if errors.Is(err, repository.ErrNotFound) || (err == nil && user.Status == model.UserStatusDisabled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	authority, err := p.graph.Resolver().Resolve(r.Context(), user.ID, "")
	if err != nil || !authority.IsSuperadmin() {
		return nil, err
	}
	return &Operator{ID: user.ID, Role: "owner", Scope: ScopeInstance}, nil
}

// adminAuthorizer is the admin plugin's operator check (the one its own routes apply) and the id
// of the operator it resolved.
type adminAuthorizer interface {
	AuthorizeOperator(ctx context.Context, capability, organizationID string) (userID string, refusal endpoint.Result, ok bool)
	OperatorID(ctx context.Context) (id, kind string, ok bool)
}

// acting is the operator of an admin route: actor is the user its events name ("" for an API
// key), id the user or API key id a created client records in created_by.
type acting struct{ actor, id string }

// operator is the caller of an admin route when it may act (own: owner only; otherwise read) on
// organizationID ("" the instance); else the admin/* problem to answer. Config.Operators wins;
// then the admin plugin; then the superadmins.
func (p *Plugin) operator(ctx context.Context, r *http.Request, own bool, organizationID string) (acting, *endpoint.Result) {
	if p.settings.operators == nil {
		if a, ok := p.graph.Plugin("admin").(adminAuthorizer); ok {
			capability := "read"
			if own {
				capability = "own"
			}
			userID, refusal, ok := a.AuthorizeOperator(ctx, capability, organizationID)
			if !ok {
				return acting{}, &refusal
			}
			id, _, _ := a.OperatorID(ctx)
			return acting{actor: userID, id: id}, nil
		}
	}
	deny := func(status int, typ, title, detail string) (acting, *endpoint.Result) {
		res := endpoint.Problem(status, typ, title, detail, nil)
		return acting{}, &res
	}
	resolve := p.settings.operators
	if resolve == nil {
		resolve = p.superadmins
	}
	op, err := resolve(r)
	switch {
	case errors.Is(err, errImpersonation):
		return deny(http.StatusForbidden, "admin/impersonation_denied", "Impersonation denied", "An impersonation token cannot call the admin routes.")
	case err != nil:
		res := p.fail(ctx, err)
		return acting{}, &res
	case op == nil:
		return deny(http.StatusUnauthorized, "admin/unauthorized", "Unauthorized", "An admin user or an API key is required.")
	case own && op.Role != "owner":
		return deny(http.StatusForbidden, "admin/forbidden", "Forbidden", "The "+op.Role+" role does not allow this action.")
	case !op.covers(organizationID):
		return deny(http.StatusForbidden, "admin/forbidden", "Forbidden", "This action is outside the scope of your admin role.")
	}
	return acting{actor: op.actor(), id: op.ID}, nil
}

func (p *Plugin) serveAdminClientsList(ctx context.Context, in *endpoint.Input) endpoint.Result {
	// Reading every client takes an instance-wide operator (organization "": the instance).
	if _, refused := p.operator(ctx, in.Request, false, ""); refused != nil {
		return *refused
	}
	return p.clientList(ctx, func(Client) bool { return true }, "")
}

func (p *Plugin) serveAdminClientsCreate(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("organization_id")
	op, refused := p.operator(ctx, in.Request, true, orgID)
	if refused != nil {
		return *refused
	}
	issued, err := p.clients.create(ctx, ClientFields(in.All()), orgID, op.id, true)
	var oe *Error
	if errors.As(err, &oe) {
		return endpoint.Problem(oe.Status, "oauth/"+oe.Code, "Invalid client metadata", oe.Description,
			map[string]any{"error": oe.Code, "error_description": oe.Description})
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventClientCreated, op.actor, issued.Client.ClientID, orgID,
		map[string]any{"name": issued.Client.Name, "how": "admin", "trusted": issued.Client.Trusted})
	return endpoint.Data(http.StatusCreated, clientWithSecret(issued))
}

func (p *Plugin) serveAdminClientsDelete(ctx context.Context, in *endpoint.Input) endpoint.Result {
	c, err := p.clients.findByID(ctx, in.String("id"))
	if err != nil {
		return p.fail(ctx, err)
	}
	orgID := ""
	if c != nil {
		orgID = c.OrganizationID
	}
	op, refused := p.operator(ctx, in.Request, true, orgID)
	if refused != nil {
		return *refused
	}
	if c == nil {
		return endpoint.Problem(http.StatusNotFound, "admin/not_found", "Not found", "The client does not exist.", nil)
	}
	if err := p.DeleteClient(ctx, *c); err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventClientDeleted, op.actor, c.ClientID, c.OrganizationID, map[string]any{"name": c.Name, "how": "admin"})
	return endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"})
}
