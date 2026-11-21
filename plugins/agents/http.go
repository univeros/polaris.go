package agents

import (
	"context"
	"github.com/univeros/polaris.go/internal/version"
	"net/http"
	"regexp"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// orgPermission is what a member needs to manage an organization's agents. It is checked by the
// endpoints, not by requires_permissions (which would make the routes delegable).
const orgPermission = "org.update"

var bearerOnly = regexp.MustCompile(`(?i)^Bearer\s+(\S+)$`)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	return map[string]endpoint.Endpoint{
		"polaris.agents.configuration":    endpoint.Func(p.configuration),
		"polaris.agents.capabilities":     endpoint.Func(p.listCapabilities),
		"polaris.agents.register":         endpoint.Func(p.register),
		"polaris.agents.enroll":           endpoint.Func(p.enroll),
		"polaris.agents.list":             endpoint.Func(p.listAgents),
		"polaris.agents.show":             endpoint.Func(p.showAgent),
		"polaris.agents.suspend":          endpoint.Func(p.suspend),
		"polaris.agents.resume":           endpoint.Func(p.resume),
		"polaris.agents.revoke":           endpoint.Func(p.revokeAgent),
		"polaris.agents.hosts-create":     endpoint.Func(p.createHost),
		"polaris.agents.hosts-list":       endpoint.Func(p.listHosts),
		"polaris.agents.hosts-delete":     endpoint.Func(p.deleteHost),
		"polaris.agents.grants-request":   endpoint.Func(p.requestGrants),
		"polaris.agents.grants-delete":    endpoint.Func(p.deleteGrant),
		"polaris.agents.approvals-list":   endpoint.Func(p.listApprovals),
		"polaris.agents.approvals-read":   endpoint.Func(p.readApproval),
		"polaris.agents.approvals-decide": endpoint.Func(p.decideApproval),
		"polaris.agents.execute":          endpoint.Func(p.executeEndpoint),
		"polaris.agents.session":          endpoint.Func(p.session),
		"polaris.agents.receipts":         endpoint.Func(p.listReceipts),
		"polaris.agents.receipts-verify":  endpoint.Func(p.verifyReceipt),
		"polaris.agents.admin-list":       endpoint.Func(p.adminList),
		"polaris.agents.admin-revoke":     endpoint.Func(p.adminRevoke),
	}
}

func noStore(status int, body any) endpoint.Result {
	return endpoint.JSON(status, body).WithHeader("Cache-Control", "no-store")
}

func data(v any) map[string]any { return map[string]any{"data": v} }

// fail answers err: its problem, or a logged 500.
func (p *Plugin) fail(ctx context.Context, err error) endpoint.Result {
	if e, ok := asError(err); ok {
		return e.result()
	}
	p.s.log.ErrorContext(ctx, "agents: request failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

func unauthorized() endpoint.Result {
	return endpoint.Unauthorized().WithHeader("WWW-Authenticate", "Bearer")
}

func clientOf(ctx context.Context) client {
	c := endpoint.Client(ctx)
	return client{ip: c.IP, userAgent: c.UserAgent}
}

// text is a trimmed string field, "" when absent or blank.
func text(in *endpoint.Input, field string) string { return strings.TrimSpace(in.String(field)) }

// allows asks core's gate whether the caller holds permission in their active organization.
func (p *Plugin) allows(ctx context.Context, tok *token.Token, permission string) (bool, error) {
	return p.s.gate.Allows(ctx, wiring.Caller(tok), permission)
}

// owner is who a registration acts for: the caller (in their active organization), or the
// organization organization_id names when it is the caller's active one and they hold org.update.
func (p *Plugin) owner(ctx context.Context, in *endpoint.Input, tok *token.Token) (ownerType, ownerID, orgID string, err error) {
	org := text(in, "organization_id")
	if org == "" {
		return OwnerUser, tok.Subject(), endpoint.ActorOrganization(tok), nil
	}
	ok := org == endpoint.ActorOrganization(tok)
	if ok {
		if ok, err = p.allows(ctx, tok, orgPermission); err != nil {
			return "", "", "", err
		}
	}
	if !ok {
		return "", "", "", refuse(ErrForbidden, "Managing an organization's agents needs it as your active organization and the org.update permission in it.")
	}
	return OwnerOrganization, org, org, nil
}

// manages reports whether the caller manages the agent: its owner, or a member who may update the
// organization that owns it (their active one).
func (p *Plugin) manages(ctx context.Context, ownerType, ownerID string, tok *token.Token) (bool, error) {
	if ownerType == OwnerUser {
		return ownerID == tok.Subject(), nil
	}
	if ownerID != endpoint.ActorOrganization(tok) {
		return false, nil
	}
	return p.allows(ctx, tok, orgPermission)
}

// managed is the agent {id} names when the caller manages it.
func (p *Plugin) managed(ctx context.Context, in *endpoint.Input, tok *token.Token) (Agent, error) {
	a, ok, err := p.s.agent(ctx, in.String("id"))
	if err != nil {
		return a, err
	}
	if ok {
		if ok, err = p.manages(ctx, a.OwnerType, a.OwnerID, tok); err != nil {
			return a, err
		}
	}
	if !ok {
		return a, refuse(ErrNotFound, "The agent does not exist.")
	}
	return a, nil
}

// managedAgents are the caller's agents and their active organization's when they may update it.
func (p *Plugin) managedAgents(ctx context.Context, tok *token.Token) ([]Agent, error) {
	list, err := p.s.agentsWhere(ctx, map[string]any{"owner_type": OwnerUser, "owner_id": tok.Subject()})
	if err != nil {
		return nil, err
	}
	org := endpoint.ActorOrganization(tok)
	if org == "" {
		return list, nil
	}
	ok, err := p.allows(ctx, tok, orgPermission)
	if err != nil || !ok {
		return list, err
	}
	more, err := p.s.agentsWhere(ctx, map[string]any{"owner_type": OwnerOrganization, "owner_id": org})
	return append(list, more...), err
}

// agentOf authenticates the agent calling an agent-facing route.
func (p *Plugin) agentOf(ctx context.Context, in *endpoint.Input) (principal, error) {
	return p.s.authenticate(in.Request, rawBody(ctx))
}

func views[T any](list []T, view func(T) map[string]any) []any {
	out := make([]any, len(list))
	for i, v := range list {
		out[i] = view(v)
	}
	return out
}

func agentView(a Agent) map[string]any     { return a.view() }
func grantView(g Grant) map[string]any     { return g.view() }
func hostView(h Host) map[string]any       { return h.view() }
func receiptView(r Receipt) map[string]any { return r.view() }

func (p *Plugin) configuration(context.Context, *endpoint.Input) endpoint.Result {
	return endpoint.JSON(http.StatusOK, p.discovery()).WithHeader("Cache-Control", "public, max-age=3600")
}

// discovery is the agent configuration document (docs/better/agent-auth-compat.md).
func (p *Plugin) discovery() map[string]any {
	base := p.s.settings.baseURL
	tokenURL := p.s.oauth.BaseURL() + "/oauth2/token"
	endpoints := map[string]any{
		"register": base + "/agents/register", "enroll": base + "/agents/enroll", "capabilities": base + "/agents/capabilities",
		"execute": base + "/agents/execute", "request_capability": base + "/agents/grants/request", "status": base + "/agents/session",
		"revoke": base + "/agents", "grants": base + "/agents/grants", "approvals": base + "/agents/approvals",
		"receipts": base + "/agents/receipts", "token": tokenURL,
	}
	if p.mcp {
		endpoints["mcp"] = p.s.oauth.BaseURL() + "/mcp"
	}
	return map[string]any{
		"version": "1.0-draft", "provider_name": p.s.settings.providerName, "description": p.s.settings.description,
		"issuer": p.issuer, "default_location": endpoints["execute"], "algorithms": algorithms, "modes": modes,
		"approval_methods": methods, "approval_strengths": p.s.settings.strengths, "endpoints": endpoints,
		"token_endpoint": tokenURL, "agent_sdk_versions": map[string]any{"github.com/univeros/polaris.go/agent": version.Module()},
	}
}

// DiscoveryHandler serves the agent configuration document; hosts mount it at the application
// root, where agents look for it:
//
//	mux.Handle("GET /.well-known/agent-configuration", agentsPlugin.DiscoveryHandler())
func (p *Plugin) DiscoveryHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpoint.Write(w, p.configuration(r.Context(), nil))
	})
}

func (p *Plugin) listCapabilities(ctx context.Context, in *endpoint.Input) endpoint.Result {
	var statuses map[string]string
	if in.Request.Header.Get("Authorization") != "" {
		pr, err := p.agentOf(ctx, in)
		if err != nil {
			return p.fail(ctx, err)
		}
		all, err := p.s.grantsOf(ctx, pr.agent, "")
		if err != nil {
			return p.fail(ctx, err)
		}
		statuses = map[string]string{}
		now := p.s.clock.Now()
		for _, g := range all {
			if g.Live(now) {
				statuses[g.Capability] = GrantActive
			} else if g.Status == GrantPending && statuses[g.Capability] != GrantActive {
				statuses[g.Capability] = GrantPending
			}
		}
	}
	list := []any{}
	for _, c := range p.caps.list {
		item := c.view()
		if statuses != nil {
			item["grant_status"] = "none"
			if s, ok := statuses[c.Name]; ok {
				item["grant_status"] = s
			}
		}
		list = append(list, item)
	}
	body := data(map[string]any{"capabilities": list, "next_cursor": nil, "has_more": false})
	if statuses == nil {
		return endpoint.JSON(http.StatusOK, body).WithHeader("Cache-Control", "public, max-age=300")
	}
	return noStore(http.StatusOK, body)
}

// registered is the 201 body of a registration or an enrolment.
func (p *Plugin) registered(a Agent, secret string, grants []Grant, ap *Approval) endpoint.Result {
	out := a.view()
	if secret != "" {
		out["client_secret"] = secret
	}
	out["grants"] = views(grants, grantView)
	out["approval"] = nil
	if ap != nil {
		out["approval"] = p.s.approvalResponse(*ap)
	}
	return noStore(http.StatusCreated, data(out))
}

// enrolment creates the agent and asks for capabilities at once, in one transaction: what the
// policy does not approve waits for the owner in an in_app approval.
func (p *Plugin) enrolment(ctx context.Context, fields map[string]any, owner Agent, asked []any, agentAsks bool, c client) (Agent, string, []Grant, *Approval, error) {
	var a Agent
	var secret string
	var grants []Grant
	var ap *Approval
	err := p.s.db.Tx(ctx, func(ctx context.Context) error {
		var err error
		if a, secret, err = p.s.createAgent(ctx, fields, owner); err != nil {
			return err
		}
		if len(asked) > 0 {
			grants, ap, err = p.s.requestGrantsAndApproval(ctx, a, asked, MethodInApp, "", "", agentAsks, c)
		}
		return err
	})
	return a, secret, grants, ap, err
}

func (p *Plugin) register(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	asked, ok := listOf(in, "capabilities")
	if !ok {
		return p.fail(ctx, refuse(ErrInvalidInput, "capabilities is a list of capability names or {name, constraints}."))
	}
	ownerType, ownerID, org, err := p.owner(ctx, in, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	c := clientOf(ctx)
	owner := Agent{OwnerType: ownerType, OwnerID: ownerID, OrganizationID: org, CreatedBy: tok.Subject()}
	a, secret, grants, ap, err := p.enrolment(ctx, in.All(), owner, asked, false, c)
	if err != nil {
		return p.fail(ctx, err)
	}
	p.s.dispatch(ctx, byUser(EventRegistered, a, tok.Subject(), map[string]any{"name": a.Name, "mode": a.Mode, "auth": a.Auth, "owner_type": ownerType}, c))
	return p.registered(a, secret, grants, ap)
}

// listOf reads an optional list field (absent or null: empty); ok is false for anything else.
func listOf(in *endpoint.Input, field string) ([]any, bool) {
	switch v := in.Value(field).(type) {
	case nil:
		return nil, true
	case []any:
		return v, true
	case map[string]any:
		out := make([]any, 0, len(v))
		for _, k := range sortedKeys(v) {
			out = append(out, v[k])
		}
		return out, true
	}
	return nil, false
}

func (p *Plugin) enroll(ctx context.Context, in *endpoint.Input) endpoint.Result {
	var host Host
	ok := false
	if m := bearerOnly.FindStringSubmatch(in.Request.Header.Get("Authorization")); m != nil {
		var err error
		if host, ok, err = p.s.hostByToken(ctx, m[1]); err != nil {
			return p.fail(ctx, err)
		}
	}
	if !ok {
		return p.fail(ctx, refuse(ErrUnauthorized, "A live host enrolment token (peh_...) is required as the bearer."))
	}
	c := clientOf(ctx)
	owner := Agent{OwnerType: host.OwnerType, OwnerID: host.OwnerID, OrganizationID: host.OrganizationID, CreatedBy: host.CreatedBy, HostID: host.ID}
	asked := make([]any, len(host.DefaultCapabilities))
	for i, name := range host.DefaultCapabilities {
		asked[i] = name
	}
	a, secret, grants, ap, err := p.enrolment(ctx, in.All(), owner, asked, true, c)
	if err != nil {
		return p.fail(ctx, err)
	}
	p.s.dispatch(ctx, byAgent(EventEnrolled, a, map[string]any{"host_id": host.ID, "name": a.Name, "mode": a.Mode, "auth": a.Auth}, c))
	return p.registered(a, secret, grants, ap)
}

func (p *Plugin) listAgents(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	list, err := p.managedAgents(ctx, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	return endpoint.JSON(http.StatusOK, data(views(list, agentView)))
}

func (p *Plugin) showAgent(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	a, err := p.managed(ctx, in, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	grants, err := p.s.grantsOf(ctx, a, "")
	if err != nil {
		return p.fail(ctx, err)
	}
	out := a.view()
	out["grants"] = views(grants, grantView)
	return endpoint.JSON(http.StatusOK, data(out))
}

func (p *Plugin) suspend(ctx context.Context, in *endpoint.Input) endpoint.Result {
	return p.transition(ctx, in, StatusActive, StatusSuspended, "Only an active agent can be suspended.", EventSuspended)
}

func (p *Plugin) resume(ctx context.Context, in *endpoint.Input) endpoint.Result {
	return p.transition(ctx, in, StatusSuspended, StatusActive, "Only a suspended agent can be resumed.", EventResumed)
}

func (p *Plugin) transition(ctx context.Context, in *endpoint.Input, from, to, otherwise, name string) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	a, err := p.managed(ctx, in, tok)
	if err == nil {
		a, err = p.s.transition(ctx, a, from, to, otherwise)
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	p.s.dispatch(ctx, byUser(name, a, tok.Subject(), map[string]any{"name": a.Name}, clientOf(ctx)))
	return endpoint.JSON(http.StatusOK, data(a.view()))
}

func (p *Plugin) revokeAgent(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	a, err := p.managed(ctx, in, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	a, sealed, err := p.s.revoke(ctx, a, tok.Subject(), "owner", clientOf(ctx))
	if err != nil {
		return p.fail(ctx, err)
	}
	out := a.view()
	out["sealed_receipt"] = sealed.view()
	return endpoint.JSON(http.StatusOK, data(out))
}

func (p *Plugin) createHost(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	defaults, ok := listOf(in, "default_capabilities")
	if !ok {
		return p.fail(ctx, refuse(ErrInvalidInput, "default_capabilities is a list of capability names."))
	}
	ownerType, ownerID, org, err := p.owner(ctx, in, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	h, secret, err := p.s.createHost(ctx, Host{OwnerType: ownerType, OwnerID: ownerID, OrganizationID: org, CreatedBy: tok.Subject()}, in.Value("name"), defaults)
	if err != nil {
		return p.fail(ctx, err)
	}
	out := h.view()
	out["enrollment_token"] = secret
	return noStore(http.StatusCreated, data(out))
}

func (p *Plugin) listHosts(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	hosts, err := p.s.liveHosts(ctx, map[string]any{"owner_type": OwnerUser, "owner_id": tok.Subject()})
	if err != nil {
		return p.fail(ctx, err)
	}
	if org := endpoint.ActorOrganization(tok); org != "" {
		ok, err := p.allows(ctx, tok, orgPermission)
		if err != nil {
			return p.fail(ctx, err)
		}
		if ok {
			more, err := p.s.liveHosts(ctx, map[string]any{"owner_type": OwnerOrganization, "owner_id": org})
			if err != nil {
				return p.fail(ctx, err)
			}
			hosts = append(hosts, more...)
		}
	}
	return endpoint.JSON(http.StatusOK, data(views(hosts, hostView)))
}

func (p *Plugin) deleteHost(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	h, ok, err := p.s.host(ctx, in.String("id"))
	if err == nil && ok {
		ok, err = p.manages(ctx, h.OwnerType, h.OwnerID, tok)
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	if !ok || h.RevokedAt != nil {
		return p.fail(ctx, refuse(ErrNotFound, "The host does not exist."))
	}
	if err := p.s.revokeHosts(ctx, map[string]any{"id": h.ID}); err != nil {
		return p.fail(ctx, err)
	}
	return endpoint.JSON(http.StatusOK, data(map[string]any{"status": "revoked"}))
}

func (p *Plugin) requestGrants(ctx context.Context, in *endpoint.Input) endpoint.Result {
	pr, err := p.agentOf(ctx, in)
	if err != nil {
		return p.fail(ctx, err)
	}
	asked, ok := listOf(in, "capabilities")
	if !ok || asked == nil {
		return p.fail(ctx, refuse(ErrInvalidInput, "capabilities is a list of capability names or {name, constraints}."))
	}
	grants, ap, err := p.s.requestGrantsAndApproval(ctx, pr.agent, asked, text(in, "preferred_method"), text(in, "binding_message"), text(in, "reason"), true, clientOf(ctx))
	if err != nil {
		return p.fail(ctx, err)
	}
	body := map[string]any{"agent_id": pr.agent.ID, "agent_capability_grants": views(grants, grantView)}
	if ap != nil {
		body["approval"] = p.s.approvalResponse(*ap)
	}
	return noStore(http.StatusOK, body)
}

func (p *Plugin) deleteGrant(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	g, ok, err := p.s.grant(ctx, in.String("id"))
	var a Agent
	if err == nil && ok {
		if a, ok, err = p.s.agent(ctx, g.AgentID); err == nil && ok {
			ok, err = p.manages(ctx, a.OwnerType, a.OwnerID, tok)
		}
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	if !ok {
		return p.fail(ctx, refuse(ErrNotFound, "The grant does not exist."))
	}
	if g, err = p.s.endGrant(ctx, g, []string{GrantActive, GrantPending}, GrantRevoked); err != nil {
		return p.fail(ctx, err)
	}
	if err := p.s.syncClientScopes(ctx, a); err != nil {
		return p.fail(ctx, err)
	}
	p.s.dispatch(ctx, byUser(EventGrantRevoked, a, tok.Subject(), map[string]any{"capability": g.Capability, "grant_id": g.ID}, clientOf(ctx)))
	return endpoint.JSON(http.StatusOK, data(g.view()))
}

func (p *Plugin) listApprovals(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	agents, err := p.managedAgents(ctx, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	pending, err := p.s.pendingApprovals(ctx, agents)
	if err != nil {
		return p.fail(ctx, err)
	}
	out := []any{}
	for _, ap := range pending {
		a, ok, err := p.s.agent(ctx, ap.AgentID)
		if err != nil {
			return p.fail(ctx, err)
		}
		var ptr *Agent
		if ok {
			ptr = &a
		}
		d, err := p.s.describe(ctx, ap, ptr)
		if err != nil {
			return p.fail(ctx, err)
		}
		out = append(out, d)
	}
	return noStore(http.StatusOK, data(out))
}

func (p *Plugin) readApproval(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	ap, ok, err := p.s.approvalByCode(ctx, in.String("user_code"))
	var a Agent
	if err == nil && ok {
		if a, ok, err = p.s.agent(ctx, ap.AgentID); err == nil && ok {
			ok, err = p.manages(ctx, a.OwnerType, a.OwnerID, tok)
		}
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	if !ok {
		return p.fail(ctx, refuse(ErrNotFound, "No pending approval has this code."))
	}
	d, err := p.s.describe(ctx, ap, &a)
	if err != nil {
		return p.fail(ctx, err)
	}
	return noStore(http.StatusOK, data(d))
}

func (p *Plugin) decideApproval(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	decision := in.Value("decision")
	constraints := in.Value("constraints")
	if (decision != "approve" && decision != "deny") || (constraints != nil && !isMap(constraints) && !isList(constraints)) {
		return p.fail(ctx, refuse(ErrInvalidInput, "decision is approve or deny; constraints, when given, an object."))
	}
	ap, ok, err := p.s.approval(ctx, in.String("id"))
	var a Agent
	if err == nil && ok {
		if a, ok, err = p.s.agent(ctx, ap.AgentID); err == nil && ok {
			ok, err = p.manages(ctx, a.OwnerType, a.OwnerID, tok)
		}
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	if !ok {
		return p.fail(ctx, refuse(ErrNotFound, "The approval does not exist."))
	}
	approve := decision == "approve"
	if approve {
		if err := p.mayApprove(ctx, ap, a, tok); err != nil {
			return p.fail(ctx, err)
		}
	}
	ap, decided, err := p.s.decide(ctx, ap, approve, tok.Subject(), constraints)
	if err != nil {
		return p.fail(ctx, err)
	}
	if err := p.s.syncClientScopes(ctx, a); err != nil {
		return p.fail(ctx, err)
	}
	name := EventGrantDenied
	if approve {
		name = EventGrantApproved
	}
	c := clientOf(ctx)
	for _, g := range decided {
		p.s.dispatch(ctx, byUser(name, a, tok.Subject(), map[string]any{"capability": g.Capability, "grant_id": g.ID, "how": ap.Method, "budget": nullInt(g.BudgetTotal)}, c))
	}
	out := ap.view()
	out["grants"] = views(decided, grantView)
	return endpoint.JSON(http.StatusOK, data(out))
}

// mayApprove checks the deciding session's strength and that the permission each capability
// requires is held: by the owner for a user's agent, by the deciding member for an organization's.
func (p *Plugin) mayApprove(ctx context.Context, ap Approval, a Agent, tok *token.Token) error {
	ok, err := p.s.satisfies(ctx, ap.Strength, tok)
	if err != nil {
		return err
	}
	if !ok {
		return &Error{Type: ErrStepUpRequired, Detail: "Approving needs a session of strength \"" + ap.Strength + "\".", Extra: map[string]any{"strength": ap.Strength}}
	}
	for _, id := range ap.GrantIDs {
		g, found, err := p.s.grant(ctx, id)
		if err != nil {
			return err
		}
		c := p.caps.find(g.Capability)
		if !found || c == nil {
			continue
		}
		var holds bool
		if a.OwnerType == OwnerUser {
			holds, err = p.s.ownerHolds(ctx, a, c.Permission)
		} else {
			holds, err = p.allows(ctx, tok, c.Permission)
		}
		if err != nil {
			return err
		}
		if !holds {
			return refuse(ErrPermissionNotHeld, "The permission \""+c.Permission+"\" the capability \""+c.Name+"\" requires is not held.")
		}
	}
	return nil
}

func (p *Plugin) executeEndpoint(ctx context.Context, in *endpoint.Input) endpoint.Result {
	pr, err := p.agentOf(ctx, in)
	if err != nil {
		return p.fail(ctx, err)
	}
	args := in.Value("arguments")
	if args == nil {
		args = in.Value("input")
	}
	done, err := p.s.execute(ctx, pr, text(in, "capability"), args, clientOf(ctx))
	if err != nil {
		return p.fail(ctx, err)
	}
	return noStore(http.StatusOK, done.view())
}

func (p *Plugin) session(ctx context.Context, in *endpoint.Input) endpoint.Result {
	pr, err := p.agentOf(ctx, in)
	if err != nil {
		return p.fail(ctx, err)
	}
	a := pr.agent
	var host any
	if a.HostID != "" {
		h, ok, err := p.s.host(ctx, a.HostID)
		if err != nil {
			return p.fail(ctx, err)
		}
		if ok {
			host = map[string]any{"id": h.ID, "name": h.Name}
		}
	}
	grants, err := p.s.grantsOf(ctx, a, "")
	if err != nil {
		return p.fail(ctx, err)
	}
	return noStore(http.StatusOK, data(map[string]any{
		"agent": a.view(), "mode": a.Mode, "owner": map[string]any{"type": a.OwnerType, "id": a.OwnerID},
		"organization_id": null(a.OrganizationID), "host": host, "authenticated_via": pr.via, "grants": views(grants, grantView),
	}))
}

func (p *Plugin) listReceipts(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	a, err := p.managed(ctx, in, tok)
	if err != nil {
		return p.fail(ctx, err)
	}
	after, limit := intField(in, "after", 0), intField(in, "limit", 100)
	list, err := p.s.receiptsOf(ctx, a.ID, int64(after), limit)
	if err != nil {
		return p.fail(ctx, err)
	}
	var cursor any
	more := false
	if len(list) > 0 {
		last := list[len(list)-1].Seq
		cursor = last
		next, err := p.s.receiptsOf(ctx, a.ID, last, 1)
		if err != nil {
			return p.fail(ctx, err)
		}
		more = len(next) > 0
	}
	return endpoint.JSON(http.StatusOK, map[string]any{"data": views(list, receiptView), "next_cursor": cursor, "has_more": more})
}

// intField reads a numeric query or body field as PHP's (int) cast of an is_numeric value.
func intField(in *endpoint.Input, field string, def int) int {
	if f, ok := numeric(in.Value(field)); ok {
		return int(f)
	}
	return def
}

func (p *Plugin) verifyReceipt(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return unauthorized()
	}
	r, ok, err := p.s.receipt(ctx, in.String("id"))
	var a Agent
	if err == nil && ok {
		if a, ok, err = p.s.agent(ctx, r.AgentID); err == nil && ok {
			if self, _ := tok.Claim(oauth.ClaimClientID).(string); self != a.ID {
				ok, err = p.manages(ctx, a.OwnerType, a.OwnerID, tok)
			}
		}
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	if !ok {
		return p.fail(ctx, refuse(ErrNotFound, "The receipt does not exist."))
	}
	v, err := p.s.verifyReceipt(ctx, r)
	if err != nil {
		return p.fail(ctx, err)
	}
	out := v.view()
	out["receipt"] = r.view()
	return noStore(http.StatusOK, data(out))
}

func (p *Plugin) adminList(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if _, refusal, ok := p.operators(ctx, "read", ""); !ok {
		return refusal
	}
	all, err := p.s.agentsWhere(ctx, map[string]any{})
	if err != nil {
		return p.fail(ctx, err)
	}
	out := []any{}
	for _, a := range all {
		// An operator scoped to one organization sees that organization's agents only.
		if _, _, ok := p.operators(ctx, "read", a.OrganizationID); ok {
			out = append(out, a.view())
		}
	}
	return endpoint.JSON(http.StatusOK, data(out))
}

func (p *Plugin) adminRevoke(ctx context.Context, in *endpoint.Input) endpoint.Result {
	a, found, err := p.s.agent(ctx, in.String("id"))
	if err != nil {
		return p.fail(ctx, err)
	}
	userID, refusal, ok := p.operators(ctx, "own", a.OrganizationID)
	if !ok {
		return refusal
	}
	if !found {
		return endpoint.Problem(http.StatusNotFound, "admin/not_found", "Not found", "The agent does not exist.", nil)
	}
	a, sealed, err := p.s.revoke(ctx, a, userID, "admin", clientOf(ctx))
	if e, isProblem := asError(err); isProblem && e.Type == ErrConflict {
		return endpoint.Problem(http.StatusConflict, "admin/conflict", "Conflict", e.Detail, nil)
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	out := a.view()
	out["sealed_receipt"] = sealed.view()
	return endpoint.JSON(http.StatusOK, data(out))
}
