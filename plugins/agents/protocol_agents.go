package agents

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/store"
)

const (
	maxReason  = 500
	maxBinding = 160
)

// asking is what a registration or a capability request asks for.
type asking struct {
	capabilities []any // names or {name, constraints}, checked
	method       string
	binding      string
	reason       string
}

// askingOf reads a protocol request's capabilities and the hints of §5.3 and §5.4. What people are
// shown is bounded and holds no control character (§8.10). preferred_method is a hint: what is not
// ciba is device_authorization, the baseline every client knows (§7).
func (p *Plugin) askingOf(in *endpoint.Input) (asking, error) {
	a := asking{method: MethodDevice, binding: text(in, "binding_message"), reason: text(in, "reason")}
	if in.String("preferred_method") == MethodCIBA {
		a.method = MethodCIBA
	}
	if !displayable(a.binding, maxBinding) || !displayable(a.reason, maxReason) {
		return a, refuse(ErrInvalidRequest, "reason is at most 500 characters and binding_message 160, without control characters.")
	}
	list, ok := listOf(in, "capabilities")
	if !ok || len(list) > maxGrantsPerRequest {
		return a, refuse(ErrInvalidRequest, "capabilities is a list of at most 20 capability names or {name, constraints}.")
	}
	var unknown []string
	for _, item := range list {
		if name, _ := requestedName(item); p.caps.find(name) == nil {
			if name == "" {
				name = "?"
			}
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return a, &Error{Type: ErrInvalidCapabilities, Detail: "One or more requested capabilities do not exist.", Extra: map[string]any{"invalid_capabilities": unknown}}
	}
	for _, item := range list {
		checked, err := requestItem(item)
		if err != nil {
			return a, err
		}
		a.capabilities = append(a.capabilities, checked)
	}
	return a, nil
}

func displayable(s string, limit int) bool {
	return utf8.RuneCountInString(s) <= limit && !strings.ContainsFunc(s, unicode.IsControl)
}

// requestedName is the capability an item of a request names, and the item when it is an object.
func requestedName(item any) (string, map[string]any) {
	if obj, ok := item.(map[string]any); ok {
		name, _ := obj["name"].(string)
		return name, obj
	}
	name, _ := item.(string)
	return name, nil
}

// requestItem is an item of a request as requestGrants reads it: an exact value (§2.13) is the one
// value the argument may have. An operator this server does not know is refused by name.
func requestItem(item any) (any, error) {
	name, obj := requestedName(item)
	fields, ok := obj["constraints"].(map[string]any)
	if !ok {
		return item, nil // none, or what parseConstraints refuses
	}
	out := make(map[string]any, len(fields))
	var unknown []string
	for field, v := range fields {
		out[field] = v
		switch v := v.(type) {
		case map[string]any:
			for op := range v {
				if field != "budget" && !slices.Contains(operators, op) && !slices.Contains(unknown, op) {
					unknown = append(unknown, op)
				}
			}
		default:
			if scalar(v) {
				out[field] = map[string]any{"in": []any{v}}
			}
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return nil, &Error{Type: ErrUnknownConstraintOperator, Detail: "A constraint has an operator this server does not know.", Extra: map[string]any{"unknown_operators": unknown}}
	}
	return map[string]any{"name": name, "constraints": out}, nil
}

// protocolRegister is POST /agent/register (§5.3) for a host its owner registered: the agent belongs to
// the host's owner, and is active unless a person must approve everything it asked for.
func (p *Plugin) protocolRegister(ctx context.Context, in *endpoint.Input) endpoint.Result {
	host, claims, err := p.s.hostOf(in.Request)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	jwk, err := protocolKey(claims["agent_public_key"])
	if e, ok := asError(err); ok && e.Type == ErrInvalidInput {
		err = refuse(ErrInvalidRequest, "agent_public_key is required in the host JWT: the agent's public key as a JWK, its public part only. agent_jwks_url is not taken. "+e.Detail)
	}
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	mode := in.Value("mode")
	if m, ok := mode.(string); mode != nil && (!ok || !slices.Contains(modes, m)) {
		return p.protocolFail(ctx, refuse(ErrUnsupportedMode, "mode is delegated or autonomous."))
	}
	asked, err := p.askingOf(in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	fields := map[string]any{"name": in.Value("name"), "mode": mode, "auth": AuthPrivateKeyJWT, "jwk": jwk}
	a, grants, approval, err := p.s.registerUnder(ctx, host, fields, asked, clientOf(ctx))
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	body := map[string]any{"agent_id": a.ID, "host_id": host.ID, "name": a.Name, "mode": a.Mode, "status": protocolStatusOf(a),
		"agent_capability_grants": p.grantStates(grants, false)}
	if approval != nil {
		body["approval"] = p.s.approvalResponse(*approval)
	}
	return noStore(http.StatusOK, body)
}

// registerUnder creates the agent under the live host with what it asks for, in one transaction. When
// a person must approve everything, the agent is pending: it cannot act until they do (§2.3).
func (s *service) registerUnder(ctx context.Context, host Host, fields map[string]any, asked asking, c client) (Agent, []Grant, *Approval, error) {
	owner := Agent{OwnerType: host.OwnerType, OwnerID: host.OwnerID, OrganizationID: host.OrganizationID, CreatedBy: host.CreatedBy, HostID: host.ID}
	var a Agent
	var grants []Grant
	var approval *Approval
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockHost(ctx, host.ID); err != nil {
			return err
		}
		var err error
		if a, _, err = s.createAgent(ctx, fields, owner); err != nil {
			return err
		}
		if len(asked.capabilities) > 0 {
			if grants, approval, err = s.requestGrantsAndApproval(ctx, a, asked.capabilities, asked.method, asked.binding, asked.reason, true, c); err != nil {
				return err
			}
		}
		if approval != nil && !slices.ContainsFunc(grants, func(g Grant) bool { return g.Status == GrantActive }) {
			a.Status = StatusPending
			_, err = s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID}, store.Data{"status": StatusPending})
		}
		return err
	})
	if err != nil {
		return Agent{}, nil, nil, err
	}
	s.dispatch(ctx, byAgent(EventEnrolled, a, map[string]any{"host_id": host.ID, "name": a.Name, "mode": a.Mode, "auth": a.Auth}, c))
	return a, grants, approval, nil
}

// protocolStatusOf is the agent's status as the protocol names it (§2.3). A suspended agent reads
// pending: it cannot act until a person lets it, and it is not for its client to reactivate.
func protocolStatusOf(a Agent) string {
	if a.Status == StatusSuspended {
		return StatusPending
	}
	return a.Status
}

// protocolStatus is GET /agent/status (§5.5).
func (p *Plugin) protocolStatus(ctx context.Context, in *endpoint.Input) endpoint.Result {
	host, _, err := p.s.hostOf(in.Request)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	id := in.String("agent_id")
	if id == "" {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "agent_id is required."))
	}
	a, ok, err := p.s.agent(ctx, id)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	if !ok || a.HostID != host.ID { // another host's agent is not told from none
		return p.protocolFail(ctx, refuse(ErrAgentNotFound, "The agent does not exist under this host."))
	}
	grants, err := p.s.grantsOf(ctx, a, "")
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	return noStore(http.StatusOK, map[string]any{"agent_id": a.ID, "host_id": host.ID, "name": a.Name, "status": protocolStatusOf(a), "mode": a.Mode,
		"agent_capability_grants": p.grantStates(grants, true), "user_id": a.Subject(), "created_at": timestamp(a.CreatedAt)})
}

// protocolRequest is POST /agent/request-capability (§5.4). status is what the reference client reads
// to know that a person must approve.
func (p *Plugin) protocolRequest(ctx context.Context, in *endpoint.Input) endpoint.Result {
	pr, err := p.s.authenticateWith(p.s.issuerJWTs, in.Request, rawBody(ctx), ownURL(p.s.settings.baseURL, in.Request))
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	asked, err := p.askingOf(in)
	if err == nil && len(asked.capabilities) == 0 {
		err = refuse(ErrInvalidRequest, "capabilities names at least one capability.")
	}
	if err == nil {
		err = p.s.notAllGranted(ctx, pr.agent, asked.capabilities)
	}
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	grants, approval, err := p.s.requestGrantsAndApproval(ctx, pr.agent, asked.capabilities, asked.method, asked.binding, asked.reason, true, clientOf(ctx))
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	body := map[string]any{"agent_id": pr.agent.ID, "status": "granted", "agent_capability_grants": p.grantStates(grants, false)}
	if approval != nil {
		body["status"], body["approval"] = GrantPending, p.s.approvalResponse(*approval)
	}
	return noStore(http.StatusOK, body)
}

// notAllGranted refuses a request whose every capability the agent holds live already (§5.13).
func (s *service) notAllGranted(ctx context.Context, a Agent, asked []any) error {
	for _, item := range asked {
		name, _ := requestedName(item)
		g, err := s.activeGrant(ctx, a, name)
		if err != nil || g == nil {
			return err
		}
	}
	return refuse(ErrAlreadyGranted, "Every capability asked for is granted already.")
}

// grantStates are the grants as the protocol shows them (§5.3), one per capability: an active one in
// full (with granted_by on request, §5.5), a pending one by name, any other as denied with the reason.
// A capability's older grants are history and are left out.
func (p *Plugin) grantStates(grants []Grant, full bool) []any {
	now := p.s.clock.Now()
	rank := func(g Grant) int {
		switch {
		case g.Live(now) && p.caps.find(g.Capability) != nil:
			return 2
		case g.Status == GrantPending:
			return 1
		}
		return 0
	}
	var order []string
	best := map[string]Grant{}
	for _, g := range grants { // oldest first
		current, seen := best[g.Capability]
		if !seen {
			order = append(order, g.Capability)
		}
		if !seen || rank(g) >= rank(current) {
			best[g.Capability] = g
		}
	}
	out := []any{}
	for _, name := range order {
		g := best[name]
		state := map[string]any{"capability": name}
		switch rank(g) {
		case 2:
			c := p.caps.find(name)
			state["status"], state["description"], state["input"] = GrantActive, c.Description, c.Input
			view := g.view()
			if len(g.Constraints) > 0 {
				state["constraints"] = view["constraints"]
			}
			if view["budget"] != nil {
				state["budget"] = view["budget"]
			}
			if g.ExpiresAt != nil {
				state["expires_at"] = view["expires_at"]
			}
			if full && g.GrantedBy != "" {
				state["granted_by"] = g.GrantedBy
			}
		case 1:
			state["status"] = GrantPending
		default:
			state["status"], state["reason"] = GrantDenied, endedReason(g)
		}
		out = append(out, state)
	}
	return out
}

// endedReason is why a grant that is neither live nor pending cannot be used.
func endedReason(g Grant) string {
	switch g.Status {
	case GrantDenied:
		return "A person denied the request."
	case GrantRevoked:
		return "The grant was revoked."
	case GrantExhausted:
		return "The grant's budget is spent."
	}
	return "The grant has ended."
}

// protocolExecute is POST /capability/execute (§5.11): the execution every other path runs, its budget
// and receipt included, answered as the protocol does; the receipt's id is in ReceiptHeader.
func (p *Plugin) protocolExecute(ctx context.Context, in *endpoint.Input) endpoint.Result {
	pr, err := p.s.authenticateWith(p.s.executeJWTs, in.Request, rawBody(ctx), ownURL(p.s.settings.baseURL, in.Request))
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	name := text(in, "capability")
	if name == "" {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "capability is required."))
	}
	done, err := p.s.execute(ctx, pr, name, in.Value("arguments"), clientOf(ctx))
	if err != nil {
		return p.protocolFail(ctx, p.s.executionRefusal(ctx, pr.agent, name, err))
	}
	return noStore(http.StatusOK, data(done.result)).WithHeader(ReceiptHeader, done.receipt.ID)
}

// executionRefusal is a refused execution as §5.11 and §2.12 word it: a violation with the
// constraint's operand, and a capability the agent was granted but the server removed as not granted.
func (s *service) executionRefusal(ctx context.Context, a Agent, name string, err error) error {
	e, ok := asError(err)
	if !ok {
		return err
	}
	switch e.Type {
	case ErrCapabilityNotFound:
		grants, err := s.grantsOf(ctx, a, "")
		if err != nil {
			return err
		}
		if slices.ContainsFunc(grants, func(g Grant) bool { return g.Capability == name }) {
			return refuse(ErrCapabilityNotGranted, "The capability \""+name+"\" was removed.")
		}
	case ErrConstraintViolated:
		list, ok := e.Extra["violations"].([]Violation)
		g, err := s.activeGrant(ctx, a, name)
		if err != nil {
			return err
		}
		if !ok || g == nil {
			return e
		}
		shown := make([]any, len(list))
		for i, v := range list {
			shown[i] = map[string]any{"field": v.Field, "constraint": map[string]any{v.Constraint: g.Constraints[v.Field][v.Constraint]}, "actual": v.Actual}
		}
		return &Error{Type: e.Type, Detail: e.Detail, Extra: map[string]any{"violations": shown}}
	}
	return e
}
