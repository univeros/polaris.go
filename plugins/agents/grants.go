package agents

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

const maxGrantsPerRequest = 20

// requested is what a grant request produced.
type requested struct {
	grants   []Grant // every capability asked, as it stands
	pending  []Grant // new grants waiting for a person
	approved []Grant // new grants approved by policy
	reused   []Grant // pending grants asked again
}

// requestGrants creates one grant per capability asked (a name or {name, constraints}): active at
// once when the policy auto-approves the risk tier within its budget ceiling, the owner holds
// the permission, and the agent neither exhausted a grant of the capability whose window still
// runs nor had one revoked (personDecides); pending otherwise. A capability already held live, or
// already waiting, is answered as it is. The caller holds the transaction.
func (s *service) requestGrants(ctx context.Context, a Agent, asked []any) (requested, error) {
	var out requested
	if len(asked) == 0 || len(asked) > maxGrantsPerRequest {
		return out, refuse(ErrInvalidInput, fmt.Sprintf("capabilities names 1 to %d capabilities.", maxGrantsPerRequest))
	}
	now := s.now()
	seen := map[string]bool{}
	for _, item := range asked {
		name, _ := item.(string)
		obj, isObj := item.(map[string]any)
		if isObj {
			name, _ = obj["name"].(string)
		}
		capability := s.caps.find(name)
		if capability == nil {
			return out, &Error{Type: ErrCapabilityNotFound, Detail: fmt.Sprintf("Unknown capability \"%s\".", name),
				Extra: map[string]any{"invalid_capabilities": []string{name}}}
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		existing, err := s.activeGrant(ctx, a, name)
		if err != nil {
			return out, err
		}
		if existing == nil {
			if existing, err = s.grantWith(ctx, a, name, GrantPending); err != nil {
				return out, err
			}
			if existing != nil {
				out.reused = append(out.reused, *existing)
			}
		}
		if existing != nil {
			out.grants = append(out.grants, *existing)
			continue
		}
		var raw any
		if isObj {
			raw = obj["constraints"]
		}
		parsed, err := parseConstraints(raw)
		if err != nil {
			return out, err
		}
		g := Grant{ID: newID(), AgentID: a.ID, Capability: name, Constraints: parsed.fields, Status: GrantPending, CreatedAt: now, UpdatedAt: now}
		g = withBudget(g, parsed.budget)
		policy, auto := s.settings.autoApprove[capability.Risk]
		auto = auto && a.OwnerType != "" // nobody's yet (a registration): a person decides
		if auto {
			// A budget the agent already spent is not refilled by asking again, and a revoked
			// capability is not handed back by the policy: a person decides.
			decided, err := s.personDecides(ctx, a, name)
			if err != nil {
				return out, err
			}
			auto = !decided
		}
		holds := false
		if auto && withinPolicy(parsed.budget, policy) {
			if holds, err = s.ownerHolds(ctx, a, capability.Permission); err != nil {
				return out, err
			}
		}
		if holds {
			if g.BudgetKind == "" && policy != nil {
				g = withBudget(g, policy)
			}
			g.Status, g.ApprovedVia = GrantActive, ViaAuto
			out.approved = append(out.approved, g)
		} else {
			out.pending = append(out.pending, g)
		}
		if err := s.db.Insert(ctx, TableGrants, g.row()); err != nil {
			return out, err
		}
		out.grants = append(out.grants, g)
	}
	if len(out.approved) > 0 {
		return out, s.syncClientScopes(ctx, a)
	}
	return out, nil
}

func isMap(v any) bool { _, ok := v.(map[string]any); return ok }

// withinPolicy: none asked (the policy's applies), or the same kind, field and window, and no larger.
// The policy's budget is a ceiling the asker cannot raise, nor refill: a shorter window than the
// policy's would be the budget again each time it passes.
func withinPolicy(asked, ceiling *budget) bool {
	if asked == nil || ceiling == nil {
		return true
	}
	if asked.kind != ceiling.kind || asked.field != ceiling.field || asked.total > ceiling.total {
		return false
	}
	return asked.window == ceiling.window
}

// withBudget sets the grant's budget; its window is the grant's lifetime from its creation.
func withBudget(g Grant, b *budget) Grant {
	g.BudgetKind, g.BudgetTotal, g.BudgetRemaining, g.BudgetField, g.ExpiresAt = "", nil, nil, "", nil
	if b == nil {
		return g
	}
	total, remaining := b.total, b.total
	g.BudgetKind, g.BudgetTotal, g.BudgetRemaining, g.BudgetField = b.kind, &total, &remaining, b.field
	if b.window > 0 {
		exp := g.CreatedAt.Add(time.Duration(b.window) * time.Second)
		g.ExpiresAt = &exp
	}
	return g
}

// approveGrant activates a pending grant once, with the owner's constraints when given.
func (s *service) approveGrant(ctx context.Context, g Grant, by, via string, c *constraints) (Grant, error) {
	if c != nil {
		g.Constraints = c.fields
		g = withBudget(g, c.budget)
	}
	g.Status, g.GrantedBy, g.ApprovedVia, g.UpdatedAt = GrantActive, by, via, s.now()
	n, err := s.db.Update(ctx, TableGrants, store.Criteria{"id": g.ID, "status": GrantPending}, store.Data(g.row()))
	if err != nil {
		return g, err
	}
	if n != 1 {
		return g, refuse(ErrConflict, "The grant is no longer pending.")
	}
	return g, nil
}

// endGrant moves a grant from one of the statuses to another with a conditional update.
func (s *service) endGrant(ctx context.Context, g Grant, from []string, to string) (Grant, error) {
	now := s.now()
	n, err := s.db.Update(ctx, TableGrants, store.Criteria{"id": g.ID, "status": from}, store.Data{"status": to, "updated_at": now})
	if err != nil {
		return g, err
	}
	if n != 1 {
		return g, refuse(ErrConflict, fmt.Sprintf("The grant is %s and cannot be %s.", g.Status, to))
	}
	g.Status, g.UpdatedAt = to, now
	return g, nil
}

// spend charges cost to the grant by a conditional update (live and covering the cost), so two
// executions can never spend the same budget; ok is false when nothing was spent. A grant without
// a budget is only checked to be still active.
func (s *service) spend(ctx context.Context, g Grant, cost int64) (*int64, bool, error) {
	criteria := store.Criteria{"id": g.ID, "status": GrantActive}
	data := store.Data{"updated_at": s.now()}
	if g.BudgetKind != "" {
		criteria["budget_remaining"] = store.Gte(cost)
		data["budget_remaining"] = store.Increment{By: -cost}
	}
	n, err := s.db.Update(ctx, TableGrants, criteria, data)
	if err != nil || n != 1 {
		return nil, false, err
	}
	if g.BudgetKind == "" {
		return nil, true, nil
	}
	row, err := s.db.FindOne(ctx, TableGrants, store.Criteria{"id": g.ID})
	if err != nil || row == nil {
		return nil, false, errors.Join(err, errors.New("agents: the grant vanished while spending"))
	}
	return rowInt(row, "budget_remaining"), true, nil
}

func (s *service) grant(ctx context.Context, id string) (Grant, bool, error) {
	row, err := s.db.FindOne(ctx, TableGrants, store.Criteria{"id": id})
	if err != nil || row == nil {
		return Grant{}, false, err
	}
	return grantFromRow(row), true, nil
}

func (s *service) grantsOf(ctx context.Context, a Agent, status string) ([]Grant, error) {
	c := store.Criteria{"agent_id": a.ID}
	if status != "" {
		c["status"] = status
	}
	rows, err := s.db.FindMany(ctx, TableGrants, c, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Grant, 0, len(rows))
	for _, r := range rows {
		out = append(out, grantFromRow(r))
	}
	return out, nil
}

// liveGrants are the agent's grants usable now.
func (s *service) liveGrants(ctx context.Context, a Agent) ([]Grant, error) {
	all, err := s.grantsOf(ctx, a, GrantActive)
	now := s.clock.Now()
	return slices.DeleteFunc(all, func(g Grant) bool { return !g.Live(now) }), err
}

// activeGrant is the agent's live grant for a capability, nil when none.
func (s *service) activeGrant(ctx context.Context, a Agent, capability string) (*Grant, error) {
	live, err := s.liveGrants(ctx, a)
	for _, g := range live {
		if g.Capability == capability {
			return &g, nil
		}
	}
	return nil, err
}

// personDecides reports whether a request for capability must wait for a person rather than the
// auto-approval policy: the agent exhausted a grant of it whose budget window has not passed (a
// budget without a window never passes: otherwise the budget would be spent as many times as the
// agent asks), or a grant of it was revoked (taking back access stands until a person approves
// again). A denial does not: a person denied a request the policy did not cover, and the policy
// still covers the smaller ones it was set for.
func (s *service) personDecides(ctx context.Context, a Agent, capability string) (bool, error) {
	exhausted, err := s.grantsOf(ctx, a, GrantExhausted)
	if err != nil {
		return false, err
	}
	now := s.clock.Now()
	for _, g := range exhausted {
		if g.Capability == capability && (g.ExpiresAt == nil || g.ExpiresAt.After(now)) {
			return true, nil
		}
	}
	revoked, err := s.grantWith(ctx, a, capability, GrantRevoked)
	return revoked != nil, err
}

func (s *service) grantWith(ctx context.Context, a Agent, capability, status string) (*Grant, error) {
	list, err := s.grantsOf(ctx, a, status)
	for _, g := range list {
		if g.Capability == capability {
			return &g, nil
		}
	}
	return nil, err
}

// permissionsOf are the permissions the agent's live grants require: what its tokens may carry.
func (s *service) permissionsOf(ctx context.Context, a Agent) ([]string, error) {
	live, err := s.liveGrants(ctx, a)
	out := []string{}
	for _, g := range live {
		if c := s.caps.find(g.Capability); c != nil && !slices.Contains(out, c.Permission) {
			out = append(out, c.Permission)
		}
	}
	return out, err
}

// ClientPermissions implements oauth.ClientAuthority: an agent's own token (client credentials)
// may carry the permissions its live grants require and the user it acts as holds now; an
// inactive agent holds none. owned is false when clientID is not an agent.
func (p *Plugin) ClientPermissions(ctx context.Context, clientID string) ([]string, bool, error) {
	a, found, err := p.s.agent(ctx, clientID)
	if err != nil || !found {
		return nil, false, err
	}
	if !a.Active() {
		return nil, true, nil
	}
	granted, err := p.s.permissionsOf(ctx, a)
	if err != nil {
		return nil, true, err
	}
	held := []string{}
	for _, permission := range granted {
		ok, err := p.s.ownerHolds(ctx, a, permission)
		if err != nil {
			return nil, true, err
		}
		if ok {
			held = append(held, permission)
		}
	}
	return held, true, nil
}

// ownerHolds reports whether the user the agent acts as holds the permission now, in its
// organization.
func (s *service) ownerHolds(ctx context.Context, a Agent, permission string) (bool, error) {
	authority, err := s.resolver.Resolve(ctx, a.Subject(), a.OrganizationID)
	if err != nil {
		return false, err
	}
	return slices.Contains(authority.Scope, permission), nil
}

// syncClientScopes makes the agent's OAuth client ask only for what its live grants require.
func (s *service) syncClientScopes(ctx context.Context, a Agent) error {
	cl, err := s.oauth.Client(ctx, a.ID)
	if errors.Is(err, oauth.ErrClientNotFound) || (err == nil && cl.DisabledAt != nil) {
		return nil
	}
	if err != nil {
		return err
	}
	permissions, err := s.permissionsOf(ctx, a)
	if err != nil {
		return err
	}
	scopes := []any{noGrantScope}
	if len(permissions) > 0 {
		scopes = make([]any, len(permissions))
		for i, p := range permissions {
			scopes[i] = p
		}
	}
	_, _, err = s.oauth.UpdateClient(ctx, cl, oauth.ClientFields{"scopes": scopes}, false)
	return err
}
