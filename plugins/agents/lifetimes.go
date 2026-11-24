package agents

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/store"
)

// Lifetimes bound the agents that a host's JWT registered (Agent Auth Protocol §2.4); zero is unlimited.
// Other agents do not expire: they have no host to reactivate them. Whole seconds.
type Lifetimes struct {
	// Session is how long an agent may go without a request, at least two minutes, as its last use is
	// recorded once a minute. Past it the agent is expired until its host reactivates it.
	Session time.Duration
	// Max is how long an agent stays active since it was activated. Past it, it is expired too.
	Max time.Duration
	// Absolute is how long an agent lives since it was created. Past it, it is revoked for good.
	Absolute time.Duration
}

// usedEvery is how often an agent's last use is recorded at most.
const usedEvery = time.Minute

func (l Lifetimes) check(bad func(format string, args ...any)) {
	for name, d := range map[string]time.Duration{"Session": l.Session, "Max": l.Max, "Absolute": l.Absolute} {
		if d < 0 || d%time.Second != 0 {
			bad("Config.Lifetimes.%s must be whole seconds, not negative (0: unlimited), got %s", name, d)
		}
	}
	if l.Session > 0 && l.Session < 2*usedEvery {
		bad("Config.Lifetimes.Session must be at least %s, got %s", 2*usedEvery, l.Session)
	}
}

// activation is when the agent was last activated.
func (a Agent) activation() time.Time {
	if a.ActivatedAt != nil {
		return *a.ActivatedAt
	}
	return a.CreatedAt
}

// expiry is when an active agent expires or is revoked by its lifetimes; nil for never.
func (l Lifetimes) expiry(a Agent) *time.Time {
	if !a.ofHostJWT() {
		return nil
	}
	used := a.activation()
	if a.LastUsedAt != nil && a.LastUsedAt.After(used) {
		used = *a.LastUsedAt
	}
	var first *time.Time
	for _, end := range []struct {
		from time.Time
		life time.Duration
	}{{used, l.Session}, {a.activation(), l.Max}, {a.CreatedAt, l.Absolute}} {
		if at := end.from.Add(end.life); end.life > 0 && (first == nil || at.Before(*first)) {
			first = &at
		}
	}
	return first
}

// over reports whether the agent's absolute lifetime has passed.
func (l Lifetimes) over(a Agent, now time.Time) bool {
	return a.ofHostJWT() && l.Absolute > 0 && !now.Before(a.CreatedAt.Add(l.Absolute))
}

// loaded is the agent of a row as it stands now: past its lifetimes it reads expired, or revoked, whatever
// is stored, so that no job has to say so.
func (s *service) loaded(row store.Row) Agent {
	a, now := agentFromRow(row), s.clock.Now()
	expiry := s.settings.lifetimes.expiry(a)
	switch {
	case a.Status != StatusActive && a.Status != StatusSuspended && a.Status != StatusPending:
	case s.settings.lifetimes.over(a, now):
		a.Status = StatusRevoked
	case a.Status == StatusActive && expiry != nil && !now.Before(*expiry):
		a.Status = StatusExpired
	}
	return a
}

// used records that the agent was used, at most once a minute.
func (s *service) used(ctx context.Context, a Agent) error {
	now := s.now()
	if !a.ofHostJWT() || (a.LastUsedAt != nil && now.Sub(*a.LastUsedAt) < usedEvery) {
		return nil
	}
	_, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID}, store.Data{"last_used_at": now})
	return err
}

// revokeOver revokes the agents past their absolute lifetime, with the kill switch.
func (s *service) revokeOver(ctx context.Context) error {
	if s.settings.lifetimes.Absolute <= 0 {
		return nil
	}
	list, err := s.agentsWhere(ctx, store.Criteria{"status": []string{StatusActive, StatusSuspended, StatusPending},
		"created_at": store.Lte(s.now().Add(-s.settings.lifetimes.Absolute))})
	if err != nil {
		return err
	}
	for _, a := range list {
		if !a.ofHostJWT() {
			continue
		}
		if _, _, err := s.revoke(ctx, a, "", "absolute_lifetime", client{}); err != nil {
			if e, ok := asError(err); !ok || e.Type != ErrConflict { // revoked meanwhile
				return err
			}
		}
	}
	return nil
}

// protocolReactivate is POST /agent/reactivate (§5.6): an expired agent of the calling host, with the host's
// default capabilities and no other it had.
func (p *Plugin) protocolReactivate(ctx context.Context, in *endpoint.Input) endpoint.Result {
	h, err := p.hostRequest(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	a, err := p.hostsAgent(ctx, h, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	var approval *Approval
	switch {
	case a.Status != StatusRejected && p.s.settings.lifetimes.over(a, p.s.clock.Now()):
		return p.protocolFail(ctx, p.s.refuseOver(ctx, a, clientOf(ctx)))
	case a.Status == StatusActive:
	case a.Status == StatusExpired, a.Status == StatusPending && a.ActivatedAt != nil:
		if a, approval, err = p.s.reactivate(ctx, h, a, clientOf(ctx)); err != nil {
			return p.protocolFail(ctx, err)
		}
	case a.Status == StatusSuspended: // its owner's to resume (5.2)
		return p.protocolFail(ctx, refuse(ErrAgentPending, "The agent is paused by its owner, who may resume it."))
	default:
		return p.protocolFail(ctx, assertActive(a))
	}
	grants, err := p.s.grantsOf(ctx, a, "")
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	body := p.agentState(a, grants)
	if approval != nil {
		delete(body, "activated_at")
		body["approval"] = p.s.approvalResponse(*approval)
	}
	return noStore(http.StatusOK, body)
}

// refuseOver refuses an agent past its absolute lifetime, revoking it when nothing did yet.
func (s *service) refuseOver(ctx context.Context, a Agent, c client) error {
	_, _, err := s.revoke(ctx, a, "", "absolute_lifetime", c)
	if e, ok := asError(err); ok && e.Type == ErrConflict {
		return refuse(ErrAgentRevoked, "The agent is revoked.")
	}
	if err != nil {
		return err
	}
	return refuse(ErrAbsoluteLifetimeExceeded, "The agent's absolute lifetime has passed; register another.")
}

// reactivate brings the agent back to its host's default capabilities, by the policy (decay). The agent
// is active with new clocks, or pending when a person must approve all of it; asked again then, it waits for
// the same approval, opened again when that expired.
func (s *service) reactivate(ctx context.Context, h Host, a Agent, c client) (Agent, *Approval, error) {
	var approval *Approval
	waits := a.Status == StatusPending
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockHost(ctx, h.ID); err != nil {
			return err
		}
		from := StatusActive // what an expired one is stored as
		if waits {
			from = StatusPending
		}
		n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID, "status": from}, store.Data{"id": a.ID})
		if err != nil {
			return err
		}
		stored, ok, err := s.agent(ctx, a.ID)
		if err != nil {
			return err
		}
		if n != 1 || !ok || stored.Status != a.Status { // reactivated, or decided, meanwhile
			return refuse(ErrConflict, "The agent changed meanwhile.")
		}
		if waits {
			_, open, _, err := s.waiting(ctx, a, "", "", s.strengthFor)
			approval = &open
			return err
		}
		if err := s.decay(ctx, h, a); err != nil {
			return err
		}
		var grants []Grant
		if len(h.DefaultCapabilities) > 0 {
			asked := make([]any, len(h.DefaultCapabilities))
			for i, name := range h.DefaultCapabilities {
				asked[i] = name
			}
			if grants, approval, err = s.requestGrantsAndApproval(ctx, a, asked, "", "", "The agent is reactivated.", true, c); err != nil {
				return err
			}
		}
		now := s.now()
		set := store.Data{"status": StatusActive, "activated_at": now, "last_used_at": now, "updated_at": now}
		if approval != nil && !anyActive(grants) { // the clocks stay: denied, it is expired again
			set = store.Data{"status": StatusPending, "updated_at": now}
		} else {
			approval, a.ActivatedAt, a.LastUsedAt = nil, &now, &now
		}
		a.Status = set["status"].(string)
		_, err = s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID}, set)
		return err
	})
	if err != nil {
		return a, nil, err
	}
	if err := s.syncClientScopes(ctx, a); err != nil {
		return a, nil, err
	}
	if !waits {
		s.dispatch(ctx, byAgent(EventReactivated, a, map[string]any{"host_id": h.ID, "status": a.Status}, c))
	}
	return a, approval, nil
}

// decay ends what the agent holds and asks for beyond its host's default capabilities, and the approvals that
// wait. A live grant the policy gave of one is kept as it is, with what is left of its budget: ending it and
// giving it again would refill the budget, which the policy never does.
func (s *service) decay(ctx context.Context, h Host, a Agent) error {
	held, err := s.liveGrants(ctx, a)
	if err != nil {
		return err
	}
	kept := []string{}
	for _, g := range held {
		c := s.caps.find(g.Capability)
		if c == nil || g.ApprovedVia != ViaAuto || !slices.Contains(h.DefaultCapabilities, g.Capability) {
			continue
		}
		if _, auto := s.settings.autoApprove[c.Risk]; auto {
			kept = append(kept, g.ID)
		}
	}
	now := s.now()
	all, err := s.grantsOf(ctx, a, "")
	if err != nil {
		return err
	}
	for _, g := range all {
		if (g.Status != GrantActive && g.Status != GrantPending) || slices.Contains(kept, g.ID) {
			continue
		}
		if _, err := s.db.Update(ctx, TableGrants, store.Criteria{"id": g.ID, "status": []string{GrantActive, GrantPending}},
			store.Data{"status": GrantRevoked, "updated_at": now}); err != nil {
			return err
		}
	}
	_, err = s.db.Update(ctx, TableApprovals, store.Criteria{"agent_id": a.ID, "status": ApprovalPending},
		store.Data{"status": ApprovalCancelled, "updated_at": now})
	return err
}
