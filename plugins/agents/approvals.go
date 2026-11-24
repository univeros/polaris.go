package agents

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

const (
	// codeAlphabet is AAP's unambiguous alphabet: no vowels, no 0/O, 1/I/L.
	codeAlphabet = "BCDFGHJKMNPQRSTVWXZ"
	codeLength   = 8
	pollInterval = 5
	// maxPending is the most approvals an agent may have waiting at once.
	maxPending = 5
)

var notAlnum = regexp.MustCompile(`[^A-Za-z0-9]`)

// requestGrantsAndApproval is a grant request end to end: the grants, one approval for what a
// person must decide (of the strength the riskiest capability needs), and the events.
func (s *service) requestGrantsAndApproval(ctx context.Context, a Agent, asked []any, method, binding, reason string, agentAsks bool, c client) ([]Grant, *Approval, error) {
	var res requested
	var approval *Approval
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockAgent(ctx, a.ID); err != nil {
			return err
		}
		var err error
		if res, err = s.requestGrants(ctx, a, asked); err != nil {
			return err
		}
		pending := res.pending
		// A grant already waiting keeps its approval while it is open; one whose approval expired
		// joins a new one.
		for _, g := range res.reused {
			open, ok, err := s.approval(ctx, g.ApprovalID)
			if err != nil {
				return err
			}
			if ok && open.Status == ApprovalPending {
				if approval == nil {
					approval = &open
				}
			} else {
				pending = append(pending, g)
			}
		}
		if len(pending) > 0 {
			opened, err := s.openApproval(ctx, a, pending, method, s.strengthFor(pending), binding)
			if err != nil {
				return err
			}
			approval = &opened
			for i, g := range res.grants {
				if slices.Contains(opened.GrantIDs, g.ID) {
					res.grants[i].ApprovalID = opened.ID
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	data := requestedData(res.grants, approval, reason, binding)
	events := []Event{byUser(EventGrantRequested, a, a.Subject(), data, c)}
	if agentAsks {
		events[0] = byAgent(EventGrantRequested, a, data, c)
	}
	for _, g := range res.approved {
		events = append(events, bySystem(EventGrantApproved, a, map[string]any{"capability": g.Capability, "grant_id": g.ID, "how": ViaAuto, "budget": nullInt(g.BudgetTotal)}))
	}
	s.dispatch(ctx, events...)
	return res.grants, approval, nil
}

// requestedData is what EventGrantRequested says.
func requestedData(grants []Grant, approval *Approval, reason, binding string) map[string]any {
	data := map[string]any{"capabilities": capabilityNames(grants), "reason": null(reason), "approval_id": nil, "method": nil, "user_code": nil, "binding_message": null(binding)}
	if approval != nil {
		data["approval_id"], data["method"], data["user_code"] = approval.ID, approval.Method, approval.UserCode
	}
	return data
}

func capabilityNames(grants []Grant) []string {
	names := make([]string, len(grants))
	for i, g := range grants {
		names[i] = g.Capability
	}
	return names
}

// strengthFor is the strongest strength the grants' capabilities require.
func (s *service) strengthFor(grants []Grant) string {
	rank := 0
	for _, g := range grants {
		risk := RiskHigh
		if c := s.caps.find(g.Capability); c != nil {
			risk = c.Risk
		}
		rank = max(rank, slices.Index(strengths, s.settings.strengthFor(risk)))
	}
	return strengths[rank]
}

// openApproval opens an approval for pending grants with a user code unique among the pending
// ones; at most maxPending per agent.
func (s *service) openApproval(ctx context.Context, a Agent, grants []Grant, method, strength, binding string) (Approval, error) {
	if method == "" {
		method = MethodInApp
		if s.settings.approvalURL != "" {
			method = MethodDevice
		}
	}
	if !slices.Contains(methods, method) {
		return Approval{}, refuse(ErrInvalidInput, "preferred_method is device_authorization, ciba or in_app.")
	}
	if utf8.RuneCountInString(binding) > 160 {
		return Approval{}, refuse(ErrInvalidInput, "binding_message is at most 160 characters.")
	}
	// The caller holds the agent's row lock (lockAgent), so the count and the insert are atomic.
	open, err := s.pendingApprovals(ctx, []Agent{a})
	if err != nil {
		return Approval{}, err
	}
	if len(open) >= maxPending {
		return Approval{}, refuse(ErrConflict, fmt.Sprintf("The agent has %d approvals waiting; one must be decided or expire first.", maxPending))
	}
	code, err := s.freshCode(ctx)
	if err != nil {
		return Approval{}, err
	}
	now := s.now()
	ap := Approval{ID: newID(), AgentID: a.ID, Method: method, Strength: strength, UserCode: code, BindingMessage: binding,
		GrantIDs: []string{}, Status: ApprovalPending, ExpiresAt: now.Add(time.Duration(s.settings.approvalTTL) * time.Second), CreatedAt: now, UpdatedAt: now}
	for _, g := range grants {
		ap.GrantIDs = append(ap.GrantIDs, g.ID)
	}
	if err := s.db.Insert(ctx, TableApprovals, ap.row()); err != nil {
		return Approval{}, err
	}
	if _, err := s.db.Update(ctx, TableGrants, store.Criteria{"id": ap.GrantIDs}, store.Data{"approval_id": ap.ID}); err != nil {
		return Approval{}, err
	}
	return ap, nil
}

// decide records the decision once, in one transaction: approved grants become active (with the
// owner's constraints, validated before anything is written), denied ones denied. For an unknown
// host's registration (reg, not nil) approving creates the agent it becomes, denying rejects it.
func (s *service) decide(ctx context.Context, ap Approval, approve bool, by string, raw any, reg *registration) (Approval, []Grant, error) {
	now := s.clock.Now()
	if !ap.Pending(now) {
		status := ap.Status
		if !ap.ExpiresAt.After(now) {
			status = ApprovalExpired
		}
		return ap, nil, refuse(ErrConflict, fmt.Sprintf("The approval is %s.", status))
	}
	var c *constraints
	if raw != nil {
		parsed, err := parseConstraints(raw)
		if err != nil {
			return ap, nil, err
		}
		c = &parsed
	}
	status := ApprovalDenied
	if approve {
		status = ApprovalApproved
	}
	var decided []Grant
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		var err error
		if reg != nil {
			err = s.lockRegistration(ctx, reg.ID, refuse(ErrConflict, "The registration was already decided."))
		} else {
			err = s.lockAgent(ctx, ap.AgentID) // the order the kill switch locks in
		}
		if err != nil {
			return err
		}
		n, err := s.db.Update(ctx, TableApprovals, store.Criteria{"id": ap.ID, "status": ApprovalPending, "expires_at": store.Gt(s.now())},
			store.Data{"status": status, "decided_by": by, "updated_at": s.now()})
		if err != nil {
			return err
		}
		if n != 1 {
			return refuse(ErrConflict, "The approval was already decided.")
		}
		switch {
		case reg != nil && approve:
			err = s.admit(ctx, *reg)
		case reg != nil:
			err = s.reject(ctx, *reg)
		}
		if err != nil {
			return err
		}
		for _, id := range ap.GrantIDs {
			g, ok, err := s.grant(ctx, id)
			if err != nil {
				return err
			}
			if !ok || g.Status != GrantPending {
				continue
			}
			if approve {
				g, err = s.approveGrant(ctx, g, by, ap.Method, c)
			} else {
				g, err = s.endGrant(ctx, g, []string{GrantPending}, GrantDenied)
			}
			if err != nil {
				return err
			}
			decided = append(decided, g)
		}
		return s.settle(ctx, ap.AgentID, approve)
	})
	if err != nil {
		return ap, nil, err
	}
	ap.Status, ap.DecidedBy, ap.UpdatedAt = status, by, s.now()
	return ap, decided, nil
}

// settle ends a registration that waited for this decision (StatusPending): the agent is active, or
// rejected for good (§7.1), its OAuth client disabled and its tokens revoked. One that was active before
// waited to be reactivated (§5.6): denied, it is expired as it was. Any other agent stays as it is.
func (s *service) settle(ctx context.Context, agentID string, approved bool) error {
	now := s.now()
	if approved {
		_, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": agentID, "status": StatusPending},
			store.Data{"status": StatusActive, "activated_at": now, "last_used_at": now, "updated_at": now})
		return err
	}
	n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": agentID, "status": StatusPending, "activated_at": nil}, store.Data{"status": StatusRejected, "updated_at": now})
	if err != nil {
		return err
	}
	if n == 0 {
		_, err = s.db.Update(ctx, TableAgents, store.Criteria{"id": agentID, "status": StatusPending}, store.Data{"status": StatusActive, "updated_at": now})
		return err
	}
	if err := s.disableClient(ctx, agentID); err != nil {
		return err
	}
	_, err = s.oauth.RevokeClientTokens(ctx, agentID)
	return err
}

// satisfies reports whether the deciding session is strong enough: session any; step_up core's
// step-up rule (a user with a confirmed factor re-authenticated within the step-up max age);
// passkey a recent passkey sign-in. In the protocol's mode (§8.11) every approval needs a recent sign-in,
// step_up being satisfied by any session of a person without a second factor, and a passkey must have
// verified the person, as the session's mfa says.
func (s *service) satisfies(ctx context.Context, strength string, tok *token.Token) (bool, error) {
	recent, protocol := s.recent(tok), s.settings.discovery == DiscoveryAgentAuth
	if protocol && !recent {
		return false, nil
	}
	switch strength {
	case StrengthStepUp:
		if recent {
			return true, nil
		}
		has, err := s.mfa.HasConfirmedFactor(ctx, tok.Subject())
		return !has, err
	case StrengthPasskey:
		amr, _ := tok.Claim("amr").([]any)
		verified, _ := tok.Claim("mfa").(bool)
		return recent && slices.Contains(amr, any("passkey")) && (verified || !protocol), nil
	}
	return true, nil
}

// recent reports whether the session's last full authentication is within the step-up max age.
func (s *service) recent(tok *token.Token) bool {
	authTime, ok := tok.Claim("auth_time").(int64)
	return ok && s.clock.Now().Unix()-authTime <= int64(s.stepUpMaxAge/time.Second)
}

// approval reads an approval as it stands now: a pending one past its expiry reads expired.
func (s *service) approval(ctx context.Context, id string) (Approval, bool, error) {
	if id == "" {
		return Approval{}, false, nil
	}
	row, err := s.db.FindOne(ctx, TableApprovals, store.Criteria{"id": id})
	if err != nil || row == nil {
		return Approval{}, false, err
	}
	return s.read(row), true, nil
}

func (s *service) read(row store.Row) Approval {
	ap := approvalFromRow(row)
	if ap.Status == ApprovalPending && !ap.ExpiresAt.After(s.clock.Now()) {
		ap.Status = ApprovalExpired
	}
	return ap
}

// approvalByCode is the pending approval behind a user code (dashes and case do not matter).
func (s *service) approvalByCode(ctx context.Context, code string) (Approval, bool, error) {
	code = strings.ToUpper(notAlnum.ReplaceAllString(code, ""))
	if len(code) != codeLength {
		return Approval{}, false, nil
	}
	row, err := s.db.FindOne(ctx, TableApprovals, store.Criteria{"user_code": code, "status": ApprovalPending})
	if err != nil || row == nil {
		return Approval{}, false, err
	}
	ap := s.read(row)
	return ap, ap.Pending(s.clock.Now()), nil
}

// lockAgent serializes one agent's grant requests, so concurrent ones can neither pass the
// pending-approval cap nor create one capability's grant twice. It must be the first statement of
// the transaction: a no-op UPDATE of the agent's row takes its row lock on PostgreSQL and MySQL
// (before MySQL's snapshot is taken, so the reads that follow are current) and the database write
// lock on SQLite; the lock holds until commit. memstore transactions are serial already.
func (s *service) lockAgent(ctx context.Context, agentID string) error {
	_, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": agentID}, store.Data{"id": agentID})
	return err
}

// pendingApprovals are the agents' approvals still waiting.
func (s *service) pendingApprovals(ctx context.Context, agents []Agent) ([]Approval, error) {
	out := []Approval{}
	for _, a := range agents {
		rows, err := s.db.FindMany(ctx, TableApprovals, store.Criteria{"agent_id": a.ID, "status": ApprovalPending},
			store.Query{OrderBy: []store.Order{{Column: "id"}}})
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			if ap := s.read(r); ap.Pending(s.clock.Now()) {
				out = append(out, ap)
			}
		}
	}
	return out, nil
}

// freshCode is a user code no pending approval holds.
func (s *service) freshCode(ctx context.Context) (string, error) {
	for range 10 {
		b := make([]byte, codeLength)
		for i := range b {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeAlphabet))))
			if err != nil {
				return "", err
			}
			b[i] = codeAlphabet[n.Int64()]
		}
		n, err := s.db.Count(ctx, TableApprovals, store.Criteria{"user_code": string(b), "status": ApprovalPending})
		if err != nil {
			return "", err
		}
		if n == 0 {
			return string(b), nil
		}
	}
	return "", refuse(ErrConflict, "No user code is free right now; try again.")
}

// displayCode is XXXX-XXXX, as a person reads it.
func displayCode(code string) string {
	if len(code) != codeLength {
		return code
	}
	return code[:4] + "-" + code[4:]
}

// approvalResponse is the approval as the agent sees it (AAP's shape).
func (s *service) approvalResponse(ap Approval) map[string]any {
	code := displayCode(ap.UserCode)
	uri := s.settings.approvalURL
	if uri == "" {
		uri = s.settings.baseURL + "/agents/approvals/code"
	}
	expiresIn := s.settings.approvalTTL
	if ap.reused { // what is left of it
		expiresIn = int64(ap.ExpiresAt.Sub(s.now()) / time.Second)
	}
	return map[string]any{
		"id": ap.ID, "method": ap.Method, "strength": ap.Strength, "user_code": code, "verification_uri": uri,
		"verification_uri_complete": uri + "?user_code=" + code, "expires_in": expiresIn,
		"interval": pollInterval, "binding_message": null(ap.BindingMessage),
	}
}

// describe is what the owner sees of an approval: it, how to reach it, the agent and the grants; of an
// unknown host's registration, also the host and the reason as the host tells them.
func (s *service) describe(ctx context.Context, ap Approval, a *Agent, reg *registration) (map[string]any, error) {
	out := ap.view()
	for k, v := range s.approvalResponse(ap) {
		out[k] = v
	}
	out["agent"] = nil
	if a != nil {
		out["agent"] = a.view()
	}
	grants := []any{}
	for _, id := range ap.GrantIDs {
		g, ok, err := s.grant(ctx, id)
		if err != nil {
			return nil, err
		}
		if ok {
			grants = append(grants, g.view())
		}
	}
	out["grants"] = grants
	if reg != nil {
		out["reason"] = null(reg.Reason)
		out["host"] = map[string]any{"id": a.HostID, "name": reg.HostName, "key_thumbprint": reg.HostThumbprint, "known": reg.known}
	}
	return out, nil
}
