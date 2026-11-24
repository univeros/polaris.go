package agents

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

const (
	// registrationKept is how long a registration nobody decided outlives its approval, and a denied one
	// its denial (§7.1, §10.9).
	registrationKept = 24 * time.Hour
	// pruneAtOnce is how many ended registrations a new one deletes.
	pruneAtOnce = 20
	// unnamedHost is the name of a host that sends no host_name.
	unnamedHost = "Agent host"
)

// registration is what a host the server does not know asked for (polaris_agent_registration, §2.8): an
// agent that waits for a person, or that one denied. Until a person approves it there is no host, no
// agent and no OAuth client (§8.10), and nobody owns it: whoever approves it does. Its grants and its
// approval are rows that name the agent it may become.
type registration struct {
	ID              string // of the agent
	HostID          string // of the host, unless it is known by then
	HostThumbprint  string
	HostJWK         map[string]any
	HostName        string // what the host says it is
	AgentThumbprint string
	AgentJWK        map[string]any
	Name, Mode      string
	Reason          string
	Status          string // StatusPending or StatusRejected
	ExpiresAt       time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time

	known   bool  // the host's key is a host's by now
	becomes Agent // the agent, as the person deciding would own it
}

// agent is the agent the registration may become: pending or rejected, and nobody's.
func (r registration) agent() Agent {
	status := StatusRejected
	if r.Status == StatusPending {
		status = StatusPending
	}
	return Agent{ID: r.ID, Name: r.Name, Mode: r.Mode, HostID: r.HostID, Auth: AuthPrivateKeyJWT, PublicJWK: r.AgentJWK, Status: status,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, keyThumbprint: r.AgentThumbprint}
}

// agentFor is agent as a person would own it: by the host's owner when the host is known, else by the
// person who approves it, in their active organization.
func (r registration) agentFor(h *Host, userID, organizationID string) Agent {
	a := r.agent()
	if h != nil {
		a.HostID, a.OwnerType, a.OwnerID, a.OrganizationID, a.CreatedBy = h.ID, h.OwnerType, h.OwnerID, h.OrganizationID, h.CreatedBy
		return a
	}
	a.OwnerType, a.OwnerID, a.OrganizationID, a.CreatedBy = OwnerUser, userID, organizationID, userID
	return a
}

func (r registration) row() store.Row {
	return store.Row{
		"id": r.ID, "host_id": r.HostID, "host_thumbprint": r.HostThumbprint, "host_jwk": jsonColumn(r.HostJWK), "host_name": r.HostName,
		"agent_thumbprint": r.AgentThumbprint, "agent_jwk": jsonColumn(r.AgentJWK), "name": r.Name, "mode": r.Mode, "reason": null(r.Reason),
		"status": r.Status, "expires_at": r.ExpiresAt, "created_at": r.CreatedAt, "updated_at": r.UpdatedAt,
	}
}

func registrationFromRow(r store.Row) registration {
	reg := registration{ID: r.String("id"), HostID: r.String("host_id"), HostThumbprint: r.String("host_thumbprint"), HostName: r.String("host_name"),
		AgentThumbprint: r.String("agent_thumbprint"), Name: r.String("name"), Mode: r.String("mode"), Reason: r.String("reason"), Status: r.String("status"),
		ExpiresAt: rowTime(r, "expires_at"), CreatedAt: rowTime(r, "created_at"), UpdatedAt: rowTime(r, "updated_at")}
	reg.HostJWK, _ = rowJSON(r, "host_jwk").(map[string]any)
	reg.AgentJWK, _ = rowJSON(r, "agent_jwk").(map[string]any)
	return reg
}

// registrationWhere is the registration the criteria name; none where unknown hosts are not taken, and
// none past its expiry, deleted yet or not.
func (s *service) registrationWhere(ctx context.Context, c store.Criteria) (registration, bool, error) {
	if !s.settings.dynamicHosts {
		return registration{}, false, nil
	}
	c["expires_at"] = store.Gte(s.now())
	row, err := s.db.FindOne(ctx, TableRegistrations, c)
	if err != nil || row == nil {
		return registration{}, false, err
	}
	return registrationFromRow(row), true, nil
}

// registration is the registration of the agent id names.
func (s *service) registration(ctx context.Context, id string) (registration, bool, error) {
	if !possibleID(id) {
		return registration{}, false, nil
	}
	return s.registrationWhere(ctx, store.Criteria{"id": id})
}

// registrationOf is the registration of an agent's key by a host's (§5.3).
func (s *service) registrationOf(ctx context.Context, hostThumbprint, agentThumbprint string) (registration, bool, error) {
	return s.registrationWhere(ctx, store.Criteria{"host_thumbprint": hostThumbprint, "agent_thumbprint": agentThumbprint})
}

// registeredHost is the host the registration's key belongs to by now, live or revoked; nil for none.
func (s *service) registeredHost(ctx context.Context, r registration) (*Host, error) {
	row, err := s.db.FindOne(ctx, TableHosts, store.Criteria{"key_thumbprint": r.HostThumbprint})
	if err != nil || row == nil {
		return nil, err
	}
	h := hostFromRow(row)
	return &h, nil
}

// register stores a new registration with what it asks for, all of it for a person to decide.
func (s *service) register(ctx context.Context, r registration, asked asking, c client) (registration, []Grant, Approval, error) {
	// An ended registration gives up its keys, and the table does not outgrow who writes it.
	for _, ended := range []store.Criteria{{"host_thumbprint": r.HostThumbprint, "agent_thumbprint": r.AgentThumbprint}, {}} {
		if _, err := s.pruneRegistrations(ctx, ended, pruneAtOnce); err != nil {
			return r, nil, Approval{}, err
		}
	}
	r.ID, r.HostID, r.Status = newID(), newID(), StatusPending
	// The host's other registrations announced an id for it.
	other, ok, err := s.registrationWhere(ctx, store.Criteria{"host_thumbprint": r.HostThumbprint})
	if err != nil {
		return r, nil, Approval{}, err
	}
	if ok {
		r.HostID = other.HostID
	}
	r.CreatedAt = s.now()
	r.UpdatedAt, r.ExpiresAt = r.CreatedAt, s.registrationExpiry()
	var grants []Grant
	var approval Approval
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.db.Insert(ctx, TableRegistrations, r.row()); err != nil {
			return err
		}
		if len(asked.capabilities) > 0 {
			res, err := s.requestGrants(ctx, r.agent(), asked.capabilities)
			if err != nil {
				return err
			}
			grants = res.grants
		}
		var err error
		approval, err = s.openApproval(ctx, r.agent(), grants, MethodDevice, s.linkStrength(grants), asked.binding)
		return err
	})
	if err != nil {
		return r, nil, Approval{}, err
	}
	// Without the user code and the approval's id: whoever signs in with either may link the host.
	e := bySystem(EventRegistrationRequested, r.agent(), map[string]any{"host_id": r.HostID, "host_key": r.HostThumbprint, "host_name": r.HostName,
		"name": r.Name, "mode": r.Mode, "capabilities": capabilityNames(grants), "reason": null(r.Reason)})
	e.IP, e.UserAgent = c.ip, c.userAgent
	s.dispatch(ctx, e)
	return r, grants, approval, nil
}

// registrationExpiry is when a registration whose approval opens now may be deleted.
func (s *service) registrationExpiry() time.Time {
	return s.now().Add(time.Duration(s.settings.approvalTTL)*time.Second + registrationKept)
}

// linkStrength is the strength of approving an unknown host's registration: what its capabilities need, at
// least a fresh sign-in (§8.11), and what the capabilities the policy approves need, as the host may then
// register agents that get those without a person.
func (s *service) linkStrength(grants []Grant) string {
	rank := max(slices.Index(strengths, StrengthStepUp), slices.Index(strengths, s.strengthFor(grants)))
	for _, c := range s.caps.list {
		if _, auto := s.settings.autoApprove[c.Risk]; auto {
			rank = max(rank, slices.Index(strengths, s.settings.strengthFor(c.Risk)))
		}
	}
	return strengths[rank]
}

// retried answers a registration made before (§5.3): pending as it is, its approval opened again when
// that expired; a decided one is refused.
func (s *service) retried(ctx context.Context, r registration, binding string) ([]Grant, Approval, error) {
	var grants []Grant
	var approval Approval
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockRegistration(ctx, r.ID, errAgentExists()); err != nil {
			return err
		}
		var opened bool
		var err error
		if grants, approval, opened, err = s.waiting(ctx, r.agent(), MethodDevice, binding, s.linkStrength); err != nil || !opened {
			return err
		}
		_, err = s.db.Update(ctx, TableRegistrations, store.Criteria{"id": r.ID}, store.Data{"expires_at": s.registrationExpiry(), "updated_at": s.now()})
		return err
	})
	return grants, approval, err
}

// waiting is what a pending registration waits for: its pending grants and the open approval, or, opened,
// a new one when that expired. The caller holds its lock.
func (s *service) waiting(ctx context.Context, a Agent, method, binding string, strength func([]Grant) string) (grants []Grant, ap Approval, opened bool, err error) {
	if grants, err = s.grantsOf(ctx, a, GrantPending); err != nil {
		return nil, ap, false, err
	}
	open, err := s.pendingApprovals(ctx, []Agent{a})
	if err != nil {
		return nil, ap, false, err
	}
	if len(open) > 0 {
		open[0].reused = true
		return grants, open[0], false, nil
	}
	ap, err = s.openApproval(ctx, a, grants, method, strength(grants), binding)
	return grants, ap, true, err
}

func errAgentExists() *Error {
	return refuse(ErrAgentExists, "An agent with this key is registered under the host; a new registration takes a new key.")
}

// lockRegistration serializes what is done with a pending registration, as lockAgent does: it must be
// the transaction's first statement. One decided or deleted meanwhile is otherwise.
func (s *service) lockRegistration(ctx context.Context, id string, otherwise error) error {
	n, err := s.db.Update(ctx, TableRegistrations, store.Criteria{"id": id, "status": StatusPending}, store.Data{"id": id})
	if err == nil && n != 1 {
		err = otherwise
	}
	return err
}

// admit makes the approved registration the agent it is for, under the host its key is: the one that is
// known by now, when the agent becomes its owner's, else a new one, the approver's (§2.9). It is called in the
// decision's transaction, which holds the registration's lock.
func (s *service) admit(ctx context.Context, r registration) error {
	a := r.becomes
	h, err := s.registeredHost(ctx, r)
	if err != nil {
		return err
	}
	if h == nil {
		created, _, err := s.createHost(ctx, Host{ID: r.HostID, OwnerType: a.OwnerType, OwnerID: a.OwnerID, OrganizationID: a.OrganizationID, CreatedBy: a.CreatedBy,
			PublicJWK: r.HostJWK, KeyThumbprint: r.HostThumbprint}, r.HostName, nil)
		if err != nil {
			return err
		}
		h = &created
	} else if err := s.lockHost(ctx, h.ID); err != nil {
		return err
	}
	if h.ID != a.HostID || h.OwnerType != a.OwnerType || h.OwnerID != a.OwnerID || h.OrganizationID != a.OrganizationID {
		return refuse(ErrConflict, "The host became known meanwhile; decide again.")
	}
	if _, _, err := s.createAgent(ctx, map[string]any{"name": r.Name, "mode": r.Mode, "auth": AuthPrivateKeyJWT, "jwk": r.AgentJWK}, a); errors.Is(err, store.ErrDuplicate) {
		return refuse(ErrConflict, "The host registered an agent with this key meanwhile.")
	} else if err != nil {
		return err
	}
	_, err = s.db.Delete(ctx, TableRegistrations, store.Criteria{"id": r.ID})
	return err
}

// reject ends a denied registration (§7.1): its agent's key stays taken until it is deleted.
func (s *service) reject(ctx context.Context, r registration) error {
	_, err := s.db.Update(ctx, TableRegistrations, store.Criteria{"id": r.ID}, store.Data{"status": StatusRejected, "updated_at": s.now(), "expires_at": s.now().Add(registrationKept)})
	return err
}

// Prune deletes what nobody decided (Agent Auth Protocol §7.1): a day after its approval expired, the
// registration of a host the server does not know and the pending agent of one it knows; and a denied
// registration a day after. They are deleted, not revoked: they never were active. It returns the rows
// deleted per table; a host schedules it beside polaris.Polaris.Prune.
func (p *Plugin) Prune(ctx context.Context) (map[string]int64, error) {
	registrations, err := p.s.pruneRegistrations(ctx, store.Criteria{}, 0)
	var pending int64
	if err == nil {
		pending, err = p.s.prunePending(ctx)
	}
	return map[string]int64{TableRegistrations: registrations, TableAgents: pending}, err
}

// pruneRegistrations deletes the registrations of the criteria past their expiry, at most limit (0: all),
// with their grants and approvals, and counts them.
func (s *service) pruneRegistrations(ctx context.Context, c store.Criteria, limit int) (int64, error) {
	c["expires_at"] = store.Lt(s.now())
	rows, err := s.db.FindMany(ctx, TableRegistrations, c, store.Query{OrderBy: []store.Order{{Column: "id"}}, Limit: limit})
	if err != nil {
		return 0, err
	}
	var n int64
	for _, row := range rows {
		id := row.String("id")
		var deleted int64
		err := s.db.Tx(ctx, func(ctx context.Context) error {
			var err error
			if deleted, err = s.db.Delete(ctx, TableRegistrations, store.Criteria{"id": id, "expires_at": c["expires_at"]}); err != nil || deleted == 0 {
				return err // decided, or asked again, meanwhile
			}
			return s.deleteOf(ctx, id, TableGrants, TableApprovals)
		})
		if err != nil {
			return n, err
		}
		n += deleted
	}
	return n, nil
}

// deleteOf deletes an agent's rows of the tables.
func (s *service) deleteOf(ctx context.Context, agentID string, tables ...string) error {
	for _, table := range tables {
		if _, err := s.db.Delete(ctx, table, store.Criteria{"agent_id": agentID}); err != nil {
			return err
		}
	}
	return nil
}

// prunePending erases the agents of known hosts whose registration nobody decided.
func (s *service) prunePending(ctx context.Context) (int64, error) {
	cutoff := s.now().Add(-registrationKept)
	agents, err := s.agentsWhere(ctx, store.Criteria{"status": StatusPending, "created_at": store.Lt(cutoff)})
	if err != nil {
		return 0, err
	}
	var erased int64
	for _, a := range agents {
		err := s.db.Tx(ctx, func(ctx context.Context) error {
			n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID, "status": StatusPending}, store.Data{"id": a.ID})
			if err != nil || n != 1 {
				return err // decided meanwhile
			}
			recent, err := s.db.Count(ctx, TableApprovals, store.Criteria{"agent_id": a.ID, "expires_at": store.Gte(cutoff)})
			if err != nil || recent > 0 {
				return err
			}
			if err := s.erase(ctx, a); err != nil {
				return err
			}
			erased++
			return nil
		})
		if err != nil {
			return erased, err
		}
	}
	return erased, nil
}

// agentOfKey is the agent a host registered with the key, when there is one.
func (s *service) agentOfKey(ctx context.Context, hostID, thumbprint string) (Agent, bool, error) {
	row, err := s.db.FindOne(ctx, TableAgents, store.Criteria{"host_id": hostID, "key_thumbprint": thumbprint})
	if err != nil || row == nil {
		return Agent{}, false, err
	}
	return agentFromRow(row), true, nil
}

// thumbprintOf is the RFC 7638 thumbprint of a key protocolKey validated.
func thumbprintOf(jwk any) (string, error) {
	m, _ := jwk.(map[string]any)
	return oauth.Thumbprint(m)
}
