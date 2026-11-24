package agents

import (
	"context"
	"errors"
	"net/http"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// The Agent Auth Protocol's lifecycle routes (§5.7 to §5.10), each called with the host's JWT.

// hostRequest is the known host a lifecycle route is called by, within its budget.
func (p *Plugin) hostRequest(ctx context.Context, in *endpoint.Input) (Host, error) {
	h, _, err := p.s.hostCalling(in.Request, false, text(in, "agent_id"))
	if err != nil {
		return h, err
	}
	return h, p.s.spendHost(ctx, h)
}

// hostsAgent is the agent the body names, which must be the host's: another's is not told from none.
func (p *Plugin) hostsAgent(ctx context.Context, h Host, in *endpoint.Input) (Agent, error) {
	id := text(in, "agent_id")
	if id == "" {
		return Agent{}, refuse(ErrInvalidRequest, "agent_id is required.")
	}
	a, ok, err := p.s.agentUnder(ctx, h, id)
	if err == nil && !ok {
		err = refuse(ErrAgentNotFound, "The agent does not exist under this host.")
	}
	return a, err
}

// agentUnder is the host's agent of the id.
func (s *service) agentUnder(ctx context.Context, h Host, id string) (Agent, bool, error) {
	a, ok, err := s.agent(ctx, id)
	if err != nil || !ok || h.ID == "" || a.HostID != h.ID {
		return Agent{}, false, err
	}
	return a, true, nil
}

// newKeyOf is the key a rotation brings.
func newKeyOf(in *endpoint.Input) (map[string]any, string, error) {
	jwk, err := protocolKey(in.Value("public_key"))
	if e, ok := asError(err); ok && e.Type == ErrInvalidInput {
		err = refuse(ErrInvalidRequest, "public_key is the new public key as a JWK, its public part only. "+e.Detail)
	}
	if err != nil {
		return nil, "", err
	}
	thumbprint, err := thumbprintOf(jwk)
	return jwk, thumbprint, err
}

// protocolRevoke is POST /agent/revoke (§5.7): the kill switch, for an agent of the calling host.
func (p *Plugin) protocolRevoke(ctx context.Context, in *endpoint.Input) endpoint.Result {
	h, err := p.hostRequest(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	a, err := p.hostsAgent(ctx, h, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	if a.Status == StatusRejected {
		return p.protocolFail(ctx, refuse(ErrAgentRejected, "The agent's registration was denied."))
	}
	if _, _, err := p.s.revoke(ctx, a, "", "host_request", clientOf(ctx)); err != nil {
		if e, ok := asError(err); !ok || e.Type != ErrConflict { // revoked already
			return p.protocolFail(ctx, err)
		}
	}
	return noStore(http.StatusOK, map[string]any{"agent_id": a.ID, "status": StatusRevoked})
}

// protocolRevokeHost is POST /host/revoke (§5.10): the host and every agent under it.
func (p *Plugin) protocolRevokeHost(ctx context.Context, in *endpoint.Input) endpoint.Result {
	h, err := p.hostRequest(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	n, err := p.s.revokeHosts(ctx, store.Criteria{"id": h.ID})
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	return noStore(http.StatusOK, map[string]any{"host_id": h.ID, "status": "revoked", "agents_revoked": n})
}

// protocolRotateKey is POST /agent/rotate-key (§5.8). The host's JWT is what it takes, as the section says:
// whoever stole an agent's key could otherwise replace it. The tokens the old key minted end with it.
func (p *Plugin) protocolRotateKey(ctx context.Context, in *endpoint.Input) endpoint.Result {
	h, err := p.hostRequest(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	a, err := p.hostsAgent(ctx, h, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	if a.Status != StatusSuspended { // a paused agent's leaked key is replaced too
		if err := assertActive(a); err != nil {
			return p.protocolFail(ctx, err)
		}
	}
	jwk, thumbprint, err := newKeyOf(in)
	if err == nil {
		err = p.s.rekeyAgent(ctx, h, a, jwk, thumbprint)
	}
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	p.s.dispatch(ctx, bySystem(EventKeyRotated, a, map[string]any{"host_id": h.ID, "key": thumbprint}))
	return noStore(http.StatusOK, map[string]any{"agent_id": a.ID, "status": protocolStatusOf(a)})
}

func (s *service) rekeyAgent(ctx context.Context, h Host, a Agent, jwk map[string]any, thumbprint string) error {
	return s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockHost(ctx, h.ID); err != nil { // the order a revocation locks in
			return err
		}
		n, err := s.db.Update(ctx, TableAgents, store.Criteria{"id": a.ID, "status": []string{StatusActive, StatusSuspended}},
			store.Data{"public_jwk": jsonColumn(jwk), "key_thumbprint": thumbprint, "updated_at": s.now()})
		switch {
		case errors.Is(err, store.ErrDuplicate):
			return errAgentExists()
		case err != nil:
			return err
		case n != 1:
			return refuse(ErrConflict, "The agent changed meanwhile.")
		}
		cl, err := s.oauth.Client(ctx, a.ID)
		if err != nil {
			return err
		}
		if _, _, err := s.oauth.UpdateClient(ctx, cl, oauth.ClientFields{"jwks": map[string]any{"keys": []any{jwk}}}, false); err != nil {
			return err
		}
		_, err = s.oauth.RevokeClientTokens(ctx, a.ID)
		return err
	})
}

// protocolRotateHostKey is POST /host/rotate-key (§5.9), for a host that sends its key. The old key stops.
// Nothing proves the new one, and a public key is anybody's to send: it is only claimed, which takes it from
// nobody, until its holder shows that it knows the host (hostCalling), or with proof, a host link JWT.
func (p *Plugin) protocolRotateHostKey(ctx context.Context, in *endpoint.Input) endpoint.Result {
	h, err := p.hostRequest(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	if h.JWKSURL != "" {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "A host that publishes its keys rotates them at its JWKS URL."))
	}
	next := h
	if next.PublicJWK, next.KeyThumbprint, err = newKeyOf(in); err != nil {
		return p.protocolFail(ctx, err)
	}
	if next.KeyThumbprint == h.KeyThumbprint {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "public_key is the host's key already."))
	}
	proof := in.Value("proof")
	if proof != nil {
		if _, err := p.s.proven(ctx, next, proof); err != nil {
			return p.protocolFail(ctx, err)
		}
	}
	if err := p.s.rekeyHost(ctx, h, next, proof != nil); err != nil {
		return p.protocolFail(ctx, err)
	}
	p.s.dispatch(ctx, bySystem(EventHostKeyRotated, Agent{OwnerType: h.OwnerType, OwnerID: h.OwnerID, OrganizationID: h.OrganizationID, CreatedBy: h.CreatedBy},
		map[string]any{"host_id": h.ID, "host_name": h.Name, "key": next.KeyThumbprint, "proven": proof != nil}))
	return noStore(http.StatusOK, map[string]any{"host_id": h.ID, "status": StatusActive})
}

func (s *service) rekeyHost(ctx context.Context, h, next Host, proven bool) error {
	taken, err := s.db.Count(ctx, TableHosts, store.Criteria{"key_thumbprint": next.KeyThumbprint})
	if err == nil && taken > 0 {
		err = refuse(ErrConflict, "The key belongs to a host already.")
	}
	if err != nil {
		return err
	}
	set := store.Data{"public_jwk": jsonColumn(next.PublicJWK), "key_thumbprint": nil, "claimed_thumbprint": next.KeyThumbprint}
	if proven {
		set["key_thumbprint"], set["claimed_thumbprint"] = next.KeyThumbprint, nil
	}
	n, err := s.db.Update(ctx, TableHosts, store.Criteria{"id": h.ID, "key_thumbprint": h.KeyThumbprint, "revoked_at": nil}, set)
	switch {
	case errors.Is(err, store.ErrDuplicate):
		return refuse(ErrConflict, "The key belongs to a host already.")
	case err == nil && n != 1:
		return refuse(ErrConflict, "The host changed meanwhile.")
	}
	return err
}
