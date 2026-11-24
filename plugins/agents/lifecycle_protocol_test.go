package agents_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/store"
)

func TestAgentAuthLifecycleFixtures(t *testing.T) {
	run(t, protocolFixtures, map[string]func(*agentsCase){
		"testAHostRekeysAndRevokesItsAgentsAndItself": rekeysAndRevokes,
	})
}

// asHost posts body to the path with a host JWT k signs.
func (a *agentsCase) asHost(k *agentKey, path string, body map[string]any) *http.Response {
	return a.c.Post(path, body, contracttest.Bearer(k.hostJWT(nil, nil)))
}

// §5.7 to §5.10: a host rotates its agent's key and its own, and revokes an agent, then itself.
func rekeysAndRevokes(a *agentsCase) {
	h := newHostCase(a)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])

	rotated := newKey("EdDSA")
	resp = h.asHost(h.host, "/agent/rotate-key", map[string]any{"agent_id": id, "public_key": rotated.jwk()})
	h.equal([]any{resp.StatusCode, h.json(resp)}, []any{200, map[string]any{"agent_id": id, "status": "active"}}, "§5.8")
	h.agentsProblem(h.executes(key, id, "members.list", map[string]any{}), 401, "invalid_jwt", "", "§5.8: the old key stops at once")
	h.status(h.executes(rotated, id, "members.list", map[string]any{}), 200, "the new one works")

	old := h.host
	h.host = newKey("EdDSA")
	resp = h.asHost(old, "/host/rotate-key", map[string]any{"public_key": h.host.jwk()})
	h.equal([]any{resp.StatusCode, h.json(resp)}, []any{200, map[string]any{"host_id": h.hostID, "status": "active"}}, "§5.9")
	h.agentsProblem(h.c.Get("/agent/status?agent_id="+id, contracttest.Bearer(old.hostJWT(nil, nil))), 401, "invalid_jwt", "", "§5.9: the old key stops at once")
	h.equal(h.statusOf(id)["status"], "active", "§5.9: agents go on")
	h.status(h.executes(rotated, id, "members.list", map[string]any{}), 200, "and execute")

	resp = h.asHost(h.host, "/agent/revoke", map[string]any{"agent_id": id})
	h.equal([]any{resp.StatusCode, h.json(resp)}, []any{200, map[string]any{"agent_id": id, "status": "revoked"}}, "§5.7")
	h.agentsProblem(h.executes(rotated, id, "members.list", map[string]any{}), 403, "agent_revoked", "agent_revoked", "§2.6")

	_, resp = h.registers(map[string]any{"capabilities": []any{"members.list"}})
	h.status(resp, 200, "another agent")
	resp = h.asHost(h.host, "/host/revoke", nil)
	h.equal([]any{resp.StatusCode, h.json(resp)}, []any{200, map[string]any{"host_id": h.hostID, "status": "revoked", "agents_revoked": float64(1)}}, "§5.10")
	_, resp = h.registers(nil)
	h.agentsProblem(resp, 403, "host_revoked", "host_revoked", "§2.11")
}

// §5.7, §5.8, §5.9: each with the host JWT of the agent's host, and of no other.
func TestSection5_7TheLifecycleIsTheHosts(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])
	other := newKey("EdDSA")
	h.status(h.addHost(h.session, h.userID, other, nil), 201, "another host of the same owner")
	next := newKey("EdDSA").jwk()
	paths := map[string]map[string]any{"/agent/revoke": {"agent_id": id}, "/agent/rotate-key": {"agent_id": id, "public_key": next}}
	for path, body := range paths {
		h.agentsProblem(h.asHost(other, path, body), 404, "agent_not_found", "agent_not_found", path+": another host's")
		h.agentsProblem(h.asHost(h.host, path, map[string]any{"agent_id": "nobody", "public_key": next}), 404, "agent_not_found", "agent_not_found", path+": unknown")
		h.agentsProblem(h.asHost(h.host, path, map[string]any{"public_key": next}), 400, "invalid_request", "invalid_request", path+": none")
	}
	paths["/host/revoke"], paths["/host/rotate-key"] = nil, map[string]any{"public_key": next}
	for path, body := range paths {
		for name, bearer := range map[string]string{"an agent's JWT": key.requestJWT(id, base, nil, nil), "an unknown host's": newKey("EdDSA").hostJWT(nil, nil), "a session": h.session} {
			h.agentsProblem(h.c.Post(path, body, contracttest.Bearer(bearer)), 401, "invalid_jwt", "", path+": "+name)
		}
		h.agentsProblem(h.c.Post(path, body), 401, "invalid_jwt", "", path+": nobody")
	}
	h.status(h.executes(key, id, "members.list", map[string]any{}), 200, "nothing happened")
}

// §5.8: what a new key of an agent may be, and of which agents.
func TestSection5_8RotatingAnAgentsKey(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])
	second, resp := h.registers(nil)
	otherID := str(h.json(resp)["agent_id"])
	rotate := func(id string, jwk any) *http.Response {
		return h.asHost(h.host, "/agent/rotate-key", map[string]any{"agent_id": id, "public_key": jwk})
	}
	private := newKey("EdDSA").jwk()
	private["d"] = "x"
	h.agentsProblem(rotate(id, newKey("ES256").jwk()), 400, "unsupported_algorithm", "unsupported_algorithm", "§5.13")
	for _, bad := range []any{nil, "x", map[string]any{}, private} {
		h.agentsProblem(rotate(id, bad), 400, "invalid_request", "invalid_request", "no public key")
	}
	h.agentsProblem(rotate(id, second.jwk()), 409, "agent_exists", "agent_exists", "another agent's key")

	// A token the old key minted stops with it, and the new key mints.
	token := func(k *agentKey) *http.Response {
		return h.form("/oauth2/token", map[string]string{"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": h.session, "subject_token_type": exchangeType,
			"scope": "members.read", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": k.assertion(id, base+"/oauth2/token")})
	}
	minted := str(h.json(token(key))["access_token"])
	h.status(h.bearer(minted, "GET", "/agents/session", nil), 200, "the old key's token")
	next := newKey("EdDSA")
	h.status(rotate(id, next.jwk()), 200, "rotated")
	h.status(h.bearer(minted, "GET", "/agents/session", nil), 401, "stops")
	h.status(token(key), 401, "the old key mints none")
	h.status(token(next), 200, "the new one does")
	h.equal(h.data(h.c.Get("/agents/"+id, contracttest.Bearer(h.session)))["status"], "active", "the agent is the same")

	// The new key is taken, the old one is free again (§5.3).
	h.agentsProblem(h.registersWith(next), 409, "agent_exists", "agent_exists", "the new key")
	h.status(h.registersWith(key), 200, "the old key is another agent")

	h.status(h.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(h.session)), 200, "suspend")
	resp = rotate(id, newKey("EdDSA").jwk())
	h.equal([]any{resp.StatusCode, h.json(resp)["status"]}, []any{200, "pending"}, "a paused agent's leaked key is replaced")
	h.status(h.asHost(h.host, "/agent/revoke", map[string]any{"agent_id": otherID}), 200, "revoke")
	h.agentsProblem(rotate(otherID, newKey("EdDSA").jwk()), 403, "agent_revoked", "agent_revoked", "revoked")
	_, resp = h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	registered := h.json(resp)
	h.agentsProblem(rotate(str(registered["agent_id"]), newKey("EdDSA").jwk()), 403, "agent_pending", "agent_pending", "pending")
	h.decides(registered["approval"], "deny")
	h.agentsProblem(rotate(str(registered["agent_id"]), newKey("EdDSA").jwk()), 403, "agent_rejected", "agent_rejected", "rejected")
}

func (h *hostCase) registersWith(key *agentKey) *http.Response {
	return h.c.Post("/agent/register", map[string]any{"name": "Reader"}, contracttest.Bearer(h.host.hostJWT(map[string]any{"agent_public_key": key.jwk()}, nil)))
}

// §5.7: revoking is the kill switch, once.
func TestSection5_7RevokingAnAgent(t *testing.T) {
	h := unrecorded(t)
	_, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])
	for range 2 {
		resp = h.asHost(h.host, "/agent/revoke", map[string]any{"agent_id": id})
		h.equal([]any{resp.StatusCode, h.json(resp)["status"]}, []any{200, "revoked"}, "again")
	}
	h.equal([]any{len(h.audited(agents.EventRevoked)), len(h.audited(agents.EventReceiptSealed))}, []any{1, 1}, "sealed once")
	_, resp = h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	pending := h.json(resp)
	resp = h.asHost(h.host, "/agent/revoke", map[string]any{"agent_id": pending["agent_id"]})
	h.equal([]any{resp.StatusCode, h.json(resp)["status"]}, []any{200, "revoked"}, "a pending one")
	h.agentsProblem(h.c.Post("/agents/approvals/"+str(obj(pending["approval"])["id"])+"/decide", approve, contracttest.Bearer(h.session)), 409, "conflict", "", "its approval is over")
	_, resp = h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	denied := h.json(resp)
	h.decides(denied["approval"], "deny")
	h.agentsProblem(h.asHost(h.host, "/agent/revoke", map[string]any{"agent_id": denied["agent_id"]}), 403, "agent_rejected", "agent_rejected", "a denied one is over already")
}

// §5.9: nothing proves the new key, and a public key is anybody's to send: rotating to somebody else's takes nothing
// of theirs (decision 86's hole), and their client registers as it would have.
func TestSection5_9ANewHostKeyIsNotTakenOnItsWord(t *testing.T) {
	u := anUnknownHost(t, nil)
	eveID, eve := u.login("eve@example.com")
	_, eve = u.organization(eve, "Evil")
	eves, ada := newKey("EdDSA"), newKey("EdDSA")
	u.status(u.addHost(eve, eveID, eves, nil), 201, "Eve's host")
	evesAgent := newKey("EdDSA")
	id := str(u.json(u.registersAs(eves, evesAgent, map[string]any{"capabilities": []any{"members.list"}}))["agent_id"])
	evesHost := str(u.json(u.statusAs(eves, id))["host_id"])
	u.status(u.asHost(eves, "/host/rotate-key", map[string]any{"public_key": ada.jwk()}), 200, "to Ada's key")
	u.equal(u.statusAs(eves, id).StatusCode, 404, "the old key stops")

	registered := u.json(u.registersAs(ada, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}))
	u.equal([]any{registered["status"], registered["host_id"] == evesHost}, []any{"pending", false}, "Ada's client is unknown, not Eve's")
	u.agentsProblem(u.asHost(ada, "/agent/revoke", map[string]any{"agent_id": registered["agent_id"]}), 401, "invalid_jwt", "", "and waits")
	u.status(u.decides(u.session, registered, approve), 200, "Ada approves")
	u.equal([]any{u.json(u.statusAs(ada, str(registered["agent_id"])))["user_id"]}, []any{u.userID}, "it is hers")
	u.status(u.registersAs(ada, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}), 200, "and so is the next")
	u.equal(u.statusAs(ada, id).StatusCode, 404, "Eve's agent is not under Ada's host")
	u.equal(len(u.rows(agents.TableAgents, store.Criteria{"host_id": evesHost})), 1, "Eve has what she had")
}

// Whoever holds the new key and names an agent of the host is the host.
func TestSection5_9TheNewKeyIsTheHostsOnceItNamesItsAgent(t *testing.T) {
	for name, proves := range map[string]func(u *unknownCase, k *agentKey, id string) *http.Response{
		"status": func(u *unknownCase, k *agentKey, id string) *http.Response { return u.statusAs(k, id) },
		"rotate-key": func(u *unknownCase, k *agentKey, id string) *http.Response {
			return u.asHost(k, "/agent/rotate-key", map[string]any{"agent_id": id, "public_key": newKey("EdDSA").jwk()})
		},
		"reactivate": func(u *unknownCase, k *agentKey, id string) *http.Response {
			return u.asHost(k, "/agent/reactivate", map[string]any{"agent_id": id})
		},
		"revoke": func(u *unknownCase, k *agentKey, id string) *http.Response {
			return u.asHost(k, "/agent/revoke", map[string]any{"agent_id": id})
		},
	} {
		u := anUnknownHost(t, nil)
		old, next := newKey("EdDSA"), newKey("EdDSA")
		u.status(u.addHost(u.session, u.userID, old, nil), 201, "a host")
		key, id := u.agentOf(old)
		u.status(u.asHost(old, "/host/rotate-key", map[string]any{"public_key": next.jwk()}), 200, name)
		u.status(u.executes(key, id, "members.list", nil), 200, name+": its agents go on")
		withISS := u.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, map[string]any{"iss": next.kid()}, nil)))
		u.status(withISS, 200, name+": under the new iss too")
		u.agentsProblem(u.asHost(next, "/host/revoke", nil), 401, "invalid_jwt", "", name+": naming none, it is not the host yet")
		forged := newKey("EdDSA").hostJWT(map[string]any{"iss": next.kid(), "host_public_key": next.jwk()}, nil)
		u.agentsProblem(u.c.Post("/agent/revoke", map[string]any{"agent_id": id}, contracttest.Bearer(forged)), 401, "invalid_jwt", "", name+": a forged one proves nothing")
		u.agentsProblem(u.asHost(next, "/host/revoke", nil), 401, "invalid_jwt", "", name+": still")
		u.status(proves(u, next, id), 200, name)
		_, second := u.agentOf(next)
		u.equal(u.json(u.statusAs(next, second))["status"], "active", name+": it registers")
	}
}

// One that registers first waits for its owner, whose approval is the proof: the host stays one.
func TestSection5_9ANewKeyThatRegistersFirst(t *testing.T) {
	u := anUnknownHost(t, nil)
	old, next := newKey("EdDSA"), newKey("EdDSA")
	u.status(u.addHost(u.session, u.userID, old, nil), 201, "a host")
	_, id := u.agentOf(old)
	hostID := u.json(u.statusAs(old, id))["host_id"]
	u.status(u.asHost(old, "/host/rotate-key", map[string]any{"public_key": next.jwk()}), 200, "rotate")
	registered := u.json(u.registersAs(next, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}))
	u.equal(registered["status"], "pending", "a person is asked")
	u.status(u.decides(u.session, registered, approve), 200, "the host's owner")
	u.equal([]any{u.json(u.statusAs(next, str(registered["agent_id"])))["host_id"], u.json(u.statusAs(next, id))["host_id"]}, []any{hostID, hostID}, "one host")
	u.equal(len(u.rows(agents.TableHosts, store.Criteria{})), 1, "no other")
	u.equal(u.json(u.registersAs(next, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}))["status"], "active", "and the key is its")

	// Another person's approval makes another host of it.
	third := newKey("EdDSA")
	u.status(u.asHost(next, "/host/rotate-key", map[string]any{"public_key": third.jwk()}), 200, "rotate again")
	registered = u.json(u.registersAs(third, newKey("EdDSA"), nil))
	_, bob := u.login("bob@example.com")
	_, bob = u.organization(bob, "Bobs")
	u.status(u.decides(bob, registered, approve), 200, "Bob")
	u.equal([]any{u.statusAs(third, id).StatusCode, len(u.rows(agents.TableHosts, store.Criteria{}))}, []any{404, 2}, "his")
}

// What a key to rotate to may be.
func TestSection5_9TheKeysAHostRotatesTo(t *testing.T) {
	u := anUnknownHost(t, nil)
	mine, other := newKey("EdDSA"), newKey("EdDSA")
	u.status(u.addHost(u.session, u.userID, mine, nil), 201, "mine")
	u.status(u.addHost(u.session, u.userID, other, nil), 201, "another")
	rotate := func(jwk any, proof string) *http.Response {
		body := map[string]any{"public_key": jwk}
		if proof != "" {
			body["proof"] = proof
		}
		return u.asHost(mine, "/host/rotate-key", body)
	}
	u.agentsProblem(rotate(other.jwk(), ""), 409, "conflict", "", "a host's")
	u.agentsProblem(rotate(mine.jwk(), ""), 400, "invalid_request", "invalid_request", "its own")
	u.agentsProblem(rotate(newKey("ES256").jwk(), ""), 400, "unsupported_algorithm", "unsupported_algorithm", "§5.13")
	u.agentsProblem(rotate(nil, ""), 400, "invalid_request", "invalid_request", "none")
	next := newKey("EdDSA")
	u.agentsProblem(rotate(next.jwk(), other.hostLink(u.userID, nil, nil)), 400, "invalid_request", "invalid_request", "another's proof")

	// With the proof POST /agents/hosts takes, the new key is the host's at once.
	u.status(rotate(next.jwk(), next.hostLink(u.userID, nil, nil)), 200, "proven")
	u.equal(u.json(u.registersAs(next, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}))["status"], "active", "registers")
	u.equal(len(u.audited(agents.EventHostKeyRotated)), 1, "audited")
}

// A member of the approver's organization who claimed the key with a host of the organization's gets nothing by
// that: only a host the approver registered themselves is theirs to prove.
func TestSection5_9AColleaguesClaimTakesNoApproval(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	org := newKey("EdDSA")
	u.status(u.addHost(u.session, u.orgID, org, map[string]any{"organization_id": u.orgID}), 201, "the organization's host")
	hosts := u.rows(agents.TableHosts, store.Criteria{})
	if _, err := u.srv.Graph().DB().Update(u.ctx, agents.TableHosts, store.Criteria{"id": hosts[0].String("id")}, store.Data{"created_by": "a-colleague"}); err != nil {
		t.Fatal(err)
	}
	u.status(u.asHost(org, "/host/rotate-key", map[string]any{"public_key": u.host.jwk()}), 200, "claims the key")
	u.status(u.decides(u.session, registered, approve), 200, "approve")
	agent := u.data(u.c.Get("/agents/"+str(registered["agent_id"]), contracttest.Bearer(u.session)))
	u.equal([]any{agent["owner_type"], agent["owner_id"], agent["host_id"] == hosts[0].String("id")}, []any{"user", u.userID, false}, "the approver's own")
}
