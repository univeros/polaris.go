package agents_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/agent"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/store"
)

// hostJWT is a host+jwt (§4.2) signed with k for the issuer; claims and headers override or add, a
// nil claim is left out.
func (k *agentKey) hostJWT(extra, headers map[string]any) string {
	now := time.Now().Unix()
	payload := map[string]any{"iss": k.kid(), "sub": k.kid(), "aud": base, "iat": now, "exp": now + 60, "jti": jti(), "host_public_key": k.jwk()}
	for n, v := range extra {
		payload[n] = v
		if v == nil {
			delete(payload, n)
		}
	}
	header := map[string]any{"typ": "host+jwt", "alg": k.alg, "kid": k.kid()}
	for n, v := range headers {
		header[n] = v
	}
	return k.sign(header, payload)
}

// hostLink is the proof (host-link+jwt) that k's holder wants the account owner to own its host; claims and
// headers override or add, a nil claim is left out.
func (k *agentKey) hostLink(owner string, extra, headers map[string]any) string {
	now := time.Now().Unix()
	payload := map[string]any{"iss": k.kid(), "sub": owner, "aud": base, "iat": now, "exp": now + 60, "jti": jti()}
	for n, v := range extra {
		payload[n] = v
		if v == nil {
			delete(payload, n)
		}
	}
	header := map[string]any{"typ": "host-link+jwt", "alg": k.alg}
	for n, v := range headers {
		header[n] = v
	}
	return k.sign(header, payload)
}

// addHost is POST /agents/hosts for k's host, with its proof for the owner.
func (a *agentsCase) addHost(session, owner string, k *agentKey, fields map[string]any) *http.Response {
	body := map[string]any{"name": "Host", "public_key": k.jwk(), "proof": k.hostLink(owner, nil, nil)}
	for n, v := range fields {
		body[n] = v
	}
	return a.c.Post("/agents/hosts", body, contracttest.Bearer(session))
}

// hostCase is an owner with a host that has a key, pre-registered (§2.8).
type hostCase struct {
	*agentsCase
	userID, session, orgID, hostID string
	host                           *agentKey
}

func newHostCase(a *agentsCase) *hostCase {
	a.t.Helper()
	userID, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	h := &hostCase{agentsCase: a, userID: userID, session: session, orgID: orgID, host: newKey("EdDSA")}
	created := a.addHost(session, userID, h.host, map[string]any{"name": "Nightwatch"})
	body := a.data(created)
	a.equal([]any{created.StatusCode, body["key_thumbprint"]}, []any{201, h.host.kid()}, "the host is known by its key's thumbprint")
	if _, has := body["enrollment_token"]; has {
		a.t.Error("a host with a key has no enrolment token")
	}
	h.hostID = str(body["id"])
	return h
}

// unrecorded runs test against a server of its own, without a fixture.
func unrecorded(t *testing.T) *hostCase {
	t.Helper()
	srv, p := boot(t)
	return newHostCase(&agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p, ctx: t.Context()})
}

// registers sends POST /agent/register for a new agent key.
func (h *hostCase) registers(fields map[string]any) (*agentKey, *http.Response) {
	key := newKey("EdDSA")
	body := map[string]any{"name": "Reader", "mode": "delegated"}
	for k, v := range fields {
		body[k] = v
	}
	return key, h.c.Post("/agent/register", body, contracttest.Bearer(h.host.hostJWT(map[string]any{"agent_public_key": key.jwk()}, nil)))
}

func (h *hostCase) statusOf(id string) map[string]any {
	resp := h.c.Get("/agent/status?agent_id="+url.QueryEscape(id), contracttest.Bearer(h.host.hostJWT(nil, nil)))
	h.status(resp, 200, "status")
	return h.json(resp)
}

func (h *hostCase) decides(approval any, decision string) {
	h.t.Helper()
	h.status(h.c.Post("/agents/approvals/"+str(obj(approval)["id"])+"/decide", map[string]any{"decision": decision}, contracttest.Bearer(h.session)), 200, decision)
}

func (h *hostCase) requests(key *agentKey, id string, capabilities ...any) *http.Response {
	return h.c.Post("/agent/request-capability", map[string]any{"capabilities": capabilities, "reason": "the user asked"}, contracttest.Bearer(key.requestJWT(id, base, nil, nil)))
}

func (h *hostCase) executes(key *agentKey, id, capability string, args any) *http.Response {
	return h.c.Post("/capability/execute", map[string]any{"capability": capability, "arguments": args},
		contracttest.Bearer(key.requestJWT(id, base+"/capability/execute", map[string]any{"capabilities": []any{capability}}, nil)))
}

func TestAgentAuthHostFixtures(t *testing.T) {
	run(t, protocolFixtures, map[string]func(*agentsCase){
		"testAPreRegisteredHostsAgentRegistersRequestsAndExecutes": registersRequestsExecutes,
		"testARegistrationAPersonMustApproveIsPending":             registrationIsApproved,
		"testADeniedRegistrationIsRejected":                        registrationIsDenied,
	})
}

func registersRequestsExecutes(a *agentsCase) {
	h := newHostCase(a)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}, "host_name": "laptop", "force_approval": true})
	registered := h.json(resp)
	id := str(registered["agent_id"])
	h.equal([]any{resp.StatusCode, registered["host_id"], registered["name"], registered["mode"], registered["status"], registered["approval"]},
		[]any{200, h.hostID, "Reader", "delegated", "active", nil}, "§5.3: auto-approved")
	grant := at(registered["agent_capability_grants"], 0)
	h.equal([]any{grant["capability"], grant["status"], grant["description"], obj(grant["input"])["type"]}, []any{"members.list", "active", "Count the members", "object"}, "§5.3: an active grant in full")

	// §5.4: more capabilities; only the new ones are answered.
	asked := h.json(h.requests(key, id, map[string]any{"name": "org.rename", "constraints": map[string]any{"name": map[string]any{"in": []any{"Acme 2", "Acme 3"}}}}))
	h.equal([]any{asked["agent_id"], asked["status"], asked["agent_capability_grants"]},
		[]any{id, "pending", []any{map[string]any{"capability": "org.rename", "status": "pending"}}}, "§5.3: a pending grant holds its name and status only")
	ap := obj(asked["approval"])
	h.equal([]any{ap["method"], ap["verification_uri"], ap["expires_in"], ap["interval"]}, []any{"device_authorization", approveURL, 600, 5}, "§7: approval")
	h.equal(h.statusOf(id)["status"], "active", "§5.4: the agent stays active")
	h.decides(ap, "approve")

	st := h.statusOf(id)
	h.equal([]any{st["agent_id"], st["host_id"], st["name"], st["mode"], st["status"], len(st["agent_capability_grants"].([]any))}, []any{id, h.hostID, "Reader", "delegated", "active", 2}, "§5.5")
	if st["user_id"] == nil || st["created_at"] == nil {
		h.t.Errorf("§5.5: %v", st)
	}
	for _, g := range st["agent_capability_grants"].([]any) {
		if obj(g)["capability"] == "org.rename" {
			h.equal([]any{obj(g)["status"], obj(obj(g)["constraints"])["name"]}, []any{"active", map[string]any{"in": []any{"Acme 2", "Acme 3"}}}, "the approved scope")
			if obj(g)["granted_by"] == nil {
				h.t.Error("§5.5: granted_by")
			}
		}
	}

	// §5.11: a synchronous body holds data and nothing else; the receipt is in the header.
	done := h.executes(key, id, "org.rename", map[string]any{"name": "Acme 2"})
	h.equal([]any{done.StatusCode, h.json(done)}, []any{200, map[string]any{"data": map[string]any{"renamed": "Acme 2"}}}, "§5.11: sync")
	receipt := done.Header.Get(agents.ReceiptHeader)
	h.equal(obj(h.data(h.c.Get("/agents/receipts/"+receipt+"/verify", contracttest.Bearer(h.session))))["valid"], true, "the receipt verifies")
	refused := h.agentsProblem(h.executes(key, id, "org.rename", map[string]any{"name": "Other"}), 403, "constraint_violated", "", "§5.11: constraints")
	h.equal(at(refused["violations"], 0), map[string]any{"field": "name", "constraint": map[string]any{"in": []any{"Acme 2", "Acme 3"}}, "actual": "Other"}, "§5.11: violations")
	h.status(h.executes(key, id, "members.list", map[string]any{}), 200, "another")
	h.agentsProblem(h.requests(key, id, "members.list"), 409, "already_granted", "already_granted", "§5.13")
}

func registrationIsApproved(a *agentsCase) {
	h := newHostCase(a)
	key, resp := h.registers(map[string]any{"capabilities": []any{"org.rename"}, "preferred_method": "ciba", "binding_message": "Rename?"})
	registered := h.json(resp)
	id := str(registered["agent_id"])
	h.equal([]any{registered["status"], obj(registered["approval"])["method"], obj(registered["approval"])["binding_message"]}, []any{"pending", "ciba", "Rename?"}, "§5.3: approval required")
	h.equal(h.statusOf(id)["status"], "pending", "§5.5")
	// §2.3, §4.5: a pending agent cannot authenticate, on either surface.
	h.agentsProblem(h.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, nil, nil))), 403, "agent_pending", "agent_pending", "list")
	h.agentsProblem(h.executes(key, id, "org.rename", map[string]any{"name": "X"}), 403, "agent_pending", "agent_pending", "execute")
	h.agentsProblem(h.signed(key, id, "GET", "/agents/session", nil, nil), 401, "agent_inactive", "agent_pending", "the Polaris surface")
	h.decides(registered["approval"], "approve")
	h.equal(h.statusOf(id)["status"], "active", "approved")
	h.status(h.executes(key, id, "org.rename", map[string]any{"name": "X"}), 200, "and works")
}

func registrationIsDenied(a *agentsCase) {
	h := newHostCase(a)
	key, resp := h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	registered := h.json(resp)
	id := str(registered["agent_id"])
	h.decides(registered["approval"], "deny")
	st := h.statusOf(id)
	h.equal([]any{st["status"], at(st["agent_capability_grants"], 0)["status"]}, []any{"rejected", "denied"}, "§7.1: a denied registration is rejected")
	h.agentsProblem(h.executes(key, id, "org.rename", map[string]any{"name": "X"}), 403, "agent_rejected", "agent_rejected", "rejected")
	// Terminal: nothing brings it back, and its OAuth client and tokens are gone.
	h.agentsProblem(h.c.Post("/agents/"+id+"/resume", nil, contracttest.Bearer(h.session)), 409, "conflict", "", "resume")
}

// hostRoutes are the host-authenticated routes: each must hold every rule of §4.5.1.
func hostRoutes(h *hostCase, id string) map[string]func(jwt string) *http.Response {
	return map[string]func(string) *http.Response{
		"status": func(jwt string) *http.Response {
			return h.c.Get("/agent/status?agent_id="+id, contracttest.Bearer(jwt))
		},
		"register": func(jwt string) *http.Response {
			return h.c.Post("/agent/register", map[string]any{"name": "Reader"}, contracttest.Bearer(jwt))
		},
		"list": func(jwt string) *http.Response { return h.c.Get("/capability/list", contracttest.Bearer(jwt)) },
		"describe": func(jwt string) *http.Response {
			return h.c.Get("/capability/describe?name=invite", contracttest.Bearer(jwt))
		},
	}
}

// §4.2, §4.5.1, §4.6, §8.2, §8.4, §8.7, §8.18: what a host JWT must hold, on every route that takes one.
func TestSection4_5_1AHostJWT(t *testing.T) {
	h := unrecorded(t)
	_, resp := h.registers(nil)
	id := str(h.json(resp)["agent_id"])
	agentKey := newKey("EdDSA").jwk()
	other := newKey("EdDSA")
	now := time.Now()
	claim := func(name string, v any) string {
		return h.host.hostJWT(map[string]any{name: v, "agent_public_key": agentKey}, nil)
	}
	for name, send := range hostRoutes(h, id) {
		t.Run(name, func(t *testing.T) {
			jwt := h.host.hostJWT(map[string]any{"agent_public_key": newKey("EdDSA").jwk()}, nil)
			h.status(send(jwt), 200, "a host JWT")
			for what, bad := range map[string]string{
				"§4.6 the jti again":                   jwt,
				"§4.2 typ":                             h.host.hostJWT(nil, map[string]any{"typ": "JWT"}),
				"§4.2 an agent's typ":                  h.host.hostJWT(nil, map[string]any{"typ": "agent+jwt"}),
				"§8.18 aud":                            claim("aud", base+"/agent/register"),
				"§8.18 aud with a slash":               claim("aud", base+"/"),
				"§8.18 no aud":                         claim("aud", nil),
				"§4.2 iss is not the thumbprint":       claim("iss", other.kid()),
				"§4.2 no iss":                          claim("iss", nil),
				"§4.2 no iat":                          claim("iat", nil),
				"§4.2 no exp":                          claim("exp", nil),
				"§4.2 no jti":                          claim("jti", nil),
				"§8.2 iat 35 s ahead":                  claim("iat", now.Add(35*time.Second).Unix()),
				"§8.2 expired":                         h.host.hostJWT(map[string]any{"iat": now.Add(-100 * time.Second).Unix(), "exp": now.Add(-40 * time.Second).Unix()}, nil),
				"a lifetime of more than five minutes": claim("exp", now.Add(time.Hour).Unix()),
				"§8.7 the other delivery mode":         h.host.hostJWT(map[string]any{"host_public_key": nil, "host_jwks_url": "https://keys.example.com/jwks"}, nil),
				"§8.7 both delivery modes":             claim("host_jwks_url", "https://keys.example.com/jwks"),
				"§4.2 no key":                          claim("host_public_key", nil),
				"§4.2 another key than the signer's":   claim("host_public_key", other.jwk()),
				"§4.5.1 an unknown host":               other.hostJWT(nil, nil),
				"§4.5.1 another key's signature":       other.hostJWT(map[string]any{"iss": h.host.kid(), "host_public_key": h.host.jwk()}, nil),
				"a key in the header":                  h.host.hostJWT(nil, map[string]any{"jwk": h.host.jwk()}),
				"another algorithm":                    h.host.hostJWT(nil, map[string]any{"alg": "ES256"}),
				"no algorithm":                         h.host.hostJWT(nil, map[string]any{"alg": "none"}),
			} {
				h.agentsProblem(send(bad), 401, "invalid_jwt", "invalid_jwt", what)
			}
		})
	}
	// Without a credential: the capability routes are public, the others are not.
	h.agentsProblem(h.c.Get("/agent/status?agent_id="+id), 401, "invalid_jwt", "invalid_jwt", "no credential")
	h.agentsProblem(h.c.Post("/agent/register", map[string]any{"name": "x"}), 401, "invalid_jwt", "invalid_jwt", "no credential")
}

// §5.5: the server MUST verify the agent is registered under this host.
func TestSection5_5AHostSeesItsOwnAgentsOnly(t *testing.T) {
	h := unrecorded(t)
	_, resp := h.registers(nil)
	id := str(h.json(resp)["agent_id"])
	other := newKey("EdDSA")
	h.status(h.addHost(h.session, h.userID, other, nil), 201, "another host of the same owner")
	h.agentsProblem(h.c.Get("/agent/status?agent_id="+id, contracttest.Bearer(other.hostJWT(nil, nil))), 404, "agent_not_found", "agent_not_found", "another host's agent")
	h.agentsProblem(h.c.Get("/agent/status?agent_id=nobody", contracttest.Bearer(h.host.hostJWT(nil, nil))), 404, "agent_not_found", "agent_not_found", "unknown")
	h.agentsProblem(h.c.Get("/agent/status", contracttest.Bearer(h.host.hostJWT(nil, nil))), 400, "invalid_request", "invalid_request", "no agent_id")
}

// §4.3, §4.5: an agent JWT's iss, when there, is its host's current thumbprint. The reference client
// sends none.
func TestSection4_5AnAgentsHost(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])
	list := func(iss any) *http.Response {
		return h.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, map[string]any{"iss": iss}, nil)))
	}
	h.status(list(h.host.kid()), 200, "its host")
	h.status(h.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, nil, nil))), 200, "no iss")
	for _, iss := range []any{newKey("EdDSA").kid(), key.kid(), "", 5, nil} {
		h.agentsProblem(list(iss), 401, "invalid_jwt", "", "another iss")
	}
	ownKey := newKey("EdDSA")
	own := h.registerAgent(h.session, map[string]any{"name": "Owned", "auth": "private_key_jwt", "jwk": ownKey.jwk()})
	h.agentsProblem(h.c.Get("/capability/list", contracttest.Bearer(ownKey.requestJWT(str(own["id"]), base, map[string]any{"iss": h.host.kid()}, nil))), 401, "invalid_jwt", "", "an agent without a host")
}

// §2.11, §8.5: revoking a host with a key MUST revoke the agents under it; nothing registers after.
func TestSection8_5RevokingAHostRevokesItsAgents(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])
	_, resp = h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	pending := str(h.json(resp)["agent_id"])
	h.status(h.c.Delete("/agents/hosts/"+h.hostID, contracttest.Bearer(h.session)), 200, "revoke the host")
	for _, agent := range []string{id, pending} {
		h.equal(h.data(h.c.Get("/agents/"+agent, contracttest.Bearer(h.session)))["status"], "revoked", "cascade")
	}
	h.agentsProblem(h.executes(key, id, "members.list", map[string]any{}), 403, "agent_revoked", "agent_revoked", "its agent")
	for name, send := range hostRoutes(h, id) {
		h.agentsProblem(send(h.host.hostJWT(map[string]any{"agent_public_key": newKey("EdDSA").jwk()}, nil)), 403, "host_revoked", "host_revoked", name)
	}
	// §8.8.1: the key stays burned.
	h.agentsProblem(h.addHost(h.session, h.userID, h.host, nil), 409, "conflict", "", "a revoked key")
}

// A token host is revoked as in v1.0.0: the agents it enrolled keep working.
func TestRevokingATokenHostLeavesItsAgents(t *testing.T) {
	h := unrecorded(t)
	host := h.data(h.c.Post("/agents/hosts", map[string]any{"name": "Laptop"}, contracttest.Bearer(h.session)))
	key := newKey("EdDSA")
	enrolled := h.data(h.bearer(str(host["enrollment_token"]), "POST", "/agents/enroll", map[string]any{"name": "Bot", "mode": "delegated", "auth": "private_key_jwt", "jwk": key.jwk()}))
	h.status(h.c.Delete("/agents/hosts/"+str(host["id"]), contracttest.Bearer(h.session)), 200, "revoke")
	h.status(h.signed(key, str(enrolled["id"]), "GET", "/agents/session", nil, nil), 200, "still active")
}

// §5.3, §5.13: what a registration refuses, and nothing is left behind.
func TestSection5_3ARefusedRegistration(t *testing.T) {
	h := unrecorded(t)
	bad := func(body, claims map[string]any, status int, code string) map[string]any {
		t.Helper()
		extra := map[string]any{"agent_public_key": newKey("EdDSA").jwk()}
		for k, v := range claims {
			extra[k] = v
		}
		return h.agentsProblem(h.c.Post("/agent/register", body, contracttest.Bearer(h.host.hostJWT(extra, nil))), status, code, code, code)
	}
	ok := map[string]any{"name": "Reader"}
	bad(map[string]any{}, nil, 400, "invalid_request")
	bad(map[string]any{"name": strings.Repeat("x", 161)}, nil, 400, "invalid_request")
	bad(map[string]any{"name": "Reader", "mode": "sudo"}, nil, 400, "unsupported_mode")
	bad(map[string]any{"name": "Reader", "mode": 5}, nil, 400, "unsupported_mode")
	bad(map[string]any{"name": "Reader", "capabilities": "members.list"}, nil, 400, "invalid_request")
	bad(map[string]any{"name": "Reader", "reason": strings.Repeat("x", 501)}, nil, 400, "invalid_request")
	bad(map[string]any{"name": "Reader", "reason": "a\x00b"}, nil, 400, "invalid_request")
	bad(map[string]any{"name": "Reader", "binding_message": strings.Repeat("x", 161)}, nil, 400, "invalid_request")
	bad(ok, map[string]any{"agent_public_key": nil}, 400, "invalid_request")
	bad(ok, map[string]any{"agent_public_key": "key"}, 400, "invalid_request")
	bad(ok, map[string]any{"agent_public_key": newKey("ES256").jwk()}, 400, "unsupported_algorithm")
	bad(ok, map[string]any{"agent_public_key": nil, "agent_jwks_url": "https://keys.example.com/a", "agent_kid": "k"}, 400, "invalid_request")
	private := newKey("EdDSA").jwk()
	private["d"] = "x"
	bad(ok, map[string]any{"agent_public_key": private}, 400, "invalid_request") // §8.1: a private key MUST never be sent
	unknown := bad(map[string]any{"name": "Reader", "capabilities": []any{"members.list", "nope", map[string]any{"name": "nor.this"}, 5}}, nil, 400, "invalid_capabilities")
	h.equal(unknown["invalid_capabilities"], []any{"nope", "nor.this", "?"}, "§5.13: the names")
	// §2.13: an unknown constraint operator MUST be refused, not ignored.
	op := bad(map[string]any{"name": "Reader", "capabilities": []any{map[string]any{"name": "credits.spend", "constraints": map[string]any{"amount": map[string]any{"max": 5, "eq": 5}}}}}, nil, 400, "unknown_constraint_operator")
	h.equal(op["unknown_operators"], []any{"eq"}, "§2.13: the operators")
	h.equal(len(h.list(h.c.Get("/agents", contracttest.Bearer(h.session)))), 0, "nothing registered")
}

// §2.13: an exact value is a constraint.
func TestSection2_13AnExactValue(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{map[string]any{"name": "credits.spend", "constraints": map[string]any{"amount": 5}}}})
	registered := h.json(resp)
	h.decides(registered["approval"], "approve")
	id := str(registered["agent_id"])
	h.status(h.executes(key, id, "credits.spend", map[string]any{"amount": 5}), 200, "the value")
	h.agentsProblem(h.executes(key, id, "credits.spend", map[string]any{"amount": 4}), 403, "constraint_violated", "", "another")
	h.agentsProblem(h.executes(key, id, "credits.spend", map[string]any{}), 400, "invalid_request", "invalid_request", "none: required by the schema")
}

// §5.4: what a capability request refuses.
func TestSection5_4ARefusedRequest(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(nil)
	registered := h.json(resp)
	id := str(registered["agent_id"])
	h.equal([]any{registered["status"], registered["agent_capability_grants"]}, []any{"active", []any{}}, "§5.3: without capabilities")
	h.agentsProblem(h.requests(key, id), 400, "invalid_request", "invalid_request", "none")
	h.agentsProblem(h.requests(key, id, "nope"), 400, "invalid_capabilities", "invalid_capabilities", "unknown")
	h.agentsProblem(h.c.Post("/agent/request-capability", map[string]any{"capabilities": []any{"members.list"}}, contracttest.Bearer(h.host.hostJWT(nil, nil))), 401, "invalid_jwt", "", "a host JWT")
	h.agentsProblem(h.c.Post("/agent/request-capability", map[string]any{"capabilities": []any{"members.list"}}, contracttest.Bearer(key.requestJWT(id, base+"/agent/request-capability", nil, nil))), 401, "invalid_jwt", "", "§4.3: aud is the issuer")
	granted := h.json(h.requests(key, id, "members.list"))
	h.equal([]any{granted["status"], at(granted["agent_capability_grants"], 0)["status"]}, []any{"granted", "active"}, "what the reference client reads")
	if _, has := granted["approval"]; has {
		t.Error("§5.4: an approval only when a grant is pending")
	}
}

// §5.11, §2.12, §5.13: what an execution refuses, with the protocol's codes.
func TestSection5_11ARefusedExecution(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{map[string]any{"name": "members.list", "constraints": map[string]any{"budget": map[string]any{"count": 1}}}}})
	id := str(h.json(resp)["agent_id"])
	h.agentsProblem(h.executes(key, id, "nope", nil), 404, "capability_not_found", "", "unknown")
	h.agentsProblem(h.executes(key, id, "", nil), 400, "invalid_request", "invalid_request", "no capability")
	h.agentsProblem(h.executes(key, id, "org.rename", map[string]any{"name": "x"}), 403, "capability_not_granted", "", "not granted")
	h.agentsProblem(h.executes(key, id, "members.list", map[string]any{"extra": 1}), 400, "invalid_request", "invalid_request", "§5.2.1: stale arguments")
	h.agentsProblem(h.executes(key, id, "members.list", []any{}), 400, "invalid_request", "invalid_request", "not an object")
	restricted := key.requestJWT(id, base+"/capability/execute", map[string]any{"capabilities": []any{"other"}}, nil)
	h.agentsProblem(h.c.Post("/capability/execute", map[string]any{"capability": "members.list"}, contracttest.Bearer(restricted)), 403, "capability_not_granted", "", "§4.3: the JWT's capabilities")
	for _, aud := range []string{base, base + "/agents/execute", base + "/capability/execute/"} {
		h.agentsProblem(h.c.Post("/capability/execute", map[string]any{"capability": "members.list"}, contracttest.Bearer(key.requestJWT(id, aud, nil, nil))), 401, "invalid_jwt", "", "§4.3: aud is the location")
	}
	h.status(h.executes(key, id, "members.list", nil), 200, "the budget")
	h.agentsProblem(h.executes(key, id, "members.list", nil), 403, "limit_exceeded", "limit_exceeded", "§5.13: spent")
	st := h.statusOf(id)
	h.equal([]any{at(st["agent_capability_grants"], 0)["status"], len(st["agent_capability_grants"].([]any))}, []any{"denied", 1}, "a spent grant is not active")
}

// §2.12: executing a capability the server removed is 403 capability_not_granted, not 404.
func TestSection2_12ARemovedCapability(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(h.json(resp)["agent_id"])
	if _, err := h.srv.DB.Update(t.Context(), agents.TableGrants, map[string]any{"agent_id": id}, map[string]any{"capability": "gone"}); err != nil {
		t.Fatal(err)
	}
	h.agentsProblem(h.executes(key, id, "gone", nil), 403, "capability_not_granted", "", "removed")
	h.equal(at(h.statusOf(id)["agent_capability_grants"], 0)["status"], "denied", "and not offered as active")
}

// An owner's pause: the client sees an agent that cannot authenticate, and not one to reactivate.
func TestASuspendedAgentsStatus(t *testing.T) {
	h := unrecorded(t)
	_, resp := h.registers(nil)
	id := str(h.json(resp)["agent_id"])
	h.status(h.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(h.session)), 200, "suspend")
	h.equal(h.statusOf(id)["status"], "pending", "suspended")
	h.status(h.c.Post("/agents/"+id+"/resume", nil, contracttest.Bearer(h.session)), 200, "resume")
	h.status(h.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(h.session)), 200, "revoke")
	h.equal(h.statusOf(id)["status"], "revoked", "revoked")
}

// A pending agent is revocable like any other.
func TestAPendingAgentIsRevocable(t *testing.T) {
	h := unrecorded(t)
	_, resp := h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	registered := h.json(resp)
	id := str(registered["agent_id"])
	h.status(h.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(h.session)), 200, "revoke")
	h.agentsProblem(h.c.Post("/agents/approvals/"+str(obj(registered["approval"])["id"])+"/decide", map[string]any{"decision": "approve"}, contracttest.Bearer(h.session)), 409, "conflict", "", "its approval is cancelled")
	h.equal(h.statusOf(id)["status"], "revoked", "revoked")
}

// What POST /agents/hosts takes as a key.
func TestAHostsKey(t *testing.T) {
	h := unrecorded(t)
	bad := func(fields map[string]any, status int, typ string) {
		t.Helper()
		body := map[string]any{"name": "Host"}
		for k, v := range fields {
			body[k] = v
		}
		h.agentsProblem(h.c.Post("/agents/hosts", body, contracttest.Bearer(h.session)), status, typ, "", typ)
	}
	private := newKey("EdDSA").jwk()
	private["d"] = "x"
	bad(map[string]any{"public_key": private}, 422, "invalid_input")
	bad(map[string]any{"public_key": newKey("ES256").jwk()}, 422, "invalid_input")
	bad(map[string]any{"public_key": "key"}, 422, "invalid_input")
	bad(map[string]any{"public_key": map[string]any{}}, 422, "invalid_input")
	bad(map[string]any{"public_key": newKey("EdDSA").jwk(), "jwks_url": "https://keys.example.com/jwks"}, 422, "invalid_input")
	bad(map[string]any{"public_key": h.host.jwk(), "proof": h.host.hostLink(h.userID, nil, nil)}, 409, "conflict")
	bad(map[string]any{"jwks_url": "https://keys.example.com/jwks"}, 422, "invalid_input") // only in DiscoveryAgentAuth
}

// A key is taken with its holder's proof that the account is to own the host (5.9): a public key is known to
// every server the host uses, and whoever registered it first would own what the host's agents do.
func TestAHostsKeyIsProven(t *testing.T) {
	h := unrecorded(t)
	eveID, eve := h.login("eve@example.com")
	ada, mallory := newKey("EdDSA"), newKey("EdDSA")
	now := time.Now().Unix()
	link := func(claims map[string]any) string {
		all := map[string]any{"sub": eveID}
		for n, v := range claims {
			all[n] = v
		}
		return ada.hostLink(eveID, all, nil)
	}
	for name, proof := range map[string]any{
		"none": nil, "not a JWT": "x", "not a string": 5, "empty": "",
		"a host JWT": ada.hostJWT(nil, nil), "a host JWT that names the account": ada.hostJWT(map[string]any{"sub": eveID}, nil),
		"an agent JWT":      ada.requestJWT(eveID, base, map[string]any{"iss": ada.kid()}, nil),
		"another account's": ada.hostLink(h.userID, nil, nil), "nobody's": link(map[string]any{"sub": nil}),
		"another key's": mallory.hostLink(eveID, nil, nil), "another key's, in its name": mallory.hostLink(eveID, map[string]any{"iss": ada.kid()}, nil),
		"another iss": link(map[string]any{"iss": mallory.kid()}), "no iss": link(map[string]any{"iss": nil}),
		"another server's": link(map[string]any{"aud": "https://other.example"}), "no aud": link(map[string]any{"aud": nil}), "a list of aud": link(map[string]any{"aud": []any{base}}),
		"expired": link(map[string]any{"iat": now - 120, "exp": now - 31}), "from the future": link(map[string]any{"iat": now + 40, "exp": now + 60}),
		"too long": link(map[string]any{"exp": now + 301}), "no exp": link(map[string]any{"exp": nil}), "no iat": link(map[string]any{"iat": nil}), "no jti": link(map[string]any{"jti": nil}),
		"a key of its own": ada.hostLink(eveID, nil, map[string]any{"jwk": ada.jwk()}), "another alg": ada.hostLink(eveID, nil, map[string]any{"alg": "ES256"}),
		"no alg": ada.hostLink(eveID, nil, map[string]any{"alg": "none"}),
	} {
		resp := h.c.Post("/agents/hosts", map[string]any{"name": "Mine", "public_key": ada.jwk(), "proof": proof}, contracttest.Bearer(eve))
		h.agentsProblem(resp, 422, "invalid_input", "", name)
	}
	h.equal(len(h.list(h.c.Get("/agents/hosts", contracttest.Bearer(eve)))), 0, "nothing is Eve's")

	proof := ada.hostLink(h.userID, nil, nil)
	resp := h.addHost(h.session, h.userID, ada, map[string]any{"proof": proof})
	h.equal([]any{resp.StatusCode, h.data(resp)["key_thumbprint"]}, []any{201, ada.kid()}, "Ada's own")
	h.agentsProblem(h.addHost(h.session, h.userID, ada, map[string]any{"proof": proof}), 422, "invalid_input", "", "used already")

	// The SDK's proof is one.
	fleetKey, err := agent.GenerateKey(agent.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := agent.SignHostLink(fleetKey, base, h.userID)
	if err != nil {
		t.Fatal(err)
	}
	h.status(h.c.Post("/agents/hosts", map[string]any{"name": "SDK", "public_key": fleetKey.PublicJWK(), "proof": signed}, contracttest.Bearer(h.session)), 201, "agent.SignHostLink")

	// An organization's host names the organization.
	fleet := newKey("EdDSA")
	h.agentsProblem(h.addHost(h.session, h.userID, fleet, map[string]any{"organization_id": h.orgID}), 422, "invalid_input", "", "the person's, for an organization")
	h.agentsProblem(h.addHost(h.session, h.orgID, fleet, nil), 422, "invalid_input", "", "the organization's, for a person")
	h.status(h.addHost(h.session, h.orgID, fleet, map[string]any{"organization_id": h.orgID}), 201, "the organization's")
}

// A pending agent's key mints a token that carries and opens nothing.
func TestAPendingAgentsTokenOpensNothing(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"mode": "autonomous", "capabilities": []any{"org.rename"}})
	id := str(h.json(resp)["agent_id"])
	minted := h.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion": key.assertion(id, base+"/oauth2/token"), "scope": "org.update"})
	tok := str(h.json(minted)["access_token"])
	if tok == "" {
		return // nothing minted
	}
	for _, path := range []string{"/agents/session", "/capability/list", "/auth/me"} {
		if got := h.bearer(tok, "GET", path, nil); got.StatusCode < 400 {
			t.Errorf("%s: %d", path, got.StatusCode)
		}
	}
}

// What a caller writes reaches the store only in a form an id, a thumbprint or a URL can have: a NUL is
// no 500 (PostgreSQL refuses it), and nothing unauthenticated looks up a megabyte.
func TestAnUnauthenticatedLookupIsBounded(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(nil)
	id := str(h.json(resp)["agent_id"])
	_ = key
	for _, bad := range []string{"a\x00b", strings.Repeat("a", 7000), "\u0007"} {
		for _, claim := range []string{"iss", "host_jwks_url"} {
			extra := map[string]any{claim: bad}
			if claim == "host_jwks_url" {
				extra["host_public_key"] = nil
			}
			h.agentsProblem(h.c.Get("/agent/status?agent_id="+id, contracttest.Bearer(h.host.hostJWT(extra, nil))), 401, "invalid_jwt", "", claim)
		}
		h.agentsProblem(h.c.Get("/agent/status?agent_id="+url.QueryEscape(bad), contracttest.Bearer(h.host.hostJWT(nil, nil))), 404, "agent_not_found", "agent_not_found", "agent_id")
		h.agentsProblem(h.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(bad, base, nil, nil))), 401, "invalid_jwt", "", "sub")
		h.agentsProblem(h.signed(key, bad, "GET", "/agents/session", nil, nil), 401, "invalid_jwt", "", "sub on the Polaris surface")
	}
	h.agentsProblem(h.c.Get("/agent/status?agent_id=%ff%fe", contracttest.Bearer(h.host.hostJWT(nil, nil))), 404, "agent_not_found", "agent_not_found", "not UTF-8")
}

// A token minted while a registration waited ends with its denial.
func TestADeniedRegistrationEndsItsTokens(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"mode": "autonomous", "capabilities": []any{"org.rename"}})
	registered := h.json(resp)
	id := str(registered["agent_id"])
	minted := h.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		"client_assertion": key.assertion(id, base+"/oauth2/token"), "scope": "profile"})
	if minted.StatusCode != 200 {
		t.Skipf("a pending agent mints nothing: %d", minted.StatusCode)
	}
	h.decides(registered["approval"], "deny")
	rows, err := h.srv.DB.FindMany(t.Context(), "polaris_oauth_token", map[string]any{"client_id": id}, store.Query{})
	if err != nil || len(rows) == 0 {
		t.Fatalf("%v %v", rows, err)
	}
	for _, row := range rows {
		if row["revoked_at"] == nil {
			t.Errorf("a token outlived the denial: %v", row["id"])
		}
	}
}
