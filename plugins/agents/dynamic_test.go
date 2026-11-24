package agents_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
)

// unknownCase is a server in the protocol's mode, a person with an organization, and a host the server
// does not know.
type unknownCase struct {
	*agentsCase
	userID, session, orgID string
	host                   *agentKey
}

func bootDynamic(t *testing.T, change func(*agents.Config), opts ...polaristest.Option) (*polaristest.Server, *agents.Plugin) {
	t.Helper()
	cfg := agents.Config{Capabilities: capabilities(), ApprovalURL: approveURL, Discovery: agents.DiscoveryAgentAuth}
	if change != nil {
		change(&cfg)
	}
	p := agents.New(cfg)
	srv := polaristest.New(t, append(opts, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{BaseURL: base}), p))...)
	return srv, p
}

func onClock(clk clock.Clock) polaristest.Option {
	return polaristest.WithConfig(func(c *polaris.Config) { c.Clock = clk })
}

func newUnknownCase(a *agentsCase) *unknownCase {
	a.t.Helper()
	userID, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	return &unknownCase{agentsCase: a, userID: userID, session: session, orgID: orgID, host: newKey("EdDSA")}
}

// anUnknownHost is newUnknownCase on a server of its own, without a fixture.
func anUnknownHost(t *testing.T, change func(*agents.Config), opts ...polaristest.Option) *unknownCase {
	t.Helper()
	srv, p := bootDynamic(t, change, opts...)
	return newUnknownCase(&agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p, ctx: t.Context()})
}

func (u *unknownCase) registersAs(host, key *agentKey, fields map[string]any) *http.Response {
	body := map[string]any{"name": "Reader", "mode": "delegated", "host_name": "Ada's laptop"}
	for k, v := range fields {
		body[k] = v
	}
	return u.c.Post("/agent/register", body, contracttest.Bearer(host.hostJWT(map[string]any{"agent_public_key": key.jwk()}, nil)))
}

// registers registers a new agent of the unknown host, pending.
func (u *unknownCase) registers(fields map[string]any) (*agentKey, map[string]any) {
	u.t.Helper()
	key := newKey("EdDSA")
	resp := u.registersAs(u.host, key, fields)
	body := u.json(resp)
	if resp.StatusCode != 200 || body["status"] != "pending" {
		u.t.Fatalf("register: %d %v", resp.StatusCode, body)
	}
	return key, body
}

func (u *unknownCase) statusAs(host *agentKey, id string) *http.Response {
	return u.c.Get("/agent/status?agent_id="+url.QueryEscape(id), contracttest.Bearer(host.hostJWT(nil, nil)))
}

// byCode is the approval a person sees behind the code the client showed them.
func (u *unknownCase) byCode(session string, registered map[string]any) *http.Response {
	code := str(obj(registered["approval"])["user_code"])
	return u.c.Get("/agents/approvals/code?user_code="+url.QueryEscape(code), contracttest.Bearer(session))
}

func (u *unknownCase) decides(session string, registered map[string]any, body map[string]any) *http.Response {
	return u.c.Post("/agents/approvals/"+str(obj(registered["approval"])["id"])+"/decide", body, contracttest.Bearer(session))
}

func (u *unknownCase) rows(table string, c store.Criteria) []store.Row {
	u.t.Helper()
	rows, err := u.srv.DB.FindMany(u.ctx, table, c, store.Query{})
	if err != nil {
		u.t.Fatal(err)
	}
	return rows
}

func (u *unknownCase) executes(key *agentKey, id, capability string, args any) *http.Response {
	return u.c.Post("/capability/execute", map[string]any{"capability": capability, "arguments": args},
		contracttest.Bearer(key.requestJWT(id, base+"/capability/execute", nil, nil)))
}

var (
	approve = map[string]any{"decision": "approve"}
	deny    = map[string]any{"decision": "deny"}
)

func TestAgentAuthUnknownHostFixtures(t *testing.T) {
	dir := contracttest.Fixtures(t, "agents")
	for name, test := range map[string]func(*unknownCase){
		"testAnUnknownHostIsApprovedByAPerson":           unknownHostIsApproved,
		"testAnUnknownHostsDeniedRegistrationIsRejected": unknownHostIsDenied,
	} {
		t.Run(name, func(t *testing.T) {
			srv, p := bootDynamic(t, nil)
			fx := contracttest.For(t, dir, protocolFixtures, name)
			test(newUnknownCase(&agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx), plugin: p, ctx: context.Background()}))
		})
	}
}

// §2.8, §5.3, §7.1: an unknown host registers, a person approves with the code, and the agent works.
func unknownHostIsApproved(u *unknownCase) {
	key, registered := u.registers(map[string]any{"capabilities": []any{"members.list", map[string]any{"name": "org.rename", "constraints": map[string]any{"name": map[string]any{"in": []any{"Acme 2"}}}}},
		"reason": "to tidy up", "preferred_method": "ciba", "login_hint": "ada@example.com", "binding_message": "Tidy?"})
	id := str(registered["agent_id"])
	ap := obj(registered["approval"])
	u.equal([]any{registered["name"], registered["mode"], registered["status"], registered["agent_capability_grants"]},
		[]any{"Reader", "delegated", "pending", []any{map[string]any{"capability": "members.list", "status": "pending"}, map[string]any{"capability": "org.rename", "status": "pending"}}}, "§5.3: nothing is granted")
	// §7.2: no push to somebody an unknown host names.
	u.equal([]any{ap["method"], ap["verification_uri"], ap["binding_message"], ap["strength"]}, []any{"device_authorization", approveURL, "Tidy?", "step_up"}, "§7.1: device authorization")

	st := u.json(u.statusAs(u.host, id))
	u.equal([]any{st["agent_id"], st["host_id"], st["status"], st["user_id"], len(st["agent_capability_grants"].([]any))}, []any{id, registered["host_id"], "pending", nil, 2}, "§5.5: pending")
	u.agentsProblem(u.executes(key, id, "members.list", map[string]any{}), 403, "agent_pending", "agent_pending", "§2.3: cannot act")

	page := u.data(u.byCode(u.session, registered))
	shown := obj(page["host"])
	u.equal([]any{obj(page["agent"])["name"], obj(page["agent"])["owner_id"], obj(page["agent"])["organization_id"], shown["name"], shown["known"], page["reason"], len(page["grants"].([]any))},
		[]any{"Reader", u.userID, u.orgID, "Ada's laptop", false, "to tidy up", 2}, "§8.10: what the person is shown")
	u.status(u.decides(u.session, registered, approve), 200, "approve")

	st = u.json(u.statusAs(u.host, id))
	u.equal([]any{st["agent_id"], st["host_id"], st["status"], st["user_id"], at(st["agent_capability_grants"], 0)["status"], at(st["agent_capability_grants"], 1)["status"]},
		[]any{id, registered["host_id"], "active", u.userID, "active", "active"}, "approved")
	u.status(u.executes(key, id, "members.list", map[string]any{}), 200, "it works")
	u.agentsProblem(u.executes(key, id, "org.rename", map[string]any{"name": "Other"}), 403, "constraint_violated", "", "within what was asked")
	hosts := u.list(u.c.Get("/agents/hosts", contracttest.Bearer(u.session)))
	u.equal([]any{len(hosts), at(hosts, 0)["id"], at(hosts, 0)["name"], at(hosts, 0)["key_thumbprint"], at(hosts, 0)["owner_id"]}, []any{1, registered["host_id"], "Ada's laptop", u.host.kid(), u.userID}, "§2.9: linked")

	// The host is known now: what the policy approves needs no person (§2.9).
	second := u.json(u.registersAs(u.host, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}))
	u.equal([]any{second["status"], second["host_id"]}, []any{"active", registered["host_id"]}, "a known host")
}

// §7.1: a denied registration is rejected and is not retried.
func unknownHostIsDenied(u *unknownCase) {
	key, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(registered["agent_id"])
	u.status(u.decides(u.session, registered, deny), 200, "deny")
	st := u.json(u.statusAs(u.host, id))
	u.equal([]any{st["status"], at(st["agent_capability_grants"], 0)["status"]}, []any{"rejected", "denied"}, "§7.1")
	u.agentsProblem(u.executes(key, id, "members.list", map[string]any{}), 403, "agent_rejected", "agent_rejected", "rejected")
	u.agentsProblem(u.registersAs(u.host, key, nil), 409, "agent_exists", "agent_exists", "§5.3: the same key again")
	u.agentsProblem(u.decides(u.session, registered, approve), 409, "conflict", "", "terminal")
	u.equal(len(u.list(u.c.Get("/agents/hosts", contracttest.Bearer(u.session)))), 0, "no host")
}

// §8.10: before the approval nothing is a host, an agent or a client; nobody's listings show it.
func TestSection8_10NothingExistsBeforeTheApproval(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	id := str(registered["agent_id"])
	u.equal([]any{len(u.rows(agents.TableHosts, store.Criteria{})), len(u.rows(agents.TableAgents, store.Criteria{})), len(u.rows(oauth.TableClients, store.Criteria{})), len(u.rows(agents.TableRegistrations, store.Criteria{}))},
		[]any{0, 0, 0, 1}, "stored")
	u.equal([]any{len(u.list(u.c.Get("/agents", contracttest.Bearer(u.session)))), len(u.list(u.c.Get("/agents/approvals", contracttest.Bearer(u.session))))}, []any{0, 0}, "listed")
	u.agentsProblem(u.c.Get("/agents/"+id, contracttest.Bearer(u.session)), 404, "not_found", "", "shown")
	u.agentsProblem(u.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(u.session)), 404, "not_found", "", "revoked")
	grant := u.rows(agents.TableGrants, store.Criteria{})[0].String("id")
	u.agentsProblem(u.c.Delete("/agents/grants/"+grant, contracttest.Bearer(u.session)), 404, "not_found", "", "its grant")
	u.status(u.decides(u.session, registered, approve), 200, "approve")
	u.equal([]any{len(u.rows(agents.TableHosts, store.Criteria{})), len(u.rows(agents.TableAgents, store.Criteria{})), len(u.rows(oauth.TableClients, store.Criteria{"client_id": id})), len(u.rows(agents.TableRegistrations, store.Criteria{}))},
		[]any{1, 1, 1, 0}, "stored at the approval")
}

// §4.5.1 step 8: a pending host does nothing but register and read that registration's status.
func TestSection4_5_1APendingHost(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, registered := u.registers(nil)
	id := str(registered["agent_id"])
	for _, path := range []string{"/capability/list", "/capability/describe?name=members.list"} {
		u.agentsProblem(u.c.Get(path, contracttest.Bearer(u.host.hostJWT(nil, nil))), 401, "invalid_jwt", "invalid_jwt", path)
	}
	u.agentsProblem(u.statusAs(newKey("EdDSA"), id), 404, "agent_not_found", "agent_not_found", "another unknown host")
	u.agentsProblem(u.statusAs(u.host, "nobody"), 404, "agent_not_found", "agent_not_found", "another agent")
	own := u.registerAgent(u.session, nil)
	u.agentsProblem(u.statusAs(u.host, str(own["id"])), 404, "agent_not_found", "agent_not_found", "an agent without a host")
}

// §4.2, §4.5.1, §4.6, §8.2: an unknown host's JWT is verified with the key it presents, whose thumbprint
// its iss must be.
func TestSection4_5_1AnUnknownHostsJWT(t *testing.T) {
	u := anUnknownHost(t, nil)
	other := newKey("EdDSA")
	now := time.Now()
	agent := map[string]any{"agent_public_key": newKey("EdDSA").jwk()}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{"agent_public_key": agent["agent_public_key"]}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	small := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(append([]byte{1}, make([]byte, 31)...))}
	for what, bad := range map[string]string{
		"§4.2 typ":                           u.host.hostJWT(agent, map[string]any{"typ": "JWT"}),
		"§8.18 aud":                          u.host.hostJWT(with(map[string]any{"aud": base + "/"}), nil),
		"§4.2 iss is not the thumbprint":     u.host.hostJWT(with(map[string]any{"iss": other.kid()}), nil),
		"§4.2 another key than the signer's": u.host.hostJWT(with(map[string]any{"host_public_key": other.jwk()}), nil),
		"another's iss and key":              u.host.hostJWT(with(map[string]any{"iss": other.kid(), "host_public_key": other.jwk()}), nil),
		"no key":                             u.host.hostJWT(with(map[string]any{"host_public_key": nil}), nil),
		"a key that is no object":            u.host.hostJWT(with(map[string]any{"host_public_key": "key"}), nil),
		"an EC key":                          newKey("ES256").hostJWT(agent, nil),
		"a point of small order":             u.host.hostJWT(with(map[string]any{"host_public_key": small}), nil),
		"a JWKS URL":                         u.host.hostJWT(with(map[string]any{"host_public_key": nil, "host_jwks_url": "https://keys.example.com/jwks"}), nil),
		"§8.2 iat 35 s ahead":                u.host.hostJWT(with(map[string]any{"iat": now.Add(35 * time.Second).Unix()}), nil),
		"§8.2 expired":                       u.host.hostJWT(with(map[string]any{"iat": now.Add(-100 * time.Second).Unix(), "exp": now.Add(-40 * time.Second).Unix()}), nil),
		"§4.2 no jti":                        u.host.hostJWT(with(map[string]any{"jti": nil}), nil),
		"a key in the header":                u.host.hostJWT(agent, map[string]any{"jwk": u.host.jwk()}),
		"no algorithm":                       u.host.hostJWT(agent, map[string]any{"alg": "none"}),
	} {
		u.agentsProblem(u.c.Post("/agent/register", map[string]any{"name": "x"}, contracttest.Bearer(bad)), 401, "invalid_jwt", "invalid_jwt", what)
	}
	u.equal(len(u.rows(agents.TableRegistrations, store.Criteria{})), 0, "nothing registered")
	// §4.6: a JWT is spent once, the host's approval included.
	jwt := u.host.hostJWT(agent, nil)
	registered := u.json(u.c.Post("/agent/register", map[string]any{"name": "x"}, contracttest.Bearer(jwt)))
	u.agentsProblem(u.c.Post("/agent/register", map[string]any{"name": "x"}, contracttest.Bearer(jwt)), 401, "invalid_jwt", "invalid_jwt", "again")
	u.status(u.decides(u.session, registered, approve), 200, "approve")
	u.agentsProblem(u.c.Get("/capability/list", contracttest.Bearer(jwt)), 401, "invalid_jwt", "invalid_jwt", "after the approval")
}

// What a registration refuses, and nothing is left behind (§5.3, §8.10).
func TestSection5_3AnUnknownHostsRefusedRegistration(t *testing.T) {
	u := anUnknownHost(t, nil)
	bad := func(body map[string]any, code string) {
		t.Helper()
		full := map[string]any{"name": "Reader"}
		for k, v := range body {
			full[k] = v
		}
		u.agentsProblem(u.c.Post("/agent/register", full, contracttest.Bearer(u.host.hostJWT(map[string]any{"agent_public_key": newKey("EdDSA").jwk()}, nil))), 400, code, code, code)
	}
	bad(map[string]any{"name": " "}, "invalid_request")
	bad(map[string]any{"name": "\u200b\ufeff"}, "invalid_request") // nothing to see
	bad(map[string]any{"host_name": "\u200b"}, "invalid_request")
	bad(map[string]any{"name": "Reader\u202edaer"}, "invalid_request") // the text a person reads is what was sent
	bad(map[string]any{"host_name": "a\x00b"}, "invalid_request")
	bad(map[string]any{"host_name": strings.Repeat("x", 161)}, "invalid_request")
	bad(map[string]any{"host_name": "lap\u2066top"}, "invalid_request")
	bad(map[string]any{"reason": "a\u2028b"}, "invalid_request")
	bad(map[string]any{"mode": "sudo"}, "unsupported_mode")
	bad(map[string]any{"capabilities": []any{"nope"}}, "invalid_capabilities")
	bad(map[string]any{"capabilities": []any{map[string]any{"name": "members.list", "constraints": map[string]any{"budget": map[string]any{"count": -1}}}}}, "invalid_request")
	u.agentsProblem(u.c.Post("/agent/register", map[string]any{"name": "x"}, contracttest.Bearer(u.host.hostJWT(nil, nil))), 400, "invalid_request", "invalid_request", "no agent key")
	for _, table := range []string{agents.TableRegistrations, agents.TableGrants, agents.TableApprovals} {
		u.equal(len(u.rows(table, store.Criteria{})), 0, table)
	}
}

// §5.3: the same host and agent key again is one registration: pending answers it, any other state is
// 409 agent_exists. An approval that expired is opened again.
func TestSection5_3ARegistrationIsIdempotent(t *testing.T) {
	clk := clock.NewFrozen(time.Now())
	u := anUnknownHost(t, nil, onClock(clk))
	key, first := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	again := u.json(u.registersAs(u.host, key, map[string]any{"capabilities": []any{"org.rename"}, "name": "Other"}))
	u.equal([]any{again["agent_id"], again["host_id"], again["name"], again["status"], again["agent_capability_grants"], obj(again["approval"])["id"]},
		[]any{first["agent_id"], first["host_id"], "Reader", "pending", first["agent_capability_grants"], obj(first["approval"])["id"]}, "the same")
	other := u.json(u.registersAs(u.host, newKey("EdDSA"), nil))
	u.equal([]any{other["host_id"], other["agent_id"] == first["agent_id"]}, []any{first["host_id"], false}, "another agent of the host")

	clk.Advance(time.Second)
	u.equal(obj(u.json(u.registersAt(clk, newKey("EdDSA")))["approval"])["expires_in"], 600, "a new approval")
	clk.Advance(4*time.Minute - time.Second)
	u.equal(obj(u.json(u.registersAt(clk, key))["approval"])["expires_in"], 360, "what is left of the approval")
	clk.Advance(7 * time.Minute)
	u.session = u.relogin()
	u.agentsProblem(u.decides(u.session, first, approve), 409, "conflict", "", "expired")
	refreshed := u.json(u.registersAt(clk, key))
	u.equal([]any{refreshed["agent_id"], refreshed["status"], obj(refreshed["approval"])["id"] == obj(first["approval"])["id"], obj(refreshed["approval"])["strength"]},
		[]any{first["agent_id"], "pending", false, "step_up"}, "a new approval")
	u.status(u.decides(u.session, refreshed, approve), 200, "approve")
	u.agentsProblem(u.registersAt(clk, key), 409, "agent_exists", "agent_exists", "active")
	u.equal(len(u.rows(agents.TableAgents, store.Criteria{})), 1, "one agent")
}

func (u *unknownCase) relogin() string {
	tok := str(u.data(u.c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": password}))["access_token"])
	return str(u.data(u.c.Post("/auth/switch-org", map[string]any{"organization_id": u.orgID}, contracttest.Bearer(tok)))["access_token"])
}

func (u *unknownCase) registersAt(clk clock.Clock, key *agentKey) *http.Response {
	now := clk.Now().Unix()
	jwt := u.host.hostJWT(map[string]any{"agent_public_key": key.jwk(), "iat": now, "exp": now + 60}, nil)
	return u.c.Post("/agent/register", map[string]any{"name": "Reader"}, contracttest.Bearer(jwt))
}

// The same for a host the server knows.
func TestSection5_3AKnownHostsRegistrationIsIdempotent(t *testing.T) {
	h := unrecorded(t)
	key, resp := h.registers(map[string]any{"capabilities": []any{"org.rename"}})
	first := h.json(resp)
	again := func() *http.Response {
		return h.c.Post("/agent/register", map[string]any{"name": "Reader", "capabilities": []any{"members.list"}}, contracttest.Bearer(h.host.hostJWT(map[string]any{"agent_public_key": key.jwk()}, nil)))
	}
	retried := h.json(again())
	h.equal([]any{retried["agent_id"], retried["status"], retried["agent_capability_grants"], obj(retried["approval"])["id"]},
		[]any{first["agent_id"], "pending", first["agent_capability_grants"], obj(first["approval"])["id"]}, "pending: the same")
	h.decides(first["approval"], "deny")
	h.agentsProblem(again(), 409, "agent_exists", "agent_exists", "rejected")
	active, resp := h.registers(nil)
	id := str(h.json(resp)["agent_id"])
	key = active
	h.agentsProblem(again(), 409, "agent_exists", "agent_exists", "active")
	h.status(h.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(h.session)), 200, "revoke")
	h.agentsProblem(again(), 409, "agent_exists", "agent_exists", "revoked")
}

// §2.9: a host MUST NOT be linked to more than one user. The first approval links it; another person
// neither sees nor decides what is left, and its owner does.
func TestSection2_9AHostIsLinkedToOnePerson(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, first := u.registers(nil)
	secondKey, second := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	_, stranger := u.login("eve@example.com")
	u.status(u.byCode(stranger, second), 200, "nobody's yet: whoever holds the code")
	u.status(u.decides(u.session, first, approve), 200, "approve")
	u.agentsProblem(u.byCode(stranger, second), 404, "not_found", "", "another person reads it")
	u.agentsProblem(u.decides(stranger, second, approve), 404, "not_found", "", "another person approves it")
	u.agentsProblem(u.decides(stranger, second, deny), 404, "not_found", "", "another person denies it")
	st := u.json(u.statusAs(u.host, str(second["agent_id"])))
	u.equal([]any{st["status"], st["host_id"]}, []any{"pending", first["host_id"]}, "still pending, under the known host")
	u.equal(u.json(u.registersAs(u.host, secondKey, nil))["agent_id"], second["agent_id"], "and idempotent")
	page := u.data(u.byCode(u.session, second))
	u.equal(obj(page["host"])["known"], true, "the host is known")
	u.status(u.decides(u.session, second, approve), 200, "its owner")
	u.equal(len(u.rows(agents.TableHosts, store.Criteria{})), 1, "one host")
}

// §2.11: a host revoked while a registration waits takes it with it.
func TestSection2_11ARevokedHostsWaitingRegistration(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, first := u.registers(nil)
	_, second := u.registers(nil)
	u.status(u.decides(u.session, first, approve), 200, "approve")
	u.status(u.c.Delete("/agents/hosts/"+str(first["host_id"]), contracttest.Bearer(u.session)), 200, "revoke")
	u.agentsProblem(u.decides(u.session, second, approve), 403, "host_revoked", "host_revoked", "approve")
	u.agentsProblem(u.statusAs(u.host, str(second["agent_id"])), 403, "host_revoked", "host_revoked", "status")
	u.agentsProblem(u.registersAs(u.host, newKey("EdDSA"), nil), 403, "host_revoked", "host_revoked", "§8.8.1: register")
	u.equal(len(u.rows(agents.TableAgents, store.Criteria{"status": "active"})), 0, "no agent")
}

// The key an owner registers while a registration waits makes the host theirs, an organization's too.
func TestAHostRegisteredWhileItWaits(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	host := u.data(u.c.Post("/agents/hosts", map[string]any{"name": "Fleet", "public_key": u.host.jwk(), "organization_id": u.orgID}, contracttest.Bearer(u.session)))
	_, stranger := u.login("eve@example.com")
	u.agentsProblem(u.decides(stranger, registered, approve), 404, "not_found", "", "a stranger")
	u.status(u.decides(u.session, registered, approve), 200, "its organization's owner")
	agent := u.data(u.c.Get("/agents/"+str(registered["agent_id"]), contracttest.Bearer(u.session)))
	u.equal([]any{agent["host_id"], agent["owner_type"], agent["owner_id"]}, []any{host["id"], "organization", u.orgID}, "the host's owner")
}

// The decision: the approver's own constraints, the permissions they hold, the strength of the session.
func TestAnApprovalOfAnUnknownHost(t *testing.T) {
	u := anUnknownHost(t, nil)
	key, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	_, stranger := u.login("eve@example.com") // without an organization: no permission in one
	u.agentsProblem(u.decides(stranger, registered, approve), 403, "permission_not_held", "", "§2.9: the approver grants what they hold")
	u.agentsProblem(u.decides(u.session, registered, map[string]any{"decision": "maybe"}), 422, "invalid_input", "", "decision")
	u.status(u.c.Post("/agents/approvals/"+str(obj(registered["approval"])["id"])+"/decide", approve), 401, "nobody")
	narrowed := map[string]any{"decision": "approve", "constraints": map[string]any{"budget": map[string]any{"count": 1}}}
	u.status(u.decides(u.session, registered, narrowed), 200, "narrowed")
	id := str(registered["agent_id"])
	u.status(u.executes(key, id, "members.list", nil), 200, "once")
	u.agentsProblem(u.executes(key, id, "members.list", nil), 403, "limit_exceeded", "limit_exceeded", "the approver's budget, not the policy's")
	u.agentsProblem(u.decides(u.session, registered, approve), 409, "conflict", "", "decided")
	// What was decided is recorded.
	for name, want := range map[string]int{agents.EventRegistrationRequested: 1, agents.EventEnrolled: 1, agents.EventGrantApproved: 1} {
		u.equal(len(u.audited(name)), want, name)
	}
	enrolled := u.audited(agents.EventEnrolled)[0]
	u.equal([]any{enrolled.ActorID, enrolled.Data["host_id"], enrolled.Data["agent_id"]}, []any{u.userID, registered["host_id"], id}, "the approver")
	for _, e := range u.audited(agents.EventRegistrationRequested) {
		raw, _ := json.Marshal(e.Data)
		for _, secret := range []string{strings.ReplaceAll(str(obj(registered["approval"])["user_code"]), "-", ""), str(obj(registered["approval"])["id"])} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("what lets anybody approve the host is in the audit trail: %s", raw)
			}
		}
	}
	_, denied := u.registersAnew()
	u.status(u.decides(u.session, denied, deny), 200, "deny")
	u.equal(len(u.audited(agents.EventRegistrationDenied)), 1, "denied")
}

// registersAnew registers an agent of another unknown host.
func (u *unknownCase) registersAnew() (*agentKey, map[string]any) {
	u.host = newKey("EdDSA")
	return u.registers(nil)
}

// A recent sign-in is asked of everybody, a person without a second factor too: step_up alone takes their
// session however old it is (§8.11).
func TestSection8_11AnOldSessionApprovesNoHost(t *testing.T) {
	clk := clock.NewFrozen(time.Now())
	u := anUnknownHost(t, nil, onClock(clk))
	_, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	clk.Advance(6 * time.Minute)
	problem := u.agentsProblem(u.decides(u.session, registered, approve), 403, "step_up_required", "", "signed in 6 minutes ago")
	u.equal(problem["strength"], "step_up", "and says what is missing")
	u.equal(len(u.rows(agents.TableHosts, store.Criteria{})), 0, "no host")
	u.status(u.decides(u.relogin(), registered, approve), 200, "signed in again")
}

// The strength is what the capabilities' risk needs, and no less than step_up.
func TestSection8_11LinkingAHostNeedsAFreshSignIn(t *testing.T) {
	u := anUnknownHost(t, func(c *agents.Config) { c.Strengths = map[string]string{agents.RiskHigh: agents.StrengthPasskey} })
	_, none := u.registers(nil)
	_, low := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	_, high := u.registers(map[string]any{"capabilities": []any{"members.list", "org.rename"}})
	u.equal([]any{obj(none["approval"])["strength"], obj(low["approval"])["strength"], obj(high["approval"])["strength"]}, []any{"step_up", "step_up", "passkey"}, "strengths")
	problem := u.agentsProblem(u.decides(u.session, high, approve), 403, "step_up_required", "", "a password session")
	u.equal(problem["strength"], "passkey", "and says which")
}

// §8.13: new registrations of unknown hosts are bounded per address, at sign-up's budget; a retry and a
// host the server knows are not.
func TestSection8_13UnknownHostsAreLimited(t *testing.T) {
	u := anUnknownHost(t, nil)
	key, first := u.registers(nil)
	for range 4 {
		u.registersAnew()
	}
	u.host = newKey("EdDSA")
	resp := u.registersAs(u.host, newKey("EdDSA"), nil)
	u.equal([]any{resp.StatusCode, u.json(resp)["error"], resp.Header.Get("Retry-After") != ""}, []any{429, "rate_limited", true}, "§8.13")
	u.equal(len(u.rows(agents.TableRegistrations, store.Criteria{})), 5, "nothing stored")
	owned := newKey("EdDSA")
	u.status(u.c.Post("/agents/hosts", map[string]any{"name": "Known", "public_key": owned.jwk()}, contracttest.Bearer(u.session)), 201, "a known host")
	u.status(u.registersAs(owned, newKey("EdDSA"), nil), 200, "is not limited")
	u.status(u.decides(u.session, first, deny), 200, "deny")
	_ = key
}

// An IPv6 client has a /64 of addresses: they are one for the budget, as for every other limit.
func TestUnknownHostsAreLimitedPerNetwork(t *testing.T) {
	u := anUnknownHost(t, nil)
	from := func(addr string) int {
		jwt := newKey("EdDSA").hostJWT(map[string]any{"agent_public_key": newKey("EdDSA").jwk()}, nil)
		return u.c.Post("/agent/register", map[string]any{"name": "x"}, contracttest.Bearer(jwt), contracttest.RemoteAddr(addr)).StatusCode
	}
	for i := range 5 {
		u.equal(from(fmt.Sprintf("[2001:db8::%d]:1", i+1)), 200, "within the budget")
	}
	u.equal(from("[2001:db8::ffff]:1"), 429, "another address of the /64")
	u.equal(from("[2001:db8:1::1]:1"), 200, "another network")
}

// A user code is 8 characters of 19: guesses are bounded per person, and so is a right one after them.
func TestUserCodesAreNotGuessed(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, registered := u.registers(nil)
	_, eve := u.login("eve@example.com")
	for i := range 10 {
		u.agentsProblem(u.c.Get("/agents/approvals/code?user_code=BCDF-GHJ"+string("BCDFGHJKLM"[i]), contracttest.Bearer(eve)), 404, "not_found", "", "a guess")
	}
	resp := u.byCode(eve, registered)
	u.equal([]any{resp.StatusCode, resp.Header.Get("Retry-After") != ""}, []any{429, true}, "a right guess too late")
	u.status(u.byCode(u.session, registered), 200, "another person")
}

// §7.1, §10.9: what nobody decided is deleted, a day after its approval expired; a known host's agent too.
func TestSection10_9WhatNobodyDecidesIsDeleted(t *testing.T) {
	clk := clock.NewFrozen(time.Now())
	u := anUnknownHost(t, nil, onClock(clk))
	key, registered := u.registers(map[string]any{"capabilities": []any{"members.list"}})
	owned := newKey("EdDSA")
	u.status(u.c.Post("/agents/hosts", map[string]any{"name": "Known", "public_key": owned.jwk()}, contracttest.Bearer(u.session)), 201, "a known host")
	pending := u.json(u.registersAs(owned, newKey("EdDSA"), map[string]any{"capabilities": []any{"org.rename"}}))
	active := u.json(u.registersAs(owned, newKey("EdDSA"), map[string]any{"capabilities": []any{"members.list"}}))
	prune := func(registrations, agentsDeleted int64) {
		t.Helper()
		got, err := u.plugin.Prune(u.ctx)
		if err != nil {
			t.Fatal(err)
		}
		u.equal([]any{got[agents.TableRegistrations], got[agents.TableAgents]}, []any{registrations, agentsDeleted}, "pruned")
	}
	prune(0, 0)
	clk.Advance(23 * time.Hour)
	prune(0, 0)
	u.equal(u.json(u.registersAt(clk, key))["status"], "pending", "a retry keeps it")
	clk.Advance(90 * time.Minute)
	prune(0, 1)
	clk.Advance(24 * time.Hour)
	prune(1, 0)
	prune(0, 0)
	for _, id := range []any{registered["agent_id"], pending["agent_id"]} {
		for table, column := range map[string]string{agents.TableRegistrations: "id", agents.TableAgents: "id", agents.TableGrants: "agent_id", agents.TableApprovals: "agent_id", oauth.TableClients: "client_id"} {
			u.equal(len(u.rows(table, store.Criteria{column: id})), 0, table)
		}
	}
	u.equal(len(u.rows(agents.TableAgents, store.Criteria{"id": active["agent_id"]})), 1, "an active agent stays")
	u.equal(len(u.audited(agents.EventRevoked)), 0, "deleted, not revoked")
	u.agentsProblem(u.c.Get("/agent/status?agent_id="+str(registered["agent_id"]), contracttest.Bearer(u.host.hostJWT(map[string]any{"iat": clk.Now().Unix(), "exp": clk.Now().Unix() + 60}, nil))), 404, "agent_not_found", "agent_not_found", "gone")
}

// A denied registration is gone after its day, whether or not anything pruned it: its keys may ask again.
func TestADeniedRegistrationEndsByItself(t *testing.T) {
	clk := clock.NewFrozen(time.Now())
	u := anUnknownHost(t, nil, onClock(clk))
	key, registered := u.registers(nil)
	u.status(u.decides(u.session, registered, deny), 200, "deny")
	status := func() *http.Response {
		now := clk.Now().Unix()
		return u.c.Get("/agent/status?agent_id="+str(registered["agent_id"]), contracttest.Bearer(u.host.hostJWT(map[string]any{"iat": now, "exp": now + 60}, nil)))
	}
	clk.Advance(23 * time.Hour)
	u.agentsProblem(u.registersAt(clk, key), 409, "agent_exists", "agent_exists", "within the day")
	u.equal(u.json(status())["status"], "rejected", "within the day")
	clk.Advance(2 * time.Hour)
	u.agentsProblem(status(), 404, "agent_not_found", "agent_not_found", "after it")
	again := u.json(u.registersAt(clk, key))
	u.equal([]any{again["status"], again["agent_id"] == registered["agent_id"]}, []any{"pending", false}, "a new one")
}

// The owner of a known host reads its waiting registrations as often as any approval.
func TestAKnownHostsWaitingRegistrationIsNoGuess(t *testing.T) {
	u := anUnknownHost(t, nil)
	_, first := u.registers(nil)
	_, second := u.registers(nil)
	u.status(u.decides(u.session, first, approve), 200, "approve")
	for range 12 {
		u.status(u.byCode(u.session, second), 200, "its owner")
	}
}

// A server whose host did not ask for it takes no unknown host.
func TestUnknownHostsAreTakenInTheProtocolsModeOnly(t *testing.T) {
	for name, change := range map[string]func(*agents.Config){
		"the default mode": func(c *agents.Config) { c.Discovery = agents.DiscoveryPolaris },
		"turned off":       func(c *agents.Config) { c.DisableDynamicHosts = true },
	} {
		t.Run(name, func(t *testing.T) {
			u := anUnknownHost(t, change)
			u.agentsProblem(u.registersAs(u.host, newKey("EdDSA"), nil), 401, "invalid_jwt", "invalid_jwt", "register")
			u.agentsProblem(u.statusAs(u.host, "x"), 401, "invalid_jwt", "invalid_jwt", "status")
			u.equal(len(u.rows(agents.TableRegistrations, store.Criteria{})), 0, "nothing stored")
			for range 12 { // nor is there a code to guess
				u.agentsProblem(u.c.Get("/agents/approvals/code?user_code=BCDF-GHJK", contracttest.Bearer(u.session)), 404, "not_found", "", "a wrong code")
			}
		})
	}
}
