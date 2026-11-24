package agents_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
)

func perMinute(n int) config.RateLimit { return config.RateLimit{Limit: n, Window: time.Minute} }

// limited is a server with the limits, and an agent of a host its owner registered that was granted
// members.list.
func limited(t *testing.T, limits agents.RateLimits) (u *unknownCase, host, key *agentKey, id string) {
	t.Helper()
	u = anUnknownHost(t, func(c *agents.Config) { c.RateLimits = limits })
	host = newKey("EdDSA")
	u.status(u.addHost(u.session, u.userID, host, nil), 201, "a host")
	key, id = u.agentOf(host)
	return u, host, key, id
}

func (u *unknownCase) agentOf(host *agentKey) (*agentKey, string) {
	u.t.Helper()
	key := newKey("EdDSA")
	resp := u.registersAs(host, key, map[string]any{"capabilities": []any{"members.list"}})
	u.status(resp, 200, "register")
	return key, str(u.json(resp)["agent_id"])
}

func (u *unknownCase) isLimited(resp *http.Response, what string) {
	u.t.Helper()
	body := u.agentsProblem(resp, 429, "rate_limited", "rate_limited", what)
	if resp.Header.Get("Retry-After") == "" || body["message"] == nil {
		u.t.Errorf("%s: §8.13: %v %v", what, resp.Header, body)
	}
}

// §8.13: per agent, whatever it calls, and only what it signed: a sub is anybody's to write.
func TestSection8_13AnAgentIsLimited(t *testing.T) {
	u, host, key, id := limited(t, agents.RateLimits{Agent: perMinute(3)})
	for range 5 {
		u.status(u.executes(newKey("EdDSA"), id, "members.list", nil), 401, "somebody else's signature")
	}
	u.status(u.executes(key, id, "members.list", nil), 200, "execute")
	u.status(u.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, nil, nil))), 200, "list")
	u.status(u.c.Post("/agent/request-capability", map[string]any{"capabilities": []any{"org.rename"}}, contracttest.Bearer(key.requestJWT(id, base, nil, nil))), 200, "request")
	u.isLimited(u.executes(key, id, "members.list", nil), "execute")
	u.isLimited(u.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, nil, nil))), "list")
	u.isLimited(u.c.Get("/capability/describe?name=members.list", contracttest.Bearer(key.requestJWT(id, base, nil, nil))), "describe")
	u.isLimited(u.c.Post("/agent/request-capability", map[string]any{"capabilities": []any{"org.rename"}}, contracttest.Bearer(key.requestJWT(id, base, nil, nil))), "request")
	u.status(u.statusAs(host, id), 200, "its host is another")
	other, otherID := u.agentOf(host)
	u.status(u.executes(other, otherID, "members.list", nil), 200, "and so is another agent of it")
}

// §8.13: at a capability's location too.
func TestSection8_13AnAgentIsLimitedAtALocation(t *testing.T) {
	u, host, _, _ := limited(t, agents.RateLimits{Agent: perMinute(2)})
	key := newKey("EdDSA")
	registered := u.json(u.registersAs(host, key, map[string]any{"capabilities": []any{"invite"}}))
	u.status(u.decides(u.session, registered, approve), 200, "approve")
	ran := 0
	guarded := u.plugin.Protect("invite", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran++ }))
	body := map[string]any{"capability": "invite", "arguments": map[string]any{"email": "bob@acme.test"}}
	for _, want := range []int{200, 200, 429} {
		w := callHost(guarded, location, key.requestJWT(str(registered["agent_id"]), location, nil, nil), body)
		u.equal([]any{w.Code, w.Header().Get("Retry-After") != "", problemOf(w)["error"] == "rate_limited"}, []any{want, want == 429, want == 429}, "location")
	}
	u.equal(ran, 2, "ran")
}

// §8.13: per host, its agents' requests included.
func TestSection8_13AHostIsLimited(t *testing.T) {
	u, host, key, id := limited(t, agents.RateLimits{Host: perMinute(4)}) // one spent: the registration
	u.status(u.statusAs(host, id), 200, "status")
	u.status(u.executes(key, id, "members.list", nil), 200, "its agent")
	u.status(u.c.Get("/capability/list", contracttest.Bearer(host.hostJWT(nil, nil))), 200, "list")
	u.isLimited(u.statusAs(host, id), "status")
	u.isLimited(u.executes(key, id, "members.list", nil), "its agent")
	u.isLimited(u.registersAs(host, newKey("EdDSA"), nil), "register")
	other := newKey("EdDSA")
	u.status(u.addHost(u.session, u.userID, other, nil), 201, "another host")
	u.status(u.registersAs(other, newKey("EdDSA"), nil), 200, "has its own")
	forged := newKey("EdDSA").hostJWT(map[string]any{"iss": other.kid(), "host_public_key": other.jwk()}, nil)
	for range 5 {
		u.status(u.c.Get("/agent/status?agent_id=x", contracttest.Bearer(forged)), 401, "somebody else's signature")
	}
	u.status(u.registersAs(other, newKey("EdDSA"), nil), 200, "which a forged JWT does not spend")
}

// §8.13: per address, before anything is verified, on every route of the protocol.
func TestSection8_13AnAddressIsLimited(t *testing.T) {
	u, host, _, _ := limited(t, agents.RateLimits{Address: perMinute(2)}) // one spent: the registration
	u.status(u.c.Get("/capability/list"), 200, "the last")
	for name, resp := range map[string]*http.Response{
		"list": u.c.Get("/capability/list"), "describe": u.c.Get("/capability/describe?name=members.list"), "status": u.c.Get("/agent/status?agent_id=x"),
		"register": u.registersAs(host, newKey("EdDSA"), nil), "request": u.c.Post("/agent/request-capability", nil), "execute": u.c.Post("/capability/execute", nil),
	} {
		u.isLimited(resp, name)
	}
	u.status(u.c.Get("/.well-known/agent-configuration"), 200, "discovery is a constant")
	u.status(u.c.Get("/agents/hosts", contracttest.Bearer(u.session)), 200, "and the other routes are not the protocol's")
}

// What agents send does not spend the budget people refresh their sessions with.
func TestAgentsDoNotSpendTheRefreshBudget(t *testing.T) {
	u, host, _, id := limited(t, agents.RateLimits{})
	for range 70 {
		u.status(u.statusAs(host, id), 200, "status")
	}
	resp := u.c.Post("/auth/token/refresh", map[string]any{"refresh_token": strings.Repeat("x", 43)})
	if resp.StatusCode == 429 {
		t.Error("nobody at this address can refresh a session")
	}
}
