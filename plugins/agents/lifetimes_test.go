package agents_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/store"
)

// agedCase is an agent of a host its owner registered, on a clock the test moves.
type agedCase struct {
	*unknownCase
	clk *clock.Frozen
	key *agentKey
	id  string
}

func aged(t *testing.T, l agents.Lifetimes, defaults ...any) *agedCase {
	t.Helper()
	return agedWith(t, func(cfg *agents.Config) { cfg.Lifetimes = l }, defaults...)
}

func agedWith(t *testing.T, change func(*agents.Config), defaults ...any) *agedCase {
	t.Helper()
	clk := clock.NewFrozen(time.Now())
	c := &agedCase{clk: clk, unknownCase: anUnknownHost(t, change, onClock(clk))}
	fields := map[string]any{}
	if len(defaults) > 0 {
		fields["default_capabilities"] = defaults
	}
	c.status(c.addHost(c.session, c.userID, c.host, fields), 201, "a host")
	c.key = newKey("EdDSA")
	resp := c.c.Post("/agent/register", map[string]any{"name": "Reader", "capabilities": []any{"members.list"}}, c.byHost(map[string]any{"agent_public_key": c.key.jwk()}))
	c.status(resp, 200, "register")
	c.id = str(c.json(resp)["agent_id"])
	return c
}

func (c *agedCase) claims(more map[string]any) map[string]any {
	now := c.clk.Now().Unix()
	out := map[string]any{"iat": now, "exp": now + 60}
	for n, v := range more {
		out[n] = v
	}
	return out
}

func (c *agedCase) byHost(more map[string]any) contracttest.Option {
	return contracttest.Bearer(c.host.hostJWT(c.claims(more), nil))
}

func (c *agedCase) acts() *http.Response {
	return c.c.Post("/capability/execute", map[string]any{"capability": "members.list"}, contracttest.Bearer(c.key.requestJWT(c.id, base+"/capability/execute", c.claims(nil), nil)))
}

func (c *agedCase) reads() map[string]any {
	c.t.Helper()
	resp := c.c.Get("/agent/status?agent_id="+c.id, c.byHost(nil))
	c.status(resp, 200, "status")
	return c.json(resp)
}

func (c *agedCase) reactivates() *http.Response {
	return c.c.Post("/agent/reactivate", map[string]any{"agent_id": c.id}, c.byHost(nil))
}

func (c *agedCase) fresh() string { return c.relogin() }

// §2.3, §2.4: the session is measured from the last request, the maximum from the activation; past either
// the agent is expired, and only an active agent acts.
func TestSection2_4TheSessionAndTheMaximum(t *testing.T) {
	c := aged(t, agents.Lifetimes{Session: 30 * time.Minute, Max: 2 * time.Hour})
	st := c.reads()
	c.equal([]any{st["status"], st["expires_at"], st["last_used_at"]}, []any{"active", c.stamp(30 * time.Minute), nil}, "§5.5: expires_at")
	for range 5 { // used every 20 minutes: 100 minutes
		c.clk.Advance(20 * time.Minute)
		c.status(c.acts(), 200, "in its session")
	}
	st = c.reads()
	c.equal([]any{st["last_used_at"], st["expires_at"]}, []any{c.stamp(0), c.stamp(20 * time.Minute)}, "the maximum comes first")
	c.clk.Advance(21 * time.Minute)
	c.equal(c.reads()["status"], "expired", "§2.4: the maximum")
	c.agentsProblem(c.acts(), 403, "agent_expired", "agent_expired", "§5.13")
	c.equal(c.reads()["status"], "expired", "a refused request extends nothing")

	c = aged(t, agents.Lifetimes{Session: 30 * time.Minute})
	c.clk.Advance(31 * time.Minute)
	c.equal(c.reads()["status"], "expired", "§2.4: the session")
	c.agentsProblem(c.acts(), 403, "agent_expired", "agent_expired", "§5.13")
	r := c.c.Post("/agents/grants/request", map[string]any{"capabilities": []any{"members.list"}}, contracttest.Bearer(c.key.requestJWT(c.id, base+"/agents/grants/request", c.claims(nil), nil)))
	c.equal([]any{r.StatusCode, c.json(r)["error"]}, []any{401, "agent_expired"}, "on the Polaris routes")
	c.equal(c.data(c.c.Get("/agents/"+c.id, contracttest.Bearer(c.fresh())))["status"], "expired", "its owner sees it")
}

func (c *agedCase) stamp(in time.Duration) string {
	return c.clk.Now().Add(in).UTC().Truncate(time.Second).Format(time.RFC3339)
}

// Without lifetimes, and for an agent no host's JWT registered, nothing expires.
func TestNothingExpiresWithoutLifetimes(t *testing.T) {
	c := aged(t, agents.Lifetimes{})
	c.clk.Advance(1000 * time.Hour)
	st := c.reads()
	c.equal([]any{st["status"], st["expires_at"]}, []any{"active", nil}, "no lifetimes")
	c.status(c.acts(), 200, "acts")
	resp := c.reactivates()
	c.equal([]any{resp.StatusCode, c.json(resp)["status"]}, []any{200, "active"}, "§5.6: an active agent is answered as it is")

	c = aged(t, agents.Lifetimes{Session: time.Hour, Max: time.Hour, Absolute: time.Hour})
	key := newKey("EdDSA")
	own := str(c.registerAgent(c.session, map[string]any{"name": "Owned", "auth": "private_key_jwt", "jwk": key.jwk()})["id"])
	c.clk.Advance(100 * time.Hour)
	r := c.c.Get("/agents/session", contracttest.Bearer(key.requestJWT(own, base+"/agents/session", c.claims(nil), nil)))
	c.equal(r.StatusCode, 200, "an owner's agent has no host to reactivate it")
	c.equal(len(c.rows(agents.TableAgents, store.Criteria{"id": own, "last_used_at": nil, "activated_at": nil})), 1, "nor is its use recorded")
}

// §2.4, §5.6: past the absolute lifetime the agent is revoked for good, with the kill switch.
func TestSection2_4TheAbsoluteLifetime(t *testing.T) {
	c := aged(t, agents.Lifetimes{Absolute: 24 * time.Hour})
	c.equal(c.reads()["expires_at"], c.stamp(24*time.Hour), "§5.5")
	c.clk.Advance(25 * time.Hour)
	c.equal(c.reads()["status"], "revoked", "§2.4")
	c.agentsProblem(c.acts(), 403, "agent_revoked", "agent_revoked", "§5.13")
	c.agentsProblem(c.reactivates(), 403, "absolute_lifetime_exceeded", "absolute_lifetime_exceeded", "§5.6")
	c.equal([]any{len(c.audited(agents.EventRevoked)), len(c.audited(agents.EventReceiptSealed))}, []any{1, 1}, "sealed")
	c.agentsProblem(c.reactivates(), 403, "agent_revoked", "agent_revoked", "§5.6: revoked now")

	// Prune does it for those nobody asks about, and suspended ones.
	c = aged(t, agents.Lifetimes{Absolute: 24 * time.Hour})
	c.status(c.c.Post("/agents/"+c.id+"/suspend", nil, contracttest.Bearer(c.session)), 200, "suspend")
	c.clk.Advance(25 * time.Hour)
	c.equal(c.reads()["status"], "revoked", "a pause does not stop the clock")
	if _, err := c.plugin.Prune(c.ctx); err != nil {
		t.Fatal(err)
	}
	c.equal(len(c.rows(agents.TableAgents, store.Criteria{"id": c.id, "status": "revoked"})), 1, "revoked")
}

// §5.6: an expired agent comes back with its host's default capabilities and nothing it had.
func TestSection5_6Reactivation(t *testing.T) {
	c := aged(t, agents.Lifetimes{Session: 30 * time.Minute, Absolute: 24 * time.Hour}, "members.list")
	asked := c.json(c.c.Post("/agent/request-capability", map[string]any{"capabilities": []any{"org.rename"}}, contracttest.Bearer(c.key.requestJWT(c.id, base, c.claims(nil), nil))))
	c.status(c.decides(c.session, asked, approve), 200, "an escalation")
	c.clk.Advance(31 * time.Minute)
	resp := c.reactivates()
	body := c.json(resp)
	grants := body["agent_capability_grants"].([]any)
	c.equal([]any{resp.StatusCode, body["status"], body["activated_at"], body["expires_at"], len(grants), at(grants, 0)["capability"], at(grants, 0)["status"], at(grants, 1)["status"]},
		[]any{200, "active", c.stamp(0), c.stamp(30 * time.Minute), 2, "members.list", "active", "denied"}, "§5.6")
	c.status(c.acts(), 200, "its baseline")
	refused := c.c.Post("/capability/execute", map[string]any{"capability": "org.rename", "arguments": map[string]any{"name": "x"}}, contracttest.Bearer(c.key.requestJWT(c.id, base+"/capability/execute", c.claims(nil), nil)))
	c.agentsProblem(refused, 403, "capability_not_granted", "", "§2.5: what it escalated to is gone")
	c.equal(len(c.audited(agents.EventReactivated)), 1, "audited")
	// The absolute clock is never reset.
	c.clk.Advance(24 * time.Hour)
	c.agentsProblem(c.reactivates(), 403, "absolute_lifetime_exceeded", "absolute_lifetime_exceeded", "§2.5")
}

// A budget the policy gives once is not given again by letting the agent expire: what is left of it is kept, and
// when nothing is a person is asked.
func TestAReactivationRenewsNoBudget(t *testing.T) {
	c := agedWith(t, func(cfg *agents.Config) {
		cfg.Lifetimes = agents.Lifetimes{Session: 30 * time.Minute}
		cfg.AutoApprove = map[string]agents.Budget{agents.RiskLow: {Count: 2}}
	}, "members.list")
	for range 2 {
		c.status(c.acts(), 200, "one of its two")
		c.clk.Advance(31 * time.Minute)
		if len(c.rows(agents.TableGrants, store.Criteria{"agent_id": c.id, "status": "active"})) == 0 {
			break
		}
		c.equal(c.json(c.reactivates())["status"], "active", "what is left")
	}
	c.equal(c.json(c.reactivates())["status"], "pending", "nothing is left: asked of a person")
}

// What the policy did not give, or gives no more, ends: so does what is not the host's default.
func TestAReactivationKeepsOnlyWhatThePolicyGives(t *testing.T) {
	c := aged(t, agents.Lifetimes{Session: 30 * time.Minute}, "org.rename") // members.list is not a default
	asked := c.json(c.c.Post("/agent/request-capability", map[string]any{"capabilities": []any{"org.rename"}}, contracttest.Bearer(c.key.requestJWT(c.id, base, c.claims(nil), nil))))
	c.status(c.decides(c.session, asked, approve), 200, "a person gave it")
	c.clk.Advance(31 * time.Minute)
	body := c.json(c.reactivates())
	grants := body["agent_capability_grants"].([]any)
	c.equal([]any{body["status"], len(grants), at(grants, 0)["status"], at(grants, 1)["status"]}, []any{"pending", 2, "denied", "pending"}, "a person decides again")
}

// A default the policy would give, but a person gave wider, ends as any other they gave.
func TestAReactivationEndsWhatAPersonGave(t *testing.T) {
	c := aged(t, agents.Lifetimes{Session: 30 * time.Minute}, "members.list")
	registered := c.json(c.c.Post("/agent/register", map[string]any{"name": "Wide", "capabilities": []any{map[string]any{"name": "members.list", "constraints": map[string]any{"budget": map[string]any{"count": 500}}}}},
		c.byHost(map[string]any{"agent_public_key": newKey("EdDSA").jwk()})))
	c.status(c.decides(c.session, registered, approve), 200, "a person gave it")
	c.id = str(registered["agent_id"])
	c.clk.Advance(31 * time.Minute)
	c.equal(c.json(c.reactivates())["status"], "pending", "asked again")
}

// §5.6: what a person must approve waits for them; denied, the agent is expired again and loses nothing else.
func TestSection5_6AReactivationAPersonApproves(t *testing.T) {
	c := aged(t, agents.Lifetimes{Session: 30 * time.Minute}, "org.rename")
	c.status(c.acts(), 200, "a receipt")
	c.clk.Advance(31 * time.Minute)
	first := c.json(c.reactivates())
	ap := obj(first["approval"])
	c.equal([]any{first["status"], ap["method"], first["activated_at"]}, []any{"pending", "device_authorization", nil}, "§5.6: pending")
	c.equal(c.reads()["status"], "pending", "§5.5")
	again := c.json(c.reactivates())
	c.equal([]any{again["status"], obj(again["approval"])["user_code"]}, []any{"pending", ap["user_code"]}, "a retry is the same one")
	c.status(c.decides(c.fresh(), first, deny), 200, "deny")
	c.equal(c.reads()["status"], "expired", "denied: as it was")
	second := c.json(c.reactivates())
	c.clk.Advance(11 * time.Minute)
	third := c.json(c.reactivates())
	c.equal([]any{third["status"], obj(third["approval"])["user_code"] == obj(second["approval"])["user_code"]}, []any{"pending", false}, "an approval that expired is opened again")
	// Nobody decides for days: a pruning does not take an agent that was active once.
	c.clk.Advance(72 * time.Hour)
	if _, err := c.plugin.Prune(c.ctx); err != nil {
		t.Fatal(err)
	}
	fourth := c.json(c.reactivates())
	c.status(c.decides(c.fresh(), fourth, approve), 200, "approve")
	st := c.reads()
	c.equal([]any{st["status"], st["activated_at"], st["expires_at"]}, []any{"active", c.stamp(0), c.stamp(30 * time.Minute)}, "approved: a new session")
	c.equal(len(c.rows(agents.TableReceipts, store.Criteria{"agent_id": c.id})), 1, "its receipts stay")
}

// §5.6: what is not expired is not reactivated. A suspended agent is its owner's to resume (5.2).
func TestSection5_6WhatIsNotExpired(t *testing.T) {
	c := aged(t, agents.Lifetimes{Session: 30 * time.Minute})
	c.status(c.c.Post("/agents/"+c.id+"/suspend", nil, contracttest.Bearer(c.session)), 200, "suspend")
	for range 2 {
		c.equal(c.reads()["status"], "pending", "a paused agent, past its session too")
		c.agentsProblem(c.reactivates(), 403, "agent_pending", "agent_pending", "paused")
		c.clk.Advance(time.Hour)
	}
	c.status(c.c.Post("/agents/"+c.id+"/resume", nil, contracttest.Bearer(c.fresh())), 200, "resume")
	c.equal(c.reads()["status"], "expired", "resumed past its session")
	c.status(c.reactivates(), 200, "reactivate")
	resp := c.c.Post("/agent/register", map[string]any{"name": "Asks", "capabilities": []any{"org.rename"}}, c.byHost(map[string]any{"agent_public_key": newKey("EdDSA").jwk()}))
	registered := c.json(resp)
	c.id = str(registered["agent_id"])
	c.agentsProblem(c.reactivates(), 403, "agent_pending", "agent_pending", "a registration that waits")
	c.status(c.decides(c.fresh(), registered, deny), 200, "deny")
	c.agentsProblem(c.reactivates(), 403, "agent_rejected", "agent_rejected", "denied")
	c.id = "nobody"
	c.agentsProblem(c.reactivates(), 404, "agent_not_found", "agent_not_found", "unknown")
	c.agentsProblem(c.c.Post("/agent/reactivate", nil, c.byHost(nil)), 400, "invalid_request", "invalid_request", "none")
}

// A denied registration stays denied however old (§5.6).
func TestADeniedRegistrationOutlivesItsLifetime(t *testing.T) {
	c := aged(t, agents.Lifetimes{Absolute: 24 * time.Hour})
	registered := c.json(c.c.Post("/agent/register", map[string]any{"name": "Asks", "capabilities": []any{"org.rename"}}, c.byHost(map[string]any{"agent_public_key": newKey("EdDSA").jwk()})))
	c.status(c.decides(c.session, registered, deny), 200, "deny")
	c.id = str(registered["agent_id"])
	c.clk.Advance(25 * time.Hour)
	c.agentsProblem(c.reactivates(), 403, "agent_rejected", "agent_rejected", "denied")
}

// A write per request would be one too many: the last use is recorded at most once a minute.
func TestTheLastUseIsRecordedOnceAMinute(t *testing.T) {
	c := aged(t, agents.Lifetimes{})
	start := c.stamp(0)
	c.status(c.acts(), 200, "first")
	c.clk.Advance(50 * time.Second)
	c.status(c.acts(), 200, "second")
	c.equal(c.reads()["last_used_at"], start, "within the minute")
	c.clk.Advance(20 * time.Second)
	c.status(c.acts(), 200, "third")
	c.equal(c.reads()["last_used_at"], c.stamp(0), "after it")
}
