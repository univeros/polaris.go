package agents_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// The recorded lifecycle flows: register and enrol, approve grants by each method or by policy,
// execute with budgets and receipts, and the kill switch.
func TestAgentsLifecycle(t *testing.T) {
	run(t, lifecycleFixtures, map[string]func(*agentsCase){
		"testRegisterAndEnrollAgentsAndHosts":          registerAndEnroll,
		"testGrantsAreApprovedByEachMethodOrByPolicy":  grantsByEachMethod,
		"testExecutionBudgetsReceiptsAndTheKillSwitch": executionBudgetsReceiptsKillSwitch,
	})
}

func registerAndEnroll(a *agentsCase) {
	userID, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	key := newKey("ES256")

	own := a.registerAgent(session, map[string]any{"name": "Deploy bot", "mode": "autonomous", "capabilities": []any{"members.list"}})
	if !strings.HasPrefix(str(own["client_secret"]), "pcs_") {
		a.t.Errorf("secret %v", own["client_secret"])
	}
	g0 := at(own["grants"], 0)
	a.equal([]any{own["owner_type"], own["owner_id"], own["organization_id"], g0["status"], g0["approved_via"], obj(g0["budget"])["total"], own["approval"]},
		[]any{"user", userID, orgID, "active", "auto", 100, nil}, "own agent")

	org := a.registerAgent(session, map[string]any{"name": "Reviewer", "auth": "private_key_jwt", "jwk": key.jwk(), "organization_id": orgID})
	jwk := obj(org["public_jwk"])
	a.equal([]any{org["owner_type"], org["owner_id"], org["created_by"], jwk["kid"], jwk["alg"]}, []any{"organization", orgID, userID, key.kid(), "ES256"}, "org agent")
	if _, has := org["client_secret"]; has {
		a.t.Error("a key agent has no secret")
	}
	a.agentsProblem(a.c.Post("/agents/register", map[string]any{"name": "X", "mode": "delegated", "auth": "client_secret", "organization_id": repository.NewID()}, contracttest.Bearer(session)), 403, "forbidden", "", "another organization")
	a.agentsProblem(a.c.Post("/agents/register", map[string]any{"name": "X", "mode": "autonomous", "auth": "delegated_token"}, contracttest.Bearer(session)), 422, "invalid_input", "", "an autonomous agent needs a credential")

	a.equal(column(a.list(a.c.Get("/agents", contracttest.Bearer(session))), "id"), []any{own["id"], org["id"]}, "listed")
	a.equal(at(a.data(a.c.Get("/agents/"+str(own["id"]), contracttest.Bearer(session)))["grants"], 0)["capability"], "members.list", "show")
	a.agentsProblem(a.c.Get("/agents/"+repository.NewID(), contracttest.Bearer(session)), 404, "not_found", "", "unknown agent")

	host := a.data(a.c.Post("/agents/hosts", map[string]any{"name": "Laptop", "default_capabilities": []any{"members.list"}}, contracttest.Bearer(session)))
	if !strings.HasPrefix(str(host["enrollment_token"]), "peh_") {
		a.t.Errorf("enrolment token %v", host["enrollment_token"])
	}
	a.equal(column(a.list(a.c.Get("/agents/hosts", contracttest.Bearer(session))), "id"), []any{host["id"]}, "hosts")
	enrolKey := newKey("EdDSA")
	token := str(host["enrollment_token"])
	enrolled := a.data(a.bearer(token, "POST", "/agents/enroll", map[string]any{"name": "Claude Code", "mode": "delegated", "auth": "private_key_jwt", "jwk": enrolKey.jwk()}))
	a.equal([]any{enrolled["host_id"], enrolled["owner_type"], enrolled["owner_id"], enrolled["organization_id"], at(enrolled["grants"], 0)["status"], obj(enrolled["public_jwk"])["alg"]},
		[]any{host["id"], "user", userID, orgID, "active", "EdDSA"}, "enrolled")
	a.agentsProblem(a.bearer("peh_"+strings.Repeat("x", 43), "POST", "/agents/enroll", map[string]any{"name": "X", "mode": "delegated", "auth": "client_secret"}), 401, "unauthorized", "", "unknown token")
	a.agentsProblem(a.bearer(token, "POST", "/agents/enroll", map[string]any{"name": "", "mode": "delegated", "auth": "client_secret"}), 422, "invalid_input", "", "no name")

	id := str(enrolled["id"])
	me := a.data(a.signed(enrolKey, id, "GET", "/agents/session", nil, nil))
	a.equal([]any{obj(me["agent"])["id"], me["mode"], me["owner"], obj(me["host"])["name"], me["authenticated_via"], at(me["grants"], 0)["capability"]},
		[]any{id, "delegated", map[string]any{"type": "user", "id": userID}, "Laptop", "jwt", "members.list"}, "session")
	a.equal(a.data(a.c.Delete("/agents/hosts/"+str(host["id"]), contracttest.Bearer(session)))["status"], "revoked", "host revoked")
	a.agentsProblem(a.bearer(token, "POST", "/agents/enroll", map[string]any{"name": "X", "mode": "delegated", "auth": "client_secret"}), 401, "unauthorized", "", "a revoked host")

	a.equal(a.data(a.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(session)))["status"], "suspended", "suspend")
	a.agentsProblem(a.signed(enrolKey, id, "GET", "/agents/session", nil, nil), 401, "agent_inactive", "agent_suspended", "suspended")
	a.agentsProblem(a.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(session)), 409, "conflict", "", "suspended twice")
	a.equal(a.data(a.c.Post("/agents/"+id+"/resume", nil, contracttest.Bearer(session)))["status"], "active", "resume")
	a.status(a.signed(enrolKey, id, "GET", "/agents/session", nil, nil), 200, "resumed")

	discovery := a.json(a.c.Get("/.well-known/agent-configuration"))
	a.equal([]any{discovery["version"], discovery["provider_name"], discovery["default_location"], discovery["token_endpoint"]},
		[]any{"1.0-draft", "Polaris test", base + "/agents/execute", base + "/oauth2/token"}, "discovery")
	if cc := a.c.Get("/.well-known/agent-configuration").Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=3600") {
		a.t.Errorf("cache-control %q", cc)
	}
	caps := obj(a.data(a.signed(enrolKey, id, "GET", "/agents/capabilities", nil, nil)))["capabilities"]
	statuses := map[string]any{}
	for _, c := range caps.([]any) {
		statuses[str(obj(c)["name"])] = obj(c)["grant_status"]
	}
	a.equal(statuses, map[string]any{"members.list": "active", "org.rename": "none", "audit.export": "none", "credits.spend": "none", "invite": "none"}, "grant statuses")
	a.equal(at(caps, 4)["location"], location, "location")
	if _, has := at(a.data(a.c.Get("/agents/capabilities"))["capabilities"], 0)["grant_status"]; has {
		a.t.Error("anonymous capabilities carry no grant status")
	}

	actors := map[string]string{}
	for _, e := range a.audited(agents.EventRegistered, agents.EventEnrolled, agents.EventSuspended, agents.EventResumed) {
		actors[e.Name] = e.ActorType
	}
	a.equal(actors, map[string]string{"agent.enrolled": "agent", "agent.registered": "user", "agent.resumed": "user", "agent.suspended": "user"}, "actors")
}

func grantsByEachMethod(a *agentsCase) {
	userID, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(session, map[string]any{"name": "Reviewer", "auth": "private_key_jwt", "jwk": key.jwk()})
	id := str(agent["id"])

	asked := a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{"org.rename", "members.list"}, "preferred_method": "device_authorization", "reason": "Rename on request"}, nil))
	a.equal(asked["agent_id"], id, "agent id")
	byName := map[string]map[string]any{}
	for _, g := range asked["agent_capability_grants"].([]any) {
		byName[str(obj(g)["capability"])] = obj(g)
	}
	a.equal([]any{byName["org.rename"]["status"], byName["members.list"]["status"]}, []any{"pending", "active"}, "high waits, low by policy")
	ap := obj(asked["approval"])
	code := str(ap["user_code"])
	a.equal([]any{ap["method"], ap["strength"], ap["verification_uri"], ap["verification_uri_complete"], ap["expires_in"], ap["interval"]},
		[]any{"device_authorization", "step_up", approveURL, approveURL + "?user_code=" + code, 600, 5}, "approval")
	if !regexp.MustCompile(`^[BCDFGHJKMNPQRSTVWXZ]{4}-[BCDFGHJKMNPQRSTVWXZ]{4}$`).MatchString(code) {
		a.t.Errorf("user code %q", code)
	}
	a.agentsProblem(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{"nope"}}, nil), 404, "capability_not_found", "", "unknown")
	a.agentsProblem(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{map[string]any{"name": "audit.export", "constraints": map[string]any{"format": map[string]any{"between": []any{1, 2}}}}}}, nil), 400, "unknown_constraint_operator", "", "operator")
	shown := a.data(a.c.Get("/agents/approvals/code?user_code="+strings.ToLower(code), contracttest.Bearer(session)))
	a.equal([]any{obj(shown["agent"])["id"], at(shown["grants"], 0)["capability"], shown["strength"]}, []any{id, "org.rename", "step_up"}, "device page")
	a.agentsProblem(a.c.Get("/agents/approvals/code?user_code=ZZZZ-ZZZZ", contracttest.Bearer(session)), 404, "not_found", "", "no code")
	decided := a.data(a.c.Post("/agents/approvals/"+str(ap["id"])+"/decide", map[string]any{"decision": "approve", "constraints": map[string]any{"name": map[string]any{"pattern": "Acme.*"}}}, contracttest.Bearer(session)))
	g := at(decided["grants"], 0)
	a.equal([]any{decided["status"], g["status"], g["approved_via"], g["constraints"]}, []any{"approved", "active", "device_authorization", map[string]any{"name": map[string]any{"pattern": "Acme.*"}}}, "decided")
	a.agentsProblem(a.c.Post("/agents/approvals/"+str(ap["id"])+"/decide", map[string]any{"decision": "approve"}, contracttest.Bearer(session)), 409, "conflict", "", "decided once")

	ciba := a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{map[string]any{"name": "credits.spend", "constraints": map[string]any{"amount": map[string]any{"max": 50}, "budget": map[string]any{"amount": 100, "field": "amount"}}}}, "preferred_method": "ciba", "binding_message": "Spend credits?"}, nil))
	cibaAp := obj(ciba["approval"])
	a.equal([]any{cibaAp["method"], cibaAp["binding_message"], cibaAp["strength"]}, []any{"ciba", "Spend credits?", "session"}, "ciba")
	var pushed []agents.Event
	for _, e := range a.srv.Events.All() {
		if ae, ok := e.(agents.Event); ok && ae.Name == agents.EventGrantRequested && ae.Data["method"] == "ciba" {
			pushed = append(pushed, ae)
		}
	}
	if len(pushed) == 0 {
		a.t.Fatal("no ciba event")
	}
	a.equal([]any{pushed[0].Data["binding_message"], pushed[0].AgentID, pushed[0].ActorType, pushed[0].SubjectID}, []any{"Spend credits?", id, "agent", userID}, "ciba event")
	a.equal(at(a.data(a.c.Post("/agents/approvals/"+str(cibaAp["id"])+"/decide", map[string]any{"decision": "approve"}, contracttest.Bearer(session)))["grants"], 0)["status"], "active", "ciba approved")

	inApp := a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{"audit.export"}, "preferred_method": "in_app"}, nil))
	pending := a.list(a.c.Get("/agents/approvals", contracttest.Bearer(session)))
	a.equal([]any{at(pending, 0)["id"], at(at(pending, 0)["grants"], 0)["capability"], at(pending, 0)["method"]}, []any{obj(inApp["approval"])["id"], "audit.export", "in_app"}, "in app list")
	inAppID := str(obj(inApp["approval"])["id"])
	a.equal(at(a.data(a.c.Post("/agents/approvals/"+inAppID+"/decide", map[string]any{"decision": "deny"}, contracttest.Bearer(session)))["grants"], 0)["status"], "denied", "denied")
	a.equal(len(a.list(a.c.Get("/agents/approvals", contracttest.Bearer(session)))), 0, "none pending")
	a.agentsProblem(a.c.Post("/agents/approvals/"+inAppID+"/decide", map[string]any{"decision": "maybe"}, contracttest.Bearer(session)), 422, "invalid_input", "", "maybe")

	grants := a.data(a.signed(key, id, "GET", "/agents/session", nil, nil))["grants"]
	st := map[string]any{}
	for _, g := range grants.([]any) {
		st[str(obj(g)["capability"])] = obj(g)["status"]
	}
	a.equal(st, map[string]any{"org.rename": "active", "members.list": "active", "credits.spend": "active", "audit.export": "denied"}, "session grants")
	membersGrant := str(byName["members.list"]["id"])
	a.equal(a.data(a.c.Delete("/agents/grants/"+membersGrant, contracttest.Bearer(session)))["status"], "revoked", "revoked")
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": []any{}}, nil), 403, "capability_not_granted", "", "revoked grant")
	a.agentsProblem(a.c.Delete("/agents/grants/"+membersGrant, contracttest.Bearer(session)), 409, "conflict", "", "revoked twice")

	var how []string
	for _, e := range a.audited(agents.EventGrantApproved, agents.EventGrantDenied, agents.EventGrantRevoked) {
		h, _ := e.Data["how"].(string)
		if h == "" {
			h = "-"
		}
		how = append(how, e.Name+":"+h+":"+e.ActorType)
	}
	slices.Sort(how)
	want := []string{"agent.grant.revoked:-:user", "agent.grant.denied:in_app:user", "agent.grant.approved:ciba:user", "agent.grant.approved:device_authorization:user", "agent.grant.approved:auto:system"}
	slices.Sort(want)
	a.equal(how, want, "audit")
}

func executionBudgetsReceiptsKillSwitch(a *agentsCase) {
	userID, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(session, map[string]any{"name": "Spender", "auth": "private_key_jwt", "jwk": key.jwk(), "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	exec := func(capability string, args any, extra map[string]any) map[string]any {
		return map[string]any{"capability": capability, "arguments": args}
	}
	asked := a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{map[string]any{"name": "credits.spend", "constraints": map[string]any{"amount": map[string]any{"max": 50}, "budget": map[string]any{"amount": 100, "field": "amount"}}}}, "preferred_method": "in_app"}, nil))
	a.c.Post("/agents/approvals/"+str(obj(asked["approval"])["id"])+"/decide", map[string]any{"decision": "approve"}, contracttest.Bearer(session))

	first := a.json(a.signed(key, id, "POST", "/agents/execute", exec("members.list", []any{}, nil), nil))
	a.equal([]any{first["data"], obj(first["receipt"])["seq"]}, []any{map[string]any{"members": 1, "agent": id}, 1}, "first")
	a.equal(obj(a.json(a.signed(key, id, "POST", "/agents/execute", map[string]any{"capability": "members.list", "input": []any{}}, nil))["receipt"])["seq"], 2, "input alias")
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("members.list", map[string]any{"extra": 1}, nil), nil), 422, "invalid_arguments", "", "schema")
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("org.rename", map[string]any{"name": "X"}, nil), nil), 403, "capability_not_granted", "", "not granted")
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("members.list", []any{}, nil), map[string]any{"capabilities": []any{"credits.spend"}}), 403, "capability_not_granted", "", "the JWT restricts")
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("nope", []any{}, nil), nil), 404, "capability_not_found", "", "unknown")

	violated := a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("credits.spend", map[string]any{"amount": 60}, nil), nil), 403, "constraint_violated", "", "max")
	a.equal(violated["violations"], []any{map[string]any{"field": "amount", "constraint": "max", "actual": 60}}, "violations")
	a.equal(a.json(a.signed(key, id, "POST", "/agents/execute", exec("credits.spend", map[string]any{"amount": 40}, nil), nil))["data"], map[string]any{"spent": 40}, "spent 40")
	a.signed(key, id, "POST", "/agents/execute", exec("credits.spend", map[string]any{"amount": 40}, nil), nil)
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("credits.spend", map[string]any{"amount": 40}, nil), nil), 403, "budget_exhausted", "", "20 left")
	a.equal(a.json(a.signed(key, id, "POST", "/agents/execute", exec("credits.spend", map[string]any{"amount": 20}, nil), nil))["data"], map[string]any{"spent": 20}, "spent 20")
	for _, g := range a.data(a.signed(key, id, "GET", "/agents/session", nil, nil))["grants"].([]any) {
		if obj(g)["capability"] == "credits.spend" {
			a.equal([]any{obj(g)["status"], obj(obj(g)["budget"])["remaining"]}, []any{"exhausted", 0}, "exhausted")
		}
	}
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("credits.spend", map[string]any{"amount": 1}, nil), nil), 403, "budget_exhausted", "", "an exhausted grant reports its budget")

	chain := a.list(a.c.Get("/agents/"+id+"/receipts", contracttest.Bearer(session)))
	a.equal(column(chain, "seq"), []any{1, 2, 3, 4, 5}, "chain")
	a.equal([]any{at(chain, 0)["prev_hash"], at(chain, 1)["prev_hash"], at(chain, 2)["prev_hash"]}, []any{nil, at(chain, 0)["hash"], at(chain, 1)["hash"]}, "links")
	a.equal([]any{at(chain, 2)["budget_before"], at(chain, 2)["budget_after"], at(chain, 3)["budget_after"], at(chain, 4)["budget_after"]}, []any{100, 60, 20, 0}, "budgets")
	for _, r := range chain {
		a.equal(a.data(a.c.Get("/agents/receipts/"+str(obj(r)["id"])+"/verify", contracttest.Bearer(session)))["valid"], true, "receipt valid")
	}
	db := a.srv.Graph().DB()
	if n, err := db.Update(a.ctx, agents.TableReceipts, store.Criteria{"id": at(chain, 2)["id"]}, store.Data{"budget_after": 99}); err != nil || n != 1 {
		a.t.Fatalf("tamper: %d %v", n, err)
	}
	tampered := a.data(a.c.Get("/agents/receipts/"+str(at(chain, 2)["id"])+"/verify", contracttest.Bearer(session)))
	a.equal([]any{tampered["valid"], tampered["checks"]}, []any{false, map[string]any{"hash": false, "signature": false, "chain": true}}, "tampered")
	a.equal(a.data(a.c.Get("/agents/receipts/"+str(at(chain, 3)["id"])+"/verify", contracttest.Bearer(session)))["checks"], map[string]any{"hash": true, "signature": true, "chain": false}, "next no longer links")
	_, _ = db.Update(a.ctx, agents.TableReceipts, store.Criteria{"id": at(chain, 2)["id"]}, store.Data{"budget_after": 60})
	page := a.json(a.c.Get("/agents/"+id+"/receipts?after=2&limit=2", contracttest.Bearer(session)))
	a.equal([]any{column(page["data"], "seq"), page["next_cursor"], page["has_more"]}, []any{[]any{3, 4}, 4, true}, "page")

	a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{"audit.export"}, "preferred_method": "in_app"}, nil)
	revoked := a.data(a.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(session)))
	sealed := obj(revoked["sealed_receipt"])
	a.equal([]any{revoked["status"], sealed["outcome"], sealed["seq"], sealed["capability"], sealed["prev_hash"]}, []any{"revoked", "sealed", 6, nil, at(chain, 4)["hash"]}, "sealed")
	if revoked["sealed_at"] == nil {
		a.t.Error("sealed_at")
	}
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", exec("members.list", []any{}, nil), nil), 401, "agent_inactive", "agent_revoked", "revoked")
	a.agentsProblem(a.c.Post("/agents/"+id+"/resume", nil, contracttest.Bearer(session)), 409, "conflict", "", "revoked for good")
	a.agentsProblem(a.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(session)), 409, "conflict", "", "revoked twice")
	a.equal(len(a.list(a.c.Get("/agents/approvals", contracttest.Bearer(session)))), 0, "approvals cancelled")
	after := a.data(a.c.Get("/agents/"+id, contracttest.Bearer(session)))
	a.equal(column(after["grants"], "status"), []any{"revoked", "exhausted", "revoked"}, "grants ended")
	a.equal(len(a.list(a.c.Get("/agents/"+id+"/receipts", contracttest.Bearer(session)))), 6, "six receipts")
	a.equal(a.data(a.c.Get("/agents/receipts/"+str(sealed["id"])+"/verify", contracttest.Bearer(session)))["valid"], true, "seal verifies")

	a.grantOwner(userID)
	other := a.registerAgent(session, map[string]any{"name": "Other"})
	a.equal(column(a.list(a.c.Get("/admin/agents", contracttest.Bearer(session))), "id"), []any{id, other["id"]}, "operators see every agent")
	a.equal(a.data(a.c.Post("/admin/agents/"+str(other["id"])+"/revoke", nil, contracttest.Bearer(session)))["status"], "revoked", "operator revoke")
	a.status(a.c.Post("/admin/agents/"+str(other["id"])+"/revoke", nil, contracttest.Bearer(session)), 409, "operator revoke twice")

	counts := map[string]int{}
	for _, e := range a.audited(agents.EventExecuted, agents.EventExecutionDenied, agents.EventGrantExhausted, agents.EventRevoked, agents.EventReceiptSealed) {
		counts[e.Name]++
		want := "agent"
		switch e.Name {
		case agents.EventRevoked:
			want = "user"
		case agents.EventReceiptSealed:
			want = "system"
		}
		a.equal(e.ActorType, want, e.Name)
	}
	a.equal(counts, map[string]int{"agent.executed": 5, "agent.execution_denied": 7, "agent.grant.exhausted": 1, "agent.receipt.sealed": 2, "agent.revoked": 2}, "events")
}
