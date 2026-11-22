package agents_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// The recorded token flows: delegated agents through token exchange, autonomous agents through
// client credentials, and a location capability reached only through the request middleware.
func TestAgentTokens(t *testing.T) {
	run(t, tokensFixtures, map[string]func(*agentsCase){
		"testADelegatedAgentActsForTheUserThroughTokenExchange":           delegatedAgent,
		"testAnAutonomousAgentActsAsItsOwnerWithinItsGrants":              autonomousAgent,
		"testALocationCapabilityIsReachedOnlyThroughTheRequestMiddleware": locationCapability,
	})
}

func delegatedAgent(a *agentsCase) {
	userID, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(session, map[string]any{"name": "Reviewer", "auth": "private_key_jwt", "jwk": key.jwk(), "organization_id": orgID, "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	exchange := func(extra map[string]string) *http.Response {
		f := map[string]string{"client_assertion_type": oauth.AssertionType, "client_assertion": key.assertion(id, base+"/oauth2/token"),
			"grant_type": oauth.GrantTokenExchange, "subject_token": session, "subject_token_type": exchangeType}
		for k, v := range extra {
			f[k] = v
		}
		return a.form("/oauth2/token", f)
	}

	exchanged := a.json(exchange(map[string]string{"scope": "members.read"}))
	tok := str(exchanged["access_token"])
	c := claims(tok)
	a.equal([]any{c["sub"], c["org"], c["client_id"], c["act"]}, []any{userID, orgID, id, map[string]any{"sub": id, "client_id": id}}, "exchanged claims")
	a.problem(exchange(map[string]string{"scope": "org.update"}), 400, "invalid_scope", "beyond the grants")
	a.problem(a.form("/oauth2/token", map[string]string{"client_assertion_type": oauth.AssertionType, "client_assertion": key.assertion(id, base+"/oauth2/token"), "grant_type": "client_credentials"}), 400, "unauthorized_client", "a delegated agent cannot act as itself")

	a.status(a.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(tok)), 200, "members.read")
	a.status(a.c.Get("/orgs/"+orgID+"/roles", contracttest.Bearer(tok)), 403, "roles.read was not granted")
	a.equal(a.data(a.c.Get("/auth/me", contracttest.Bearer(tok)))["id"], userID, "me is Ada")
	executed := a.json(a.bearer(tok, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": []any{}}))
	a.equal(executed["data"], map[string]any{"members": 1, "agent": id}, "executed")
	a.equal(a.data(a.bearer(tok, "GET", "/agents/session", nil))["authenticated_via"], "oauth", "via")
	a.equal(a.data(a.bearer(tok, "GET", "/agents/receipts/"+str(obj(executed["receipt"])["id"])+"/verify", nil))["valid"], true, "the agent verifies its own receipt")
	a.agentsProblem(a.bearer(tok, "POST", "/agents/execute", map[string]any{"capability": "org.rename", "arguments": map[string]any{"name": "X"}}), 403, "capability_not_granted", "", "org.rename")
	a.agentsProblem(a.bearer("not-a-token", "POST", "/agents/execute", map[string]any{"capability": "members.list"}), 401, "invalid_jwt", "", "not a token")
	a.agentsProblem(a.c.Do(a.c.NewRequest("POST", base+"/agents/execute", []byte(`{"capability":"members.list"}`))), 401, "unauthorized", "", "no credential")

	events := a.audited(agents.EventExecuted)
	if len(events) != 1 {
		a.t.Fatalf("executed events: %d", len(events))
	}
	a.equal([]any{events[0].ActorType, events[0].ActorID, events[0].SubjectID, events[0].OrganizationID, events[0].Data["capability"]}, []any{"agent", id, userID, orgID, "members.list"}, "audit")

	grantID := str(at(a.data(a.c.Get("/agents/"+id, contracttest.Bearer(session)))["grants"], 0)["id"])
	a.c.Delete("/agents/grants/"+grantID, contracttest.Bearer(session))
	a.status(a.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(tok)), 403, "a revoked grant takes effect at once")
	a.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(session))
	a.status(a.c.Get("/auth/me", contracttest.Bearer(tok)), 401, "the token was revoked with the agent")
	a.problem(exchange(nil), 401, "invalid_client", "the client is disabled")
}

func autonomousAgent(a *agentsCase) {
	userID, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	agent := a.registerAgent(session, map[string]any{"name": "Deploy bot", "mode": "autonomous", "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	auth := basic(id, str(agent["client_secret"]))

	own := a.json(a.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": "members.read"}, auth))
	tok := str(own["access_token"])
	a.equal(claims(tok)["sub"], id, "sub is the agent")
	a.problem(a.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": "org.update"}, auth), 400, "invalid_scope", "the client scopes follow the grants")

	a.equal(a.data(a.c.Get("/auth/me", contracttest.Bearer(tok)))["id"], userID, "acts as Ada")
	a.status(a.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(tok)), 200, "members")
	a.status(a.c.Get("/orgs/"+orgID+"/roles", contracttest.Bearer(tok)), 403, "roles")
	a.status(a.c.Post("/orgs", map[string]any{"name": "Evil"}, contracttest.Bearer(tok)), 403, "a permissionless write")
	a.status(a.c.Post("/agents/register", map[string]any{"name": "Child", "mode": "delegated", "auth": "client_secret"}, contracttest.Bearer(tok)), 403, "an agent never registers an agent")
	executed := a.json(a.bearer(tok, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": []any{}}))
	a.equal(obj(executed["receipt"])["seq"], 1, "seq")

	a.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(session))
	a.agentsProblem(a.c.Get("/auth/me", contracttest.Bearer(tok)), 401, "agent_inactive", "agent_suspended", "suspended")
	a.c.Post("/agents/"+id+"/resume", nil, contracttest.Bearer(session))
	a.status(a.c.Get("/auth/me", contracttest.Bearer(tok)), 200, "resumed")
	a.c.Delete("/agents/grants/"+str(at(agent["grants"], 0)["id"]), contracttest.Bearer(session))
	a.status(a.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(tok)), 403, "revoked grant")
	a.agentsProblem(a.bearer(tok, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": []any{}}), 403, "capability_not_granted", "", "revoked grant")

	events := a.audited(agents.EventExecuted)
	a.equal([]any{events[0].ActorType, events[0].ActorID, events[0].SubjectID}, []any{"agent", id, userID}, "audit")
}

// hostHandler is a host route behind the request middleware.
type hostHandler struct{ seen []agents.Call }

func (h *hostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	call, _ := agents.CallFrom(r.Context())
	h.seen = append(h.seen, call)
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	status := http.StatusOK
	if body["email"] == "fail@acme.test" {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"invited": body["email"]})
}

// callHost sends a JSON POST to url through mw.
func callHost(mw http.Handler, url, jwt string, body map[string]any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		r.Header.Set("Authorization", "Bearer "+jwt)
	}
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, r)
	return w
}

func problemOf(w *httptest.ResponseRecorder) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func locationCapability(a *agentsCase) {
	_, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(session, map[string]any{"name": "Inviter", "auth": "private_key_jwt", "jwk": key.jwk()})
	id := str(agent["id"])
	asked := a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{map[string]any{"name": "invite",
		"constraints": map[string]any{"email": map[string]any{"pattern": `.*@acme\.test`}, "budget": map[string]any{"count": 2}}}}, "preferred_method": "in_app"}, nil))
	a.c.Post("/agents/approvals/"+str(obj(asked["approval"])["id"])+"/decide", map[string]any{"decision": "approve"}, contracttest.Bearer(session))
	a.agentsProblem(a.signed(key, id, "POST", "/agents/execute", map[string]any{"capability": "invite", "arguments": map[string]any{"email": "bob@acme.test"}}, nil), 403, "capability_not_granted", "", "a location capability does not run here")

	h := &hostHandler{}
	mw := a.plugin.Guard(h)
	bob := map[string]any{"email": "bob@acme.test"}
	a.equal(callHost(mw, location, "", bob).Code, 401, "no credential")
	a.equal(problemOf(callHost(mw, location, "", bob))["type"], "https://polaris.univeros.io/problems/agents/unauthorized", "type")
	a.equal(problemOf(callHost(mw, location, key.requestJWT(id, base+"/agents/execute", nil, nil), bob))["error"], "aud_mismatch", "a JWT for another aud")
	a.equal(problemOf(callHost(mw, location, key.requestJWT(id, location, map[string]any{"capabilities": []any{"invite", "members.list"}}, nil), bob))["error"], "aud_mismatch", "several capabilities at a location")
	a.equal(problemOf(callHost(mw, location, key.requestJWT(id, location, nil, nil), map[string]any{"email": "bob@evil.test"}))["error"], "constraint_violated", "constraint")
	a.equal(problemOf(callHost(mw, location, newKey("ES256").requestJWT(id, location, nil, nil), bob))["error"], "invalid_jwt", "another key")
	a.equal(len(h.seen), 0, "the handler never ran")

	ok := callHost(mw, location, key.requestJWT(id, location, nil, nil), bob)
	a.equal([]any{ok.Code, problemOf(ok)}, []any{200, map[string]any{"invited": "bob@acme.test"}}, "ok")
	a.equal([]any{h.seen[0].Grant.Capability, *h.seen[0].Grant.BudgetRemaining}, []any{"invite", 1}, "the handler sees the grant")
	row, _ := a.srv.Graph().DB().FindOne(a.ctx, agents.TableReceipts, store.Criteria{"id": ok.Header().Get(agents.ReceiptHeader)})
	a.equal([]any{row.String("capability"), row.String("outcome"), row.Int("budget_before"), row.Int("budget_after")}, []any{"invite", "success", 2, 1}, "receipt")

	failed := callHost(mw, location, key.requestJWT(id, location, nil, nil), map[string]any{"email": "fail@acme.test"})
	a.equal(failed.Code, 500, "failed")
	row, _ = a.srv.Graph().DB().FindOne(a.ctx, agents.TableReceipts, store.Criteria{"id": failed.Header().Get(agents.ReceiptHeader)})
	a.equal(row.String("outcome"), "failed", "the outcome follows the status")
	a.equal(problemOf(callHost(mw, location, key.requestJWT(id, location, nil, nil), bob))["error"], "budget_exhausted", "the budget of two is spent")
	a.equal(callHost(mw, "https://host.polaris.test/other", "", map[string]any{}).Code, 200, "other URLs pass through")
	n, _ := a.srv.Graph().DB().Count(a.ctx, agents.TableReceipts, store.Criteria{"agent_id": id})
	a.equal([]any{n, len(h.seen)}, []any{2, 3}, "two receipts; the pass-through reached the handler too")
	var capsSeen []any
	for _, e := range a.audited(agents.EventExecuted, agents.EventExecutionDenied) {
		capsSeen = append(capsSeen, e.Data["capability"])
	}
	a.equal(capsSeen, []any{"invite", "invite", "invite", "invite", "invite"}, "audited")
}
