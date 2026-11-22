package agents_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// The recorded security flows: the attacks of the plugin's security review, each refused.
func TestAgentsSecurity(t *testing.T) {
	run(t, securityFixtures, map[string]func(*agentsCase){
		"testAnotherUsersTokenNamingAnAgentIsRefusedEverywhere":                  confusedDeputy,
		"testAnAgentsClientIsNotManageableThroughTheOrganizationRoutes":          clientNotManageable,
		"testEverySpellingOfALocationIsGuardedAndABoundMiddlewareGuardsItsRoute": everySpelling,
		"testTheAskerCannotChooseItsAutoApprovalBudget":                          askerBudget,
	})
}

func (a *agentsCase) exchangeFor(clientID, subject string) *http.Response {
	return a.form("/oauth2/token", map[string]string{"client_id": clientID, "grant_type": oauth.GrantTokenExchange,
		"subject_token": subject, "subject_token_type": exchangeType, "scope": "members.read"})
}

func confusedDeputy(a *agentsCase) {
	adaID, ada := a.login("ada@example.com")
	orgID, ada := a.organization(ada, "Acme")
	agent := a.registerAgent(ada, map[string]any{"name": "Helper", "auth": "delegated_token", "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	bobID, bob := a.login("bob@example.com")

	minted := a.exchangeFor(id, bob)
	a.status(minted, 200, "the exchange is open to any session")
	tok := str(a.json(minted)["access_token"])
	a.equal([]any{claims(tok)["sub"], claims(tok)["client_id"]}, []any{bobID, id}, "Bob's token names the agent")
	a.agentsProblem(a.bearer(tok, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": map[string]any{}}), 401, "invalid_jwt", "", "execute")
	a.agentsProblem(a.bearer(tok, "GET", "/agents/session", nil), 401, "invalid_jwt", "", "the session")
	a.agentsProblem(a.c.Get("/auth/me", contracttest.Bearer(tok)), 401, "invalid_jwt", "", "a core route")
	a.agentsProblem(a.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(tok)), 401, "invalid_jwt", "", "a permissioned core route")
	n, _ := a.srv.Graph().DB().Count(a.ctx, agents.TableReceipts, store.Criteria{"agent_id": id})
	a.equal(n, 0, "nothing was chained for Ada")
	a.equal(len(a.audited(agents.EventExecuted)), 0, "no execution was audited")

	own := str(a.json(a.exchangeFor(id, ada))["access_token"])
	a.equal(obj(a.json(a.bearer(own, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": map[string]any{}}))["data"])["agent"], id, "Ada's own exchange")
	a.equal(a.data(a.c.Get("/auth/me", contracttest.Bearer(own)))["id"], adaID, "as Ada")
}

func clientNotManageable(a *agentsCase) {
	userID, ada := a.login("ada@example.com")
	orgID, ada := a.organization(ada, "Acme")
	agent := a.registerAgent(ada, map[string]any{"name": "Helper", "auth": "delegated_token", "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	orgAgent := a.registerAgent(ada, map[string]any{"name": "Org helper", "auth": "delegated_token", "organization_id": orgID})
	plugin := a.srv.Graph().Plugin(oauth.ID).(*oauth.Plugin)
	client, err := plugin.Client(a.ctx, id)
	if err != nil {
		a.t.Fatal(err)
	}
	orgClient, _ := plugin.Client(a.ctx, str(orgAgent["id"]))
	a.equal([]any{client.OrganizationID, orgClient.OrganizationID, orgAgent["organization_id"]}, []any{"", "", orgID}, "the plugin's clients belong to no organization")

	a.equal(len(a.list(a.c.Get("/orgs/"+orgID+"/oauth/clients", contracttest.Bearer(ada)))), 0, "not listed")
	attacker := newKey("ES256")
	jwk := attacker.jwk()
	jwk["kid"], jwk["alg"] = attacker.kid(), "ES256"
	rewrite := map[string]any{"type": "confidential", "token_endpoint_auth_method": "private_key_jwt", "jwks": map[string]any{"keys": []any{jwk}}, "grant_types": []any{"client_credentials"}}
	patched := a.c.Patch("/orgs/"+orgID+"/oauth/clients/"+client.ID, rewrite, contracttest.Bearer(ada))
	deleted := a.c.Delete("/orgs/"+orgID+"/oauth/clients/"+client.ID, contracttest.Bearer(ada))
	for _, resp := range []*http.Response{patched, deleted} {
		a.equal([]any{resp.StatusCode, a.json(resp)["type"]}, []any{404, "https://polaris.univeros.io/problems/oauth/not_found"}, "org routes")
	}
	client, _ = plugin.Client(a.ctx, id)
	a.equal([]any{client.Type, client.TokenEndpointAuthMethod, client.GrantTypes}, []any{"public", "none", []string{oauth.GrantTokenExchange}}, "unchanged")
	a.problem(a.form("/oauth2/token", map[string]string{"client_assertion_type": oauth.AssertionType, "client_assertion": attacker.assertion(id, base+"/oauth2/token"),
		"grant_type": "client_credentials", "scope": "members.read"}), 401, "invalid_client", "the attacker's key mints nothing")

	a.grantOwner(userID)
	if !slices.Contains(column(a.list(a.c.Get("/admin/oauth/clients", contracttest.Bearer(ada))), "client_id"), any(id)) {
		a.t.Error("operators see the agent's client")
	}
	tok := str(a.json(a.exchangeFor(id, ada))["access_token"])
	a.status(a.bearer(tok, "POST", "/agents/execute", map[string]any{"capability": "members.list", "arguments": map[string]any{}}), 200, "the agent works")
	a.equal(a.data(a.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(ada)))["status"], "revoked", "kill switch")
	client, _ = plugin.Client(a.ctx, id)
	if client.DisabledAt == nil {
		a.t.Error("the client is disabled")
	}
}

func everySpelling(a *agentsCase) {
	_, ada := a.login("ada@example.com")
	_, ada = a.organization(ada, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(ada, map[string]any{"name": "Inviter", "auth": "private_key_jwt", "jwk": key.jwk()})
	id := str(agent["id"])
	asked := a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{map[string]any{"name": "invite", "constraints": map[string]any{"budget": map[string]any{"count": 10}}}}, "preferred_method": "in_app"}, nil))
	a.c.Post("/agents/approvals/"+str(obj(asked["approval"])["id"])+"/decide", map[string]any{"decision": "approve"}, contracttest.Bearer(ada))
	h := &hostHandler{}
	bob := map[string]any{"email": "bob@acme.test"}

	global := a.plugin.Guard(h)
	for _, u := range []string{location, location + "/", "https://host.polaris.test//invite", "https://host.polaris.test/./invite", "https://host.polaris.test/x/../invite",
		"https://host.polaris.test:443/invite", "HTTPS://host.polaris.test/invite", "https://HOST.polaris.test/invite", "https://host.polaris.test/%69nvite", "http://host.polaris.test/invite"} {
		w := callHost(global, u, "", bob)
		a.equal([]any{w.Code, problemOf(w)["error"]}, []any{401, "agents_unauthorized"}, u)
	}
	a.equal(len(h.seen), 0, "no spelling reached the handler")
	a.equal(callHost(global, location+"/", key.requestJWT(id, location, nil, nil), bob).Code, 200, "the aud is compared normalised too")
	a.equal(problemOf(callHost(global, "http://host.polaris.test/invite", key.requestJWT(id, location, nil, nil), bob))["error"], "aud_mismatch", "a proxy's http is refused")
	a.equal(callHost(global, "https://host.polaris.test/other", "", bob).Code, 200, "another URL passes through")
	a.equal(len(h.seen), 2, "two reached the handler")

	bound := a.plugin.Protect("invite", h)
	route := "https://api.polaris.test/v2/invitations"
	w := callHost(bound, route, "", bob)
	a.equal([]any{w.Code, problemOf(w)["error"]}, []any{401, "agents_unauthorized"}, "bound, no credential")
	a.equal(problemOf(callHost(bound, route, key.requestJWT(id, location, nil, nil), bob))["error"], "aud_mismatch", "the aud is the URL called")
	ok := callHost(bound, route, key.requestJWT(id, route, nil, nil), bob)
	a.equal(ok.Code, 200, "bound ok")
	row, _ := a.srv.Graph().DB().FindOne(a.ctx, agents.TableReceipts, store.Criteria{"id": ok.Header().Get(agents.ReceiptHeader)})
	a.equal(row.String("capability"), "invite", "receipt")
	a.equal(len(h.seen), 3, "three calls")
}

func askerBudget(a *agentsCase) {
	_, ada := a.login("ada@example.com")
	_, ada = a.organization(ada, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(ada, map[string]any{"name": "Greedy", "auth": "private_key_jwt", "jwk": key.jwk(),
		"capabilities": []any{map[string]any{"name": "members.list", "constraints": map[string]any{"budget": map[string]any{"count": 1000000000}}}}})
	id := str(agent["id"])
	g := at(agent["grants"], 0)
	a.equal([]any{g["status"], obj(g["budget"])["total"], obj(agent["approval"])["method"]}, []any{"pending", 1000000000, "in_app"}, "wider than the policy: a person decides")
	a.equal(at(a.data(a.c.Post("/agents/approvals/"+str(obj(agent["approval"])["id"])+"/decide", map[string]any{"decision": "deny"}, contracttest.Bearer(ada)))["grants"], 0)["status"], "denied", "denied")
	ask := func(b map[string]any) map[string]any {
		return a.json(a.signed(key, id, "POST", "/agents/grants/request", map[string]any{"capabilities": []any{map[string]any{"name": "members.list", "constraints": map[string]any{"budget": b}}}, "preferred_method": "in_app"}, nil))
	}
	narrower := at(ask(map[string]any{"count": 10})["agent_capability_grants"], 0)
	a.equal([]any{narrower["status"], obj(narrower["budget"])["total"], narrower["approved_via"]}, []any{"active", 10, "auto"}, "within the ceiling")
	a.c.Delete("/agents/grants/"+str(narrower["id"]), contracttest.Bearer(ada))
	wider := ask(map[string]any{"count": 1000})
	wg := at(wider["agent_capability_grants"], 0)
	a.equal([]any{wg["status"], obj(wg["budget"])["total"], obj(wider["approval"])["method"]}, []any{"pending", 1000, "in_app"}, "wider waits")
	another := ask(map[string]any{"amount": 1, "field": "x"})
	a.equal([]any{at(another["agent_capability_grants"], 0)["id"], obj(another["approval"])["id"]}, []any{wg["id"], obj(wider["approval"])["id"]}, "asking again reuses the pending grant and its approval")
}
