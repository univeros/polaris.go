package agents_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/token"
)

// Every agents fixture has a Go test.
func TestEveryFixtureIsReplayed(t *testing.T) {
	var covered []string
	for class, tests := range map[string][]string{
		lifecycleFixtures: {"testRegisterAndEnrollAgentsAndHosts", "testGrantsAreApprovedByEachMethodOrByPolicy", "testExecutionBudgetsReceiptsAndTheKillSwitch"},
		tokensFixtures:    {"testADelegatedAgentActsForTheUserThroughTokenExchange", "testAnAutonomousAgentActsAsItsOwnerWithinItsGrants", "testALocationCapabilityIsReachedOnlyThroughTheRequestMiddleware"},
		securityFixtures: {"testAnotherUsersTokenNamingAnAgentIsRefusedEverywhere", "testAnAgentsClientIsNotManageableThroughTheOrganizationRoutes",
			"testEverySpellingOfALocationIsGuardedAndABoundMiddlewareGuardsItsRoute", "testTheAskerCannotChooseItsAutoApprovalBudget"},
		protocolFixtures: {"testThePolarisConfigurationIsServedAtItsOwnPath", "testCapabilitiesAreListedInPages", "testACapabilityIsDescribedByItsName",
			"testAPreRegisteredHostsAgentRegistersRequestsAndExecutes", "testARegistrationAPersonMustApproveIsPending", "testADeniedRegistrationIsRejected"},
	} {
		for _, test := range tests {
			covered = append(covered, class+"::"+test)
		}
	}
	missing, err := contracttest.Uncovered(contracttest.Fixtures(t, "agents"), covered)
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}

// Every capability with a handler the agent holds a live grant for is an MCP tool; a call is an
// execution with its receipt, and a refusal is the problem the route would answer.
func TestCapabilitiesAreMCPTools(t *testing.T) {
	srv, p := boot(t)
	c := contracttest.NewClient(t, srv.Handler(), nil)
	a := &agentsCase{t: t, srv: srv, c: c, plugin: p, ctx: context.Background()}
	_, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	agent := a.registerAgent(session, map[string]any{"name": "Helper", "auth": "delegated_token", "organization_id": orgID, "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	tok := str(a.json(a.exchangeFor(id, session))["access_token"])

	if tools, err := p.MCPTools(a.ctx, nil); err != nil || tools != nil {
		t.Error("no caller, no tools")
	}
	// The caller as Polaris's pipeline sees it: the agent principal of the exchanged token.
	var caller *token.Token
	var who polaris.Principal
	srv.Protect(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		caller, who = endpoint.Token(r.Context()), must(polaris.PrincipalFrom(r.Context()))
	})).ServeHTTP(httptest.NewRecorder(), authorized(tok))
	if caller == nil || caller.Claim(agents.ClaimAgentID) != id {
		t.Fatalf("agent principal %v", caller)
	}
	if who.Kind != polaris.KindAgent || who.AgentID != id || who.ClientID == "" || !who.Delegated || who.UserID == "" || who.OrganizationID != orgID {
		t.Fatalf("polaris.PrincipalFrom = %+v", who)
	}
	tools, err := p.MCPTools(a.ctx, caller)
	if err != nil || len(tools) != 1 || tools[0].Name != "agents.members.list" || tools[0].Destructive {
		t.Fatalf("tools %+v %v", tools, err)
	}
	res, err := tools[0].Call(a.ctx, map[string]any{})
	if err != nil || res.Status != 200 || obj(obj(res.Body)["receipt"])["seq"] != int64(1) {
		t.Errorf("call %+v %v", res, err)
	}
	if res, _ := tools[0].Call(a.ctx, map[string]any{"extra": true}); res.Status != 422 {
		t.Errorf("refusal %+v", res)
	}
	if tools, err := p.MCPTools(a.ctx, token.NewPrincipal(map[string]any{"sub": "x"})); err != nil || tools != nil {
		t.Error("not an agent")
	}
	a.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(session))
	if tools, err := p.MCPTools(a.ctx, caller); err != nil || tools != nil {
		t.Error("a suspended agent has no tools")
	}
}

func authorized(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, base+"/api", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

// A request JWT binds the request: htm, htu and body_hash over the bytes the pipeline received.
func TestARequestJWTBindsTheMethodURLAndBody(t *testing.T) {
	srv, p := boot(t)
	a := &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p, ctx: context.Background()}
	_, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	key := newKey("EdDSA")
	id := str(a.registerAgent(session, map[string]any{"name": "Bound", "auth": "private_key_jwt", "jwk": key.jwk(), "capabilities": []any{"members.list"}})["id"])
	raw := []byte(`{"capability":"members.list","arguments":{}}`)
	send := func(claims map[string]any) int {
		jwt := key.requestJWT(id, base+"/agents/execute", claims, nil)
		return a.c.Do(a.c.NewRequest("POST", base+"/agents/execute", raw, contracttest.Header("Content-Type", "application/json"), contracttest.Bearer(jwt))).StatusCode
	}
	if got := send(map[string]any{"htm": "POST", "htu": base + "/agents/execute", "body_hash": bodyHash(raw)}); got != 200 {
		t.Errorf("bound request: %d", got)
	}
	for name, claims := range map[string]map[string]any{
		"body":   {"body_hash": bodyHash([]byte("{}"))},
		"method": {"htm": "GET"},
		"url":    {"htu": base + "/agents/session"},
	} {
		if got := send(claims); got != 401 {
			t.Errorf("%s: %d", name, got)
		}
	}
	if _, ok := agents.CallFrom(context.Background()); ok {
		t.Error("no call outside a guarded route")
	}
}

func must[T any](v T, ok bool) T {
	if !ok {
		panic("not ok")
	}
	return v
}
