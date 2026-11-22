package agents_test

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/store"
)

// A grant with an end (expires_at) bounds the tokens issued under it (decision 75): the token a
// user delegates to the agent expires with the grant, and after it no token carries the
// permission, although nothing re-synced the client's scopes when the time passed.
func TestADelegatedTokenEndsWithTheGrantsWindow(t *testing.T) {
	srv, _ := boot(t)
	a := &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), ctx: context.Background()}
	_, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	agent := a.registerAgent(session, map[string]any{"name": "Helper", "auth": "delegated_token", "capabilities": []any{"members.list"}})
	id := str(agent["id"])
	window := func(end time.Time) {
		t.Helper()
		if _, err := srv.Graph().DB().Update(a.ctx, agents.TableGrants, store.Criteria{"agent_id": id}, store.Data{"expires_at": end}); err != nil {
			t.Fatal(err)
		}
	}

	whole := a.json(a.exchangeFor(id, session))
	a.equal([]any{whole["scope"], whole["expires_in"]}, []any{"members.read", 3600}, "a grant without an end")

	window(time.Now().Add(10 * time.Minute))
	windowed := a.json(a.exchangeFor(id, session))
	c := claims(str(windowed["access_token"]))
	exp, _ := c["exp"].(float64)
	if in, _ := windowed["expires_in"].(float64); windowed["scope"] != "members.read" || in < 590 || in > 600 || exp > float64(time.Now().Add(10*time.Minute).Unix()) {
		t.Errorf("the token must end with the grant (10 minutes): scope %v, expires_in %v, exp %v", windowed["scope"], windowed["expires_in"], c["exp"])
	}

	window(time.Now().Add(-time.Second))
	after := a.json(a.exchangeFor(id, session))
	a.equal([]any{after["scope"], after["expires_in"]}, []any{"", 3600}, "after the window no token carries the permission")
}
