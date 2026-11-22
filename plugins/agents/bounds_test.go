package agents_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/store"
)

// On the plugin's own routes a request JWT's aud is compared with the configured base URL's
// origin, never with the request's Host header (decision 69): a JWT an agent signed for another
// server is not accepted because that server forwarded it with its own Host.
func TestARequestJWTForAnotherOriginIsRefusedWhateverTheHostHeader(t *testing.T) {
	srv, p := boot(t)
	a := &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p, ctx: context.Background()}
	_, ada := a.login("ada@example.com")
	_, ada = a.organization(ada, "Acme")
	key := newKey("ES256")
	id := str(a.registerAgent(ada, map[string]any{"name": "Lister", "auth": "private_key_jwt", "jwk": key.jwk()})["id"])

	call := func(target, aud string) *http.Response {
		raw, _ := json.Marshal(map[string]any{"capabilities": []any{map[string]any{"name": "members.list"}}})
		return a.c.Do(a.c.NewRequest("POST", target, raw, contracttest.Header("Content-Type", "application/json"),
			contracttest.Bearer(key.requestJWT(id, aud, nil, nil))))
	}
	const path = "/agents/grants/request"
	other := "https://relay.example" + path
	if resp := call(other, other); a.json(resp)["error"] != "aud_mismatch" {
		t.Errorf("a JWT for %s, forwarded with that Host: status %d, want aud_mismatch", other, resp.StatusCode)
	}
	// The configured origin is what counts: a proxy that hands over plain http or its own Host
	// changes nothing.
	if resp := call("http://10.0.0.7:8080"+path, base+path); resp.StatusCode >= 300 {
		t.Errorf("a JWT for the base URL behind a proxy: status %d %v", resp.StatusCode, a.json(resp))
	}
}

// An autonomous agent's own token carries the permissions of its live grants only while the user
// it acts as still holds them (decision 69): a service that reads the token's scope without the
// database sees what the host would allow.
func TestAnAgentsOwnTokenIsBoundedByItsOwnersAuthority(t *testing.T) {
	srv, p := boot(t)
	a := &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p, ctx: context.Background()}
	userID, ada := a.login("ada@example.com")
	_, ada = a.organization(ada, "Acme")
	agent := a.registerAgent(ada, map[string]any{"name": "Deploy bot", "mode": "autonomous", "capabilities": []any{"members.list"}})
	auth := basic(str(agent["id"]), str(agent["client_secret"]))
	scope := func() any {
		return a.json(a.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": "members.read"}, auth))["scope"]
	}
	a.equal(scope(), "members.read", "the grant's permission, held by the owner")
	if _, err := srv.DB.Update(a.ctx, "auth_memberships", store.Criteria{"user_id": userID}, store.Data{"status": "suspended"}); err != nil {
		t.Fatal(err)
	}
	a.equal(scope(), "", "the owner no longer holds it")
}
