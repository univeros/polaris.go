package agents_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/store"
)

// resourceServer is a client an operator registered, trusted or not, and what it introspects with.
func (u *unknownCase) resourceServer(trusted bool) func(raw any) *http.Response {
	u.t.Helper()
	u.grantOwner(u.userID)
	made := u.c.Post("/admin/oauth/clients", map[string]any{"name": "Resource server", "grant_types": []string{"client_credentials"}, "token_endpoint_auth_method": "client_secret_post", "trusted": trusted},
		contracttest.Bearer(u.session))
	client := u.data(made)
	if client["client_secret"] == nil {
		u.t.Fatalf("client: %d %v", made.StatusCode, client)
	}
	return func(raw any) *http.Response {
		return u.c.Post("/agent/introspect", map[string]any{"token": raw, "client_id": client["client_id"], "client_secret": client["client_secret"]})
	}
}

func (u *unknownCase) inactive(resp *http.Response, what string) {
	u.t.Helper()
	u.equal([]any{resp.StatusCode, u.json(resp)}, []any{200, map[string]any{"active": false}}, what)
}

// §5.12: what a resource server is told of an agent's JWT.
func TestSection5_12Introspection(t *testing.T) {
	u, host, key, id := limited(t, agents.RateLimits{})
	introspect := u.resourceServer(true)
	jwt := key.requestJWT(id, location, nil, nil)
	for range 2 { // it is not spent
		body := u.json(introspect(jwt))
		u.equal([]any{body["active"], body["agent_id"], body["user_id"], body["mode"], body["aud"], body["agent_capability_grants"]},
			[]any{true, id, u.userID, "delegated", location, []any{map[string]any{"capability": "members.list", "status": "active"}}}, "§5.12: active")
	}
	u.equal(len(u.rows(agents.TableAgents, store.Criteria{"id": id, "last_used_at": nil})), 0, "what it did there counts as use")
	u.equal(u.json(introspect(jwt))["host_id"], u.json(u.statusAs(host, id))["host_id"], "its host")
	u.equal(u.json(introspect(key.requestJWT(id, base, nil, nil)))["active"], true, "the issuer")
	u.equal(u.json(introspect(key.requestJWT(id, base+"/capability/execute", nil, nil)))["active"], true, "the execute route")
	u.equal(u.json(introspect(key.requestJWT(id, location, map[string]any{"capabilities": []any{"invite"}}, nil)))["agent_capability_grants"], []any{}, "§5.12: only those the JWT lists")
	u.equal(u.json(introspect(key.requestJWT(id, location, map[string]any{"iss": host.kid()}, nil)))["active"], true, "its host's iss")

	now := time.Now().Unix()
	for name, raw := range map[string]any{
		"another server's":  key.requestJWT(id, "https://other.example/x", nil, nil), // a JWT for one resource server is not another's
		"a location's path": key.requestJWT(id, location+"/", nil, nil), "no aud": key.requestJWT(id, location, map[string]any{"aud": nil}, nil), "a list of aud": key.requestJWT(id, location, map[string]any{"aud": []any{location}}, nil),
		"expired": key.requestJWT(id, location, map[string]any{"iat": now - 90, "exp": now - 31}, nil), "from the future": key.requestJWT(id, location, map[string]any{"iat": now + 40, "exp": now + 90}, nil),
		"another key": newKey("EdDSA").requestJWT(id, location, nil, nil), "nobody's": key.requestJWT("nobody", location, nil, nil), "another iss": key.requestJWT(id, location, map[string]any{"iss": key.kid()}, nil),
		"a host's JWT": host.hostJWT(nil, nil), "a session": u.session, "garbage": "x", "empty": "", "a number": 5, "no exp": key.requestJWT(id, location, map[string]any{"exp": nil}, nil), "too long": key.requestJWT(id, location, map[string]any{"iat": now, "exp": now + 301}, nil), "no iat": key.requestJWT(id, location, map[string]any{"iat": nil}, nil),
		"no jti":           key.requestJWT(id, location, map[string]any{"jti": ""}, nil),
		"a key of its own": key.requestJWT(id, location, nil, map[string]any{"jwk": key.jwk()}), "another alg": key.requestJWT(id, location, nil, map[string]any{"alg": "ES256"}),
	} {
		u.inactive(introspect(raw), name)
	}
	u.status(u.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(u.session)), 200, "suspend")
	u.inactive(introspect(jwt), "suspended")
	u.status(u.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(u.session)), 200, "revoke")
	u.inactive(introspect(jwt), "revoked")
}

// 5.4: a client an operator trusted, authenticated, and nobody else.
func TestSection5_12WhoIntrospects(t *testing.T) {
	u, host, key, id := limited(t, agents.RateLimits{Address: perMinute(8)}) // one spent: the registration
	jwt := key.requestJWT(id, location, nil, nil)
	untrusted, trusted := u.resourceServer(false), u.resourceServer(true)
	u.status(untrusted(jwt), 401, "a client nobody trusted")
	for name, resp := range map[string]*http.Response{
		"nobody": u.c.Post("/agent/introspect", map[string]any{"token": jwt}), "a session": u.c.Post("/agent/introspect", map[string]any{"token": jwt}, contracttest.Bearer(u.session)),
		"the agent": u.c.Post("/agent/introspect", map[string]any{"token": jwt}, contracttest.Bearer(key.requestJWT(id, base, nil, nil))),
		"its host":  u.c.Post("/agent/introspect", map[string]any{"token": jwt}, contracttest.Bearer(host.hostJWT(nil, nil))),
		"a secret":  u.c.Post("/agent/introspect", map[string]any{"token": jwt, "client_id": "x", "client_secret": "y"}),
	} {
		u.equal([]any{resp.StatusCode, u.json(resp)["error"]}, []any{401, "unauthorized"}, name)
	}
	for range 20 {
		u.status(trusted(jwt), 200, "a resource server asks as often as it is called")
	}
	u.status(u.c.Post("/agent/introspect", map[string]any{"token": jwt}), 401, "the last refusal")
	u.isLimited(u.c.Post("/agent/introspect", map[string]any{"token": jwt}), "who is refused is limited")
	u.status(trusted(jwt), 200, "a resource server is not")
}
