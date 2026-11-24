package agents_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/agent"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// protocolFixtures is the recorded Agent Auth Protocol flows' file-name prefix. Section numbers in
// this file are the protocol's (https://agent-auth-protocol.com/specification, v1.0-draft).
const protocolFixtures = "Polaris.Agents.Tests.Functional.AgentAuthProtocolTest"

func TestAgentAuthProtocolFixtures(t *testing.T) {
	run(t, protocolFixtures, map[string]func(*agentsCase){
		"testThePolarisConfigurationIsServedAtItsOwnPath": func(a *agentsCase) {
			doc := a.c.Get("/agents/configuration")
			a.equal(doc.Header.Get("Cache-Control"), "public, max-age=3600", "cache")
			a.equal(a.json(doc)["token_endpoint"], base+"/oauth2/token", "the Polaris document")
		},
		"testCapabilitiesAreListedInPages":    listCapabilities,
		"testACapabilityIsDescribedByItsName": describeCapability,
	})
}

// listAgent registers an agent holding members.list and signs JWTs for the issuer (§4.3).
func listAgent(a *agentsCase) (key *agentKey, id, session string) {
	_, session = a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	key = newKey("EdDSA")
	agent := a.registerAgent(session, map[string]any{"name": "Reader", "auth": "private_key_jwt", "jwk": key.jwk(), "capabilities": []any{"members.list"}})
	return key, str(agent["id"]), session
}

func listCapabilities(a *agentsCase) {
	// §5.2, no auth: public capabilities, no 401, no grant status.
	anonymous := a.c.Get("/capability/list")
	a.equal(anonymous.Header.Get("Cache-Control"), "public, max-age=300", "§10.6: cache")
	all := a.json(anonymous)
	a.equal(column(all["capabilities"], "name"), []any{"members.list", "org.rename", "audit.export", "credits.spend", "invite"}, "names")
	a.equal([]any{all["has_more"], all["next_cursor"]}, []any{false, nil}, "one page")
	for _, item := range all["capabilities"].([]any) {
		c := obj(item)
		_, status := c["grant_status"]
		_, input := c["input"]
		if status || input || c["description"] == "" {
			a.t.Errorf("a list entry is a summary, without a grant status: %v", c)
		}
	}
	a.equal(at(all["capabilities"], 4)["location"], location, "the client executes at the location the list gives")

	// §5.2: pages, with an opaque cursor.
	first := a.json(a.c.Get("/capability/list?limit=2"))
	a.equal([]any{column(first["capabilities"], "name"), first["has_more"]}, []any{[]any{"members.list", "org.rename"}, true}, "first page")
	second := a.json(a.c.Get("/capability/list?limit=3&cursor=" + url.QueryEscape(str(first["next_cursor"]))))
	a.equal([]any{column(second["capabilities"], "name"), second["has_more"], second["next_cursor"]},
		[]any{[]any{"audit.export", "credits.spend", "invite"}, false, nil}, "last page")

	// §5.2: the server's own matching.
	found := a.json(a.c.Get("/capability/list?query=MEMBER+invite"))
	a.equal(column(found["capabilities"], "name"), []any{"invite"}, "every word, in the name or the description, in any case")
	page := a.json(a.c.Get("/capability/list?query=the&limit=1"))
	a.equal([]any{column(page["capabilities"], "name"), page["has_more"]}, []any{[]any{"members.list"}, true}, "a page of a search")
	rest := a.json(a.c.Get("/capability/list?query=the&limit=1&cursor=" + url.QueryEscape(str(page["next_cursor"]))))
	a.equal(column(rest["capabilities"], "name"), []any{"org.rename"}, "the next page of the search")
	a.equal(a.json(a.c.Get("/capability/list?query=nothing"))["capabilities"], []any{}, "no match is an empty list")

	// §5.13: invalid_request.
	for _, q := range []string{"limit=0", "limit=-1", "limit=two", "cursor=nonsense", "cursor=bm9uZQ"} {
		a.agentsProblem(a.c.Get("/capability/list?"+q), 400, "invalid_request", "invalid_request", q)
	}

	// §5.2, agent JWT: "granted" or "not_granted" on every returned capability.
	key, id, _ := listAgent(a)
	mine := a.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, nil, nil)))
	a.equal(mine.Header.Get("Cache-Control"), "no-store", "§10.6: an answer for one agent is not shared")
	a.equal(column(a.json(mine)["capabilities"], "grant_status"), []any{"granted", "not_granted", "not_granted", "not_granted", "not_granted"}, "grant statuses")
}

func describeCapability(a *agentsCase) {
	got := a.json(a.c.Get("/capability/describe?name=org.rename"))
	a.equal([]any{got["name"], got["description"], obj(got["input"])["required"], len(got)}, []any{"org.rename", "Rename the organization", []any{"name"}, 3}, "§5.2.1: the fields of §2.12")
	a.equal(a.json(a.c.Get("/capability/describe?name=invite"))["location"], location, "§2.12: location")

	// §5.2.1: an unknown name MUST be 404 capability_not_found.
	a.agentsProblem(a.c.Get("/capability/describe?name=nothing"), 404, "capability_not_found", "capability_not_found", "unknown")
	a.agentsProblem(a.c.Get("/capability/describe"), 400, "invalid_request", "invalid_request", "§5.13: no name")

	key, id, _ := listAgent(a)
	for _, c := range [][2]string{{"members.list", "granted"}, {"invite", "not_granted"}} {
		got := a.json(a.c.Get("/capability/describe?name="+c[0], contracttest.Bearer(key.requestJWT(id, base, nil, nil))))
		a.equal(got["grant_status"], c[1], "§5.2.1: "+c[0])
	}
}

// protocolCase is an agent without a fixture, for the rules below.
func protocolCase(t *testing.T) (a *agentsCase, key *agentKey, id, session string) {
	srv, p := boot(t)
	a = &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p}
	key, id, session = listAgent(a)
	return a, key, id, session
}

var capabilityRoutes = []string{"/capability/list", "/capability/describe?name=members.list"}

// §4.3, §8.18: on a non-execution route the aud of an agent JWT MUST be the issuer, and a server
// MUST reject any other, spelled differently included.
func TestSection4_3And8_18TheAudienceIsExactlyTheIssuer(t *testing.T) {
	a, key, id, _ := protocolCase(t)
	for _, route := range capabilityRoutes {
		path, _, _ := strings.Cut(route, "?")
		a.status(a.c.Get(route, contracttest.Bearer(key.requestJWT(id, base, nil, nil))), 200, route)
		for _, aud := range []any{base + path, base + "/", "HTTPS://auth.polaris.test", "https://other.test", "", []any{base}} {
			a.agentsProblem(a.c.Get(route, contracttest.Bearer(key.requestJWT(id, "", map[string]any{"aud": aud}, nil))), 401, "invalid_jwt", "invalid_jwt", route)
		}
	}
	// The Polaris routes keep their own rule.
	a.agentsProblem(a.signed(key, id, "GET", "/agents/session", nil, map[string]any{"aud": base}), 401, "aud_mismatch", "", "the issuer is not the URL called")
}

// §8.2: a JWT whose iat is more than 30 seconds in the future MUST NOT be accepted.
func TestSection8_2AJWTFromTheFutureIsRefused(t *testing.T) {
	a, key, id, _ := protocolCase(t)
	at := func(iat, exp time.Duration) string {
		now := time.Now()
		return key.requestJWT(id, base, map[string]any{"iat": now.Add(iat).Unix(), "exp": now.Add(exp).Unix()}, nil)
	}
	for _, route := range capabilityRoutes {
		a.status(a.c.Get(route, contracttest.Bearer(at(25*time.Second, 80*time.Second))), 200, "25 s ahead")
		a.agentsProblem(a.c.Get(route, contracttest.Bearer(at(35*time.Second, 80*time.Second))), 401, "invalid_jwt", "", "35 s ahead")
		a.agentsProblem(a.c.Get(route, contracttest.Bearer(at(-95*time.Second, -35*time.Second))), 401, "invalid_jwt", "", "expired 35 s ago")
	}
	if resp := a.signed(key, id, "GET", "/agents/session", nil, map[string]any{"iat": time.Now().Add(45 * time.Second).Unix(), "exp": time.Now().Add(90 * time.Second).Unix()}); resp.StatusCode != 200 {
		t.Errorf("the Polaris routes keep 60 s: %d", resp.StatusCode)
	}
}

// §4.6, §8.4: a duplicate jti MUST be rejected; one spent on either surface is spent on both.
func TestSection4_6And8_4AJTIIsAcceptedOnce(t *testing.T) {
	a, key, id, _ := protocolCase(t)
	jwt := key.requestJWT(id, base, nil, nil)
	a.status(a.c.Get("/capability/list", contracttest.Bearer(jwt)), 200, "first")
	a.agentsProblem(a.c.Get("/capability/list", contracttest.Bearer(jwt)), 401, "invalid_jwt", "", "again")
	a.agentsProblem(a.c.Get("/capability/describe?name=invite", contracttest.Bearer(jwt)), 401, "invalid_jwt", "", "on another route")
	a.agentsProblem(a.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, map[string]any{"jti": nil}, nil))), 401, "invalid_jwt", "", "§4.6: jti is required")
	a.agentsProblem(a.signed(key, id, "GET", "/agents/session", nil, map[string]any{"jti": claims(jwt)["jti"]}), 401, "invalid_jwt", "", "on the Polaris surface")
}

// §4.3: a JWT whose typ is not agent+jwt MUST be rejected as an agent's. Host JWTs (§4.2) are not
// verified yet: the 401 is what makes the reference client ask again without a credential.
func TestSection4_3TheTypeIsAgentJWT(t *testing.T) {
	a, key, id, _ := protocolCase(t)
	for _, route := range capabilityRoutes {
		for _, typ := range []string{"JWT", "host+jwt", "at+jwt"} {
			a.agentsProblem(a.c.Get(route, contracttest.Bearer(key.requestJWT(id, base, nil, map[string]any{"typ": typ}))), 401, "invalid_jwt", "", typ)
		}
		a.agentsProblem(a.c.Get(route, contracttest.Header("Authorization", "Basic eDp5")), 401, "invalid_jwt", "invalid_jwt", "another scheme")
		a.agentsProblem(a.c.Get(route, contracttest.Bearer(newKey("EdDSA").requestJWT(id, base, nil, nil))), 401, "invalid_jwt", "", "§4.5: another key")
		a.agentsProblem(a.c.Get(route, contracttest.Bearer(key.requestJWT("nobody", base, nil, nil))), 401, "invalid_jwt", "", "§4.5: an unknown agent")
	}
}

// §4.5, §5.13: an inactive agent is refused with 403. Suspended has no protocol code; §5.13 allows
// another.
func TestSection4_5AnInactiveAgentIsForbidden(t *testing.T) {
	a, key, id, session := protocolCase(t)
	refused := func(code string) {
		t.Helper()
		for _, route := range capabilityRoutes {
			a.agentsProblem(a.c.Get(route, contracttest.Bearer(key.requestJWT(id, base, nil, nil))), 403, code, code, route)
		}
	}
	a.status(a.c.Post("/agents/"+id+"/suspend", nil, contracttest.Bearer(session)), 200, "suspend")
	refused("agent_suspended")
	a.status(a.c.Post("/agents/"+id+"/revoke", nil, contracttest.Bearer(session)), 200, "revoke")
	refused("agent_revoked")
}

// htu names the URL called, not the aud (RFC 9449), when a client sends it.
func TestHTUIsTheURLCalledOnTheProtocolRoutes(t *testing.T) {
	a, key, id, _ := protocolCase(t)
	a.status(a.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, map[string]any{"htm": "GET", "htu": base + "/capability/list"}, nil))), 200, "its URL")
	a.agentsProblem(a.c.Get("/capability/list", contracttest.Bearer(key.requestJWT(id, base, map[string]any{"htu": base}, nil))), 401, "invalid_jwt", "", "the issuer")
}

// An agent's OAuth access token is accepted too (§12.1 allows it).
func TestAnAgentsAccessTokenListsItsGrants(t *testing.T) {
	a, _, _, session := protocolCase(t)
	agent := a.registerAgent(session, map[string]any{"name": "Helper", "auth": "delegated_token", "capabilities": []any{"members.list"}})
	tok := str(a.json(a.exchangeFor(str(agent["id"]), session))["access_token"])
	a.equal(at(a.json(a.c.Get("/capability/list", contracttest.Bearer(tok)))["capabilities"], 0)["grant_status"], "granted", "granted")
	a.agentsProblem(a.c.Get("/capability/list", contracttest.Bearer(session)), 401, "invalid_jwt", "", "a user's token is not an agent's")
}

func bootDiscovery(t *testing.T, mode agents.DiscoveryMode, caps []agents.Capability, baseURL, prefix string) (*polaristest.Server, *agents.Plugin) {
	t.Helper()
	// v1.0.0's strengths, so that its document is the same in every mode.
	strengths := map[string]string{agents.RiskLow: agents.StrengthSession, agents.RiskMedium: agents.StrengthSession, agents.RiskHigh: agents.StrengthStepUp}
	p := agents.New(agents.Config{Capabilities: caps, Discovery: mode, Strengths: strengths})
	return polaristest.New(t, polaristest.WithPathPrefix(prefix), polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{BaseURL: baseURL}), p)), p
}

func fetch(h http.Handler, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w
}

// The golden is what v1.0.0 answered, written by v1.0.0's code: a v1 client reads the same bytes at
// the well-known path in the default mode, and at /agents/configuration in every mode.
func TestTheDefaultDiscoveryDocumentIsByteIdenticalToV1_0_0(t *testing.T) {
	golden, err := os.ReadFile("testdata/discovery-v1.0.0.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []agents.DiscoveryMode{"", agents.DiscoveryPolaris, agents.DiscoveryAgentAuth} {
		srv, p := bootDiscovery(t, mode, capabilities(), base, "")
		answers := map[string]*httptest.ResponseRecorder{"/agents/configuration": fetch(srv.Handler(), "/agents/configuration")}
		if mode != agents.DiscoveryAgentAuth {
			answers["well-known"] = fetch(srv.Handler(), "/.well-known/agent-configuration")
			answers["DiscoveryHandler"] = fetch(p.DiscoveryHandler(), "/.well-known/agent-configuration")
		}
		for name, w := range answers {
			if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), golden) || w.Header().Get("Cache-Control") != "public, max-age=3600" || w.Header().Get("Content-Type") != "application/json" {
				t.Errorf("mode %q, %s: %d %v\n got %s\nwant %s", mode, name, w.Code, w.Header(), w.Body, golden)
			}
		}
	}
}

// §5.1: the protocol document, with every path relative to the issuer, under the mount.
func TestSection5_1TheAgentAuthDocument(t *testing.T) {
	for prefix, issuer := range map[string]string{"": base, "/auth": base + "/auth"} {
		srv, p := bootDiscovery(t, agents.DiscoveryAgentAuth, capabilities(), issuer, prefix)
		w := fetch(srv.Handler(), prefix+"/.well-known/agent-configuration")
		want := `{"algorithms":["Ed25519"],"approval_methods":["device_authorization","ciba"],"default_location":"` + issuer + `/capability/execute",` +
			`"description":"Polaris for Go agent provider","endpoints":{"capabilities":"/capability/list","describe_capability":"/capability/describe","execute":"/capability/execute",` +
			`"register":"/agent/register","request_capability":"/agent/request-capability","status":"/agent/status"},"issuer":"` + issuer + `",` +
			`"jwks_uri":"` + issuer + `/auth/.well-known/jwks.json","modes":["delegated","autonomous"],"provider_name":"Polaris","version":"1.0-draft"}`
		if w.Code != 200 || w.Body.String() != want || w.Header().Get("Cache-Control") != "public, max-age=3600" {
			t.Errorf("mounted at %q: %d %v %s", prefix, w.Code, w.Header(), w.Body)
		}
		if root := fetch(p.DiscoveryHandler(), "/.well-known/agent-configuration"); root.Body.String() != want {
			t.Errorf("DiscoveryHandler: %s", root.Body)
		}
		var doc struct {
			Endpoints map[string]string `json:"endpoints"`
			JWKS      string            `json:"jwks_uri"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		// Whatever the document names is served, where the client looks for it.
		for name, path := range doc.Endpoints {
			method := http.MethodPost
			if slices.Contains([]string{"capabilities", "describe_capability", "status"}, name) {
				method = http.MethodGet
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, httptest.NewRequest(method, strings.TrimPrefix(issuer, base)+path+"?name=invite", nil))
			if w.Code != 200 && w.Code != 401 { // 404 and 405 are the router's
				t.Errorf("%s at %s: %d", name, path, w.Code)
			}
		}
		if got := fetch(srv.Handler(), strings.TrimPrefix(doc.JWKS, base)); got.Code != 200 {
			t.Errorf("jwks_uri: %d", got.Code)
		}
	}
}

// The protocol routes are served in both modes: Discovery only decides which document is found.
func TestTheCapabilityRoutesAreServedInEveryMode(t *testing.T) {
	for _, mode := range []agents.DiscoveryMode{agents.DiscoveryPolaris, agents.DiscoveryAgentAuth} {
		srv, _ := bootDiscovery(t, mode, capabilities(), base, "")
		for _, route := range capabilityRoutes {
			w := fetch(srv.Handler(), route)
			if w.Code != 200 || !slices.Contains(w.Header().Values("Vary"), "Authorization") {
				t.Errorf("%s %s: %d %v", mode, route, w.Code, w.Header())
			}
		}
	}
}

// §5.2: a page holds at most 100 capabilities, whatever limit asks for.
func TestSection5_2AListPageIsBounded(t *testing.T) {
	var caps []agents.Capability
	for _, a := range "abcdefghijk" {
		for _, b := range "abcdefghij" {
			c := capabilities()[0]
			c.Name = string(a) + string(b)
			caps = append(caps, c)
		}
	}
	srv, _ := bootDiscovery(t, "", caps, base, "")
	seen, cursor := 0, ""
	for pages := 0; ; pages++ {
		var page struct {
			Capabilities []json.RawMessage `json:"capabilities"`
			Next         *string           `json:"next_cursor"`
			More         bool              `json:"has_more"`
		}
		w := fetch(srv.Handler(), "/capability/list?limit=1000&cursor="+url.QueryEscape(cursor))
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Capabilities) > 100 || pages > 2 {
			t.Fatalf("page %d: %d %v", pages, len(page.Capabilities), err)
		}
		seen += len(page.Capabilities)
		if !page.More {
			break
		}
		cursor = *page.Next
	}
	if seen != len(caps) {
		t.Errorf("%d of %d capabilities", seen, len(caps))
	}
}

// The Go agent SDK signs in to a server whose well-known document is the protocol's: it finds
// Polaris's at /agents/configuration, and its agent works as against the default mode.
func TestTheGoAgentSDKSignsInInAgentAuthMode(t *testing.T) {
	var handler http.Handler
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer web.Close()
	srv, p := bootDiscovery(t, agents.DiscoveryAgentAuth, capabilities(), web.URL, "")
	handler = srv.Handler()
	a := &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p}
	_, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	host := a.data(a.c.Post("/agents/hosts", map[string]any{"name": "Laptop", "default_capabilities": []any{"members.list"}}, contracttest.Bearer(session)))

	key, err := agent.GenerateKey(agent.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := agent.New(t.Context(), web.URL, agent.WithKey(key))
	if err != nil {
		t.Fatal(err)
	}
	bot, _, err := sdk.Enroll(t.Context(), str(host["enrollment_token"]), agent.Registration{Name: "Go", Mode: agent.Delegated})
	if err != nil {
		t.Fatal(err)
	}
	if done, err := bot.Execute(t.Context(), "members.list", nil); err != nil || done.Receipt.ID == "" {
		t.Fatalf("%+v %v", done, err)
	}
}
