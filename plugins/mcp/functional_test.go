package mcp_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// Port of upstream's McpServerTest (WP4 acceptance 2, over HTTP).

const (
	phpServerTest = `Polaris\Mcp\Tests\Functional\McpServerTest`
	base          = "https://auth.polaris.test"
	metadataURL   = base + "/.well-known/oauth-protected-resource/mcp"
	password      = "correct horse battery staple"
)

func newServer(t *testing.T, opts ...polaristest.Option) *polaristest.Server {
	t.Helper()
	plugins := polaristest.WithPlugins(
		audit.New(audit.Config{}),
		admin.New(admin.Config{}),
		oauth.New(oauth.Config{BaseURL: base, ConsentURL: "https://app.polaris.test/consent", PollInterval: -1,
			Audiences: []string{base + mcp.Path}}),
		mcp.New(mcp.Config{BaseURL: base, Scopes: []string{"org.read"}}),
	)
	return polaristest.New(t, append([]polaristest.Option{plugins}, opts...)...)
}

type serverCase struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
}

func (s *serverCase) data(resp *http.Response) map[string]any {
	m, _ := contracttest.JSON(s.t, resp)["data"].(map[string]any)
	return m
}

// mcp sends one JSON-RPC request in the 2026-07-28 profile: the version, method and name headers
// and the _meta the profile requires.
func (s *serverCase) mcp(method string, params map[string]any, access, name string) *http.Response {
	s.t.Helper()
	p := map[string]any{}
	for k, v := range params {
		p[k] = v
	}
	p["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": mcp.ProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": p})
	opts := []contracttest.Option{
		contracttest.Header("Content-Type", "application/json"), contracttest.Header("Accept", "application/json"),
		contracttest.Header("MCP-Protocol-Version", mcp.ProtocolVersion), contracttest.Header("Mcp-Method", method),
	}
	if name != "" {
		opts = append(opts, contracttest.Header("Mcp-Name", name))
	}
	if access != "" {
		opts = append(opts, contracttest.Bearer(access))
	}
	return s.c.Do(s.c.NewRequest(http.MethodPost, base+mcp.Path, body, opts...))
}

// call is a tool call's result.
func (s *serverCase) call(name string, args map[string]any, access string) map[string]any {
	s.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	resp := s.mcp("tools/call", map[string]any{"name": name, "arguments": args}, access, name)
	result, _ := contracttest.JSON(s.t, resp)["result"].(map[string]any)
	if resp.StatusCode != 200 || result == nil {
		s.t.Fatalf("%s: %d %v", name, resp.StatusCode, contracttest.JSON(s.t, resp))
	}
	return result
}

func (s *serverCase) login(email string) string {
	s.t.Helper()
	s.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var registered event.UserRegistered
	for _, e := range s.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			registered = r
		}
	}
	s.c.Post("/auth/email/verify", map[string]any{"token": registered.VerificationToken})
	access, _ := s.data(s.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

func claims(t *testing.T, jwt string) map[string]any {
	parts := strings.Split(jwt, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func equalJSON(t *testing.T, got, want any, msg string) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	var gv, wv any
	_ = json.Unmarshal(g, &gv)
	_ = json.Unmarshal(w, &wv)
	if gb, _ := json.Marshal(gv); string(gb) != func() string { b, _ := json.Marshal(wv); return string(b) }() {
		t.Errorf("%s:\n got %s\nwant %s", msg, g, w)
	}
}

func TestMcpServer(t *testing.T) {
	t.Run("testTheProtectedResourceListsAndCallsTheToolsOfTheTokensUser", func(t *testing.T) {
		srv := newServer(t)
		fx := contracttest.For(t, contracttest.UpstreamFixtures(t, "mcp"), phpServerTest, "testTheProtectedResourceListsAndCallsTheToolsOfTheTokensUser")
		s := &serverCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx)}

		// The metadata a challenged client is sent to.
		metadata := s.c.Get("/.well-known/oauth-protected-resource/mcp")
		doc := contracttest.JSON(t, metadata)
		if metadata.StatusCode != 200 || doc["resource"] != base+"/mcp" || !slices.Contains(doc["scopes_supported"].([]any), any("org.read")) {
			t.Fatalf("metadata: %d %v", metadata.StatusCode, doc)
		}

		// Without a token: the challenge names the metadata; a session token is not a token for this resource.
		challenged := s.mcp("tools/list", nil, "", "")
		if challenged.StatusCode != 401 || challenged.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="`+metadataURL+`"` {
			t.Fatalf("challenge: %d %v", challenged.StatusCode, challenged.Header)
		}
		session := s.login("ada@example.com")
		orgID, _ := s.data(s.c.Post("/orgs", map[string]any{"name": "Acme"}, contracttest.Bearer(session)))["id"].(string)
		session, _ = s.data(s.c.Post("/auth/switch-org", map[string]any{"organization_id": orgID}, contracttest.Bearer(session)))["access_token"].(string)
		if refused := s.mcp("tools/list", nil, session, ""); refused.StatusCode != 401 ||
			!strings.HasPrefix(refused.Header.Get("WWW-Authenticate"), `Bearer error="invalid_token"`) {
			t.Fatalf("session token: %d %v", refused.StatusCode, refused.Header)
		}

		// An access token for /mcp, by token exchange of Ada's session.
		client := s.data(s.c.Post("/orgs/"+orgID+"/oauth/clients", map[string]any{"name": "Acme CLI",
			"redirect_uris": []string{"https://cli.polaris.test/callback"}, "grant_types": []string{oauth.GrantTokenExchange},
			"token_endpoint_auth_method": "client_secret_post"}, contracttest.Bearer(session)))
		exchange := func(scope string) string {
			form := url.Values{}
			for k, v := range map[string]string{"client_id": client["client_id"].(string), "client_secret": client["client_secret"].(string),
				"grant_type": oauth.GrantTokenExchange, "subject_token": session, "subject_token_type": oauth.TokenTypeAccessToken,
				"resource": base + "/mcp", "scope": scope} {
				form.Set(k, v)
			}
			token, _ := contracttest.JSON(t, s.c.Form(base+"/oauth2/token", form))["access_token"].(string)
			return token
		}
		access := exchange("org.read members.read")
		if claims(t, access)["aud"] != base+"/mcp" {
			t.Fatalf("aud: %v", claims(t, access)["aud"])
		}

		// The tools: every public route, the bearer routes within the delegated scopes, no admin route.
		listed := contracttest.JSON(t, s.mcp("tools/list", nil, access, ""))
		result, _ := listed["result"].(map[string]any)
		tools, _ := result["tools"].([]any)
		var names []string
		for _, tool := range tools {
			names = append(names, tool.(map[string]any)["name"].(string))
		}
		for _, name := range []string{"polaris.auth.login", "polaris.auth.me", "polaris.orgs.members.list", "polaris.orgs.read", "polaris.oauth.openid.configuration", "polaris.oauth.consents.list"} {
			if !slices.Contains(names, name) {
				t.Errorf("%s not listed", name)
			}
		}
		for _, name := range []string{"polaris.orgs.update", "polaris.orgs.create", "polaris.admin.users.list", "polaris.auth.mfa.login.verify", "polaris.schema.export"} {
			if slices.Contains(names, name) {
				t.Errorf("%s listed", name)
			}
		}

		// A tool call answers what the route answers, for the same request with the same token.
		me := s.call("polaris.auth.me", nil, access)
		equalJSON(t, me["structuredContent"], map[string]any{"status": 200, "body": contracttest.JSON(t, s.c.Get("/auth/me", contracttest.Bearer(access)))}, "auth.me")
		members := s.call("polaris.orgs.members.list", map[string]any{"id": orgID}, access)
		equalJSON(t, members["structuredContent"], map[string]any{"status": 200, "body": contracttest.JSON(t, s.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(access)))}, "members")
		discovery := s.call("polaris.oauth.openid.configuration", nil, access)
		equalJSON(t, discovery["structuredContent"], map[string]any{"status": 200, "body": contracttest.JSON(t, s.c.Get("/.well-known/openid-configuration"))}, "discovery")

		// A route's refusal is an error result; a tool not listed for the token is not callable.
		other := "019aa7e0-0000-7000-8000-000000000000"
		read := s.call("polaris.orgs.read", map[string]any{"id": other}, access)
		if read["isError"] != true {
			t.Error("orgs.read of another org is an error result")
		}
		equalJSON(t, read["structuredContent"], map[string]any{"status": 403, "body": contracttest.JSON(t, s.c.Get("/orgs/"+other, contracttest.Bearer(access)))}, "orgs.read")
		unlisted := s.mcp("tools/call", map[string]any{"name": "polaris.orgs.update", "arguments": map[string]any{"id": orgID, "name": "Evil"}}, access, "polaris.orgs.update")
		if unlisted.StatusCode != 400 {
			t.Errorf("unlisted tool: %d", unlisted.StatusCode)
		}
		if resp := s.c.Patch("/orgs/"+orgID, map[string]any{"name": "Evil"}, contracttest.Bearer(access)); resp.StatusCode != 403 {
			t.Errorf("the route refuses the delegate too: %d", resp.StatusCode)
		}

		// Short of the scope /mcp requires: 403 naming it.
		insufficient := s.mcp("tools/list", nil, exchange("members.read"), "")
		if insufficient.StatusCode != 403 || insufficient.Header.Get("WWW-Authenticate") != `Bearer error="insufficient_scope", scope="org.read", resource_metadata="`+metadataURL+`"` {
			t.Errorf("insufficient scope: %d %v", insufficient.StatusCode, insufficient.Header)
		}

		// The session-based protocol is rejected.
		legacy := s.c.Do(s.c.NewRequest(http.MethodPost, base+"/mcp", nil, contracttest.Bearer(access), contracttest.Header("Mcp-Session-Id", other)))
		if legacy.StatusCode != 400 {
			t.Errorf("legacy: %d", legacy.StatusCode)
		}
	})
}

func TestEveryMcpFixtureHasAGoTest(t *testing.T) {
	missing, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "mcp"),
		[]string{phpServerTest + "::testTheProtectedResourceListsAndCallsTheToolsOfTheTokensUser"})
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
