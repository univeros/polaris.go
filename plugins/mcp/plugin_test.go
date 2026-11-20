package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/apikeys"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// Port of upstream's PluginTest and the mcp CookieModeTest.

// stub is a plugin adding one tool through wiring.ToolProvider.
type stub struct{}

func (stub) ID() string { return "stub" }

func (stub) MCPTools(context.Context, *token.Token) ([]wiring.Tool, error) {
	return []wiring.Tool{{Name: "stub.echo", Description: "Echo", Call: func(_ context.Context, args map[string]any) (wiring.ToolResult, error) {
		return wiring.ToolResult{Status: 200, Body: args}, nil
	}}}, nil
}

func boot(t *testing.T, plugins ...polaris.Plugin) *polaristest.Server {
	t.Helper()
	return polaristest.New(t, polaristest.WithPlugins(append(plugins, mcp.New(mcp.Config{BaseURL: base}))...))
}

// stdio runs ServeStdio over the messages and returns the replies, keyed by id.
func stdio(t *testing.T, p *polaris.Polaris, credential string, tools []wiring.Tool, messages ...map[string]any) map[string]map[string]any {
	t.Helper()
	var in bytes.Buffer
	for _, m := range messages {
		b, _ := json.Marshal(m)
		in.Write(append(b, '\n'))
	}
	in.WriteString("\n")
	var out bytes.Buffer
	if err := mcp.ServeStdio(context.Background(), p, mcp.StdioOptions{Credential: credential, In: &in, Out: &out, Tools: tools}); err != nil {
		t.Fatal(err)
	}
	replies := map[string]map[string]any{}
	lines := bufio.NewScanner(&out)
	lines.Buffer(nil, 4<<20)
	for lines.Scan() {
		var m map[string]any
		if err := json.Unmarshal(lines.Bytes(), &m); err != nil {
			t.Fatalf("reply %q: %v", lines.Text(), err)
		}
		id, _ := json.Marshal(m["id"])
		replies[string(id)] = m
	}
	return replies
}

func toolNames(reply map[string]any) []string {
	result, _ := reply["result"].(map[string]any)
	tools, _ := result["tools"].([]any)
	var names []string
	for _, tool := range tools {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return names
}

func toolsFor(t *testing.T, p *polaris.Polaris, credential string) []string {
	t.Helper()
	return toolNames(stdio(t, p, credential, nil, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["1"])
}

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	srv := boot(t)
	g := srv.Graph()
	p := mcp.Of(g)
	if p == nil || p.ID() != "mcp" || p.Resource() != base+"/mcp" || p.ProtectedResource().MetadataURL() != metadataURL {
		t.Fatalf("plugin: %+v", p)
	}
	for _, pattern := range [][2]string{{"POST", "/mcp"}, {"GET", "/.well-known/oauth-protected-resource/mcp"}} {
		if _, ok := g.Manifest().Find(pattern[0], pattern[1]); !ok {
			t.Errorf("%v not in the manifest", pattern)
		}
	}
	md := p.ProtectedResource().Metadata()
	if md["resource"] != base+"/mcp" || md["authorization_servers"].([]string)[0] != base || !slices.Contains(md["scopes_supported"].([]string), "org.read") {
		t.Errorf("metadata %v", md)
	}

	// The bearer resolver answers the context principal and nothing on the wire.
	resolver := p.BearerResolvers(g)[0]
	r := httptest.NewRequest(http.MethodGet, base+"/auth/me", nil)
	r.Header.Set("Authorization", "Bearer x")
	if tok, err := resolver.Resolve(r); tok != nil || err != nil {
		t.Errorf("a header is not a principal: %v %v", tok, err)
	}

	// Configuration errors name their fix; ServeStdio needs the plugin.
	_, err := polaris.New(polaris.Config{Secrets: g.Config().Secrets, Auth: g.Auth(), DB: g.DB(), Plugins: []polaris.Plugin{mcp.New(mcp.Config{BaseURL: "auth.polaris.test"})}})
	if err == nil || !strings.Contains(err.Error(), "Config.BaseURL") {
		t.Errorf("bad BaseURL: %v", err)
	}
	bare := polaristest.New(t)
	if err := mcp.ServeStdio(context.Background(), bare.Polaris, mcp.StdioOptions{}); err == nil || !strings.Contains(err.Error(), "mcp.New") {
		t.Errorf("no plugin: %v", err)
	}
}

func TestToolNamesAreUniqueOverEveryPluginOfTheRepository(t *testing.T) {
	srv := boot(t, audit.New(audit.Config{}), admin.New(admin.Config{}), apikeys.New(apikeys.Config{}),
		oauth.New(oauth.Config{BaseURL: base, Audiences: []string{base + "/mcp"}}))
	g := srv.Graph()
	names := map[string]bool{}
	valid := regexp.MustCompile(`^polaris(\.[a-z0-9_]+)+$`)
	for _, rt := range g.Manifest().Routes() {
		name := mcp.ToolName(rt)
		if names[name] {
			t.Errorf("%s twice", name)
		}
		names[name] = true
		if !valid.MatchString(name) {
			t.Errorf("tool name %s", name)
		}
	}
	for _, name := range []string{"polaris.auth.me", "polaris.orgs.members.list", "polaris.admin.users.ban", "polaris.oauth.token", "polaris.auth.mfa.totp.enroll"} {
		if !names[name] {
			t.Errorf("%s missing", name)
		}
	}
}

func TestSchemasFoldTheOpenApiOperation(t *testing.T) {
	srv := boot(t, audit.New(audit.Config{}), admin.New(admin.Config{}))
	ctx := context.Background()
	_, key, err := admin.Of(srv.Graph()).Keys().Create(ctx, admin.Key{Name: "ops", Role: admin.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	reply := stdio(t, srv.Polaris, key, nil, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["1"]
	byName := map[string]map[string]any{}
	for _, tool := range reply["result"].(map[string]any)["tools"].([]any) {
		m := tool.(map[string]any)
		byName[m["name"].(string)] = m
	}
	login := byName["polaris.auth.login"]
	equalJSON(t, login["inputSchema"].(map[string]any)["properties"].(map[string]any)["email"], map[string]any{"type": "string", "format": "email", "maxLength": 320}, "login email")
	equalJSON(t, login["inputSchema"].(map[string]any)["required"], []string{"email", "password"}, "login required")
	if login["description"] != "Authenticate with email and password (POST /auth/login)" {
		t.Error(login["description"])
	}
	equalJSON(t, login["outputSchema"].(map[string]any)["required"], []string{"status", "body"}, "output")
	// Annotations from the effect (an operator sees no session route: an admin key is nobody's session).
	users := byName["polaris.admin.users.delete"]["annotations"].(map[string]any)
	if users["destructiveHint"] != true || users["readOnlyHint"] != false {
		t.Errorf("users.delete annotations %v", users)
	}
	if byName["polaris.admin.users.list"]["annotations"].(map[string]any)["readOnlyHint"] != true {
		t.Error("users.list is read-only")
	}
}

func TestToolsAreListedPerPrincipal(t *testing.T) {
	srv := boot(t, audit.New(audit.Config{}), admin.New(admin.Config{}), apikeys.New(apikeys.Config{}), stub{})
	c := contracttest.NewClient(t, srv.Handler(), nil)
	s := &serverCase{t: t, srv: srv, c: c}

	anonymous := toolsFor(t, srv.Polaris, "")
	if !slices.Contains(anonymous, "polaris.auth.login") || !slices.Contains(anonymous, "stub.echo") {
		t.Errorf("anonymous: %v", anonymous)
	}
	for _, hidden := range []string{"polaris.auth.me", "polaris.auth.mfa.login.verify", "polaris.admin.users.list", "polaris.orgs.create"} {
		if slices.Contains(anonymous, hidden) {
			t.Errorf("anonymous sees %s", hidden)
		}
	}

	session := s.login("ada@example.com")
	orgID, _ := s.data(c.Post("/orgs", map[string]any{"name": "Acme"}, contracttest.Bearer(session)))["id"].(string)
	session, _ = s.data(c.Post("/auth/switch-org", map[string]any{"organization_id": orgID}, contracttest.Bearer(session)))["access_token"].(string)
	owner := toolsFor(t, srv.Polaris, session)
	for _, allowed := range []string{"polaris.auth.login", "polaris.auth.me", "polaris.orgs.create", "polaris.orgs.members.list", "polaris.orgs.update", "polaris.auth.mfa.totp.enroll"} {
		if !slices.Contains(owner, allowed) {
			t.Errorf("owner misses %s", allowed)
		}
	}
	for _, hidden := range []string{"polaris.admin.users.list", "polaris.auth.mfa.login.verify", "polaris.users.disable"} {
		if slices.Contains(owner, hidden) {
			t.Errorf("owner sees %s", hidden)
		}
	}

	// An API key delegated members.read only.
	created := s.data(c.Post("/api-keys", map[string]any{"name": "ci", "organization_id": orgID, "permissions": []string{"members.read"}}, contracttest.Bearer(session)))
	if secret, _ := created["key"].(string); secret != "" {
		delegated := toolsFor(t, srv.Polaris, secret)
		if !slices.Contains(delegated, "polaris.auth.me") || !slices.Contains(delegated, "polaris.orgs.members.list") {
			t.Errorf("delegated misses reads: %v", delegated)
		}
		for _, hidden := range []string{"polaris.orgs.update", "polaris.orgs.create", "polaris.auth.mfa.totp.enroll"} {
			if slices.Contains(delegated, hidden) {
				t.Errorf("delegated sees %s", hidden)
			}
		}
	} else {
		t.Errorf("api key: %v", created)
	}

	_, key, err := admin.Of(srv.Graph()).Keys().Create(context.Background(), admin.Key{Name: "ops", Role: admin.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	operator := toolsFor(t, srv.Polaris, key)
	if !slices.Contains(operator, "polaris.admin.users.list") || !slices.Contains(operator, "polaris.auth.login") || slices.Contains(operator, "polaris.auth.me") {
		t.Errorf("operator: %v", operator)
	}

	if err := mcp.ServeStdio(context.Background(), srv.Polaris, mcp.StdioOptions{Credential: "garbage", In: strings.NewReader(""), Out: &bytes.Buffer{}}); err == nil ||
		!strings.Contains(err.Error(), "does not authenticate") || !strings.Contains(err.Error(), mcp.StdioEnv) {
		t.Errorf("garbage credential: %v", err)
	}
}

func TestTheStdioTransportServesTheToolsOfThePrincipal(t *testing.T) {
	srv := boot(t, audit.New(audit.Config{}), admin.New(admin.Config{}))
	_, key, err := admin.Of(srv.Graph()).Keys().Create(context.Background(), admin.Key{Name: "ops", Role: admin.RoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	export := wiring.Tool{Name: "polaris.schema.export", Description: "Print the DDL (polaris schema:export)", ReadOnly: true,
		Call: func(_ context.Context, args map[string]any) (wiring.ToolResult, error) {
			return wiring.ToolResult{Status: 200, Body: "CREATE TABLE \"auth_users\" -- " + args["target"].(string)}, nil
		}}
	replies := stdio(t, srv.Polaris, key, []wiring.Tool{export},
		map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}}},
		map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"},
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "polaris.schema.export", "arguments": map[string]any{"target": "sql:sqlite"}}},
		map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "polaris.admin.users.list", "arguments": map[string]any{"limit": 10}}},
		map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "polaris.auth.login", "arguments": map[string]any{"email": "nobody@example.com", "password": "wrong"}}},
		map[string]any{"jsonrpc": "2.0", "id": 5, "method": "resources/read", "params": map[string]any{"uri": "polaris://manifest"}},
		map[string]any{"jsonrpc": "2.0", "id": 6, "method": "resources/templates/list"},
		map[string]any{"jsonrpc": "2.0", "id": 7, "method": "ping"},
		map[string]any{"jsonrpc": "2.0", "id": 8, "method": "resources/read", "params": map[string]any{"uri": "polaris://problems/admin/forbidden"}},
		map[string]any{"jsonrpc": "2.0", "id": 9, "method": "resources/read", "params": map[string]any{"uri": "polaris://problems/admin/nothing"}},
		map[string]any{"jsonrpc": "2.0", "id": 10, "method": "resources/read", "params": map[string]any{"uri": "polaris://schema"}},
		map[string]any{"jsonrpc": "2.0", "id": 11, "method": "resources/list"},
		map[string]any{"jsonrpc": "2.0", "id": 12, "method": "nope"},
		map[string]any{"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": map[string]any{"name": "polaris.auth.me"}},
		map[string]any{"jsonrpc": "2.0", "id": 14, "method": "tools/call", "params": map[string]any{"name": "stub", "arguments": []any{}}},
	)
	result := func(id string) map[string]any { r, _ := replies[id]["result"].(map[string]any); return r }
	errCode := func(id string) any { e, _ := replies[id]["error"].(map[string]any); return e["code"] }

	if result("0")["serverInfo"].(map[string]any)["name"] != "Polaris" || result("0")["protocolVersion"] != "2025-11-25" {
		t.Errorf("initialize: %v", replies["0"])
	}
	names := toolNames(replies["1"])
	for _, name := range []string{"polaris.schema.export", "polaris.admin.users.list", "polaris.auth.login"} {
		if !slices.Contains(names, name) {
			t.Errorf("%s not listed", name)
		}
	}
	if slices.Contains(names, "polaris.auth.me") {
		t.Error("an operator key is nobody's session")
	}
	if r := result("2"); r["isError"] != false || !strings.Contains(r["content"].([]any)[0].(map[string]any)["text"].(string), `CREATE TABLE "auth_users"`) {
		t.Errorf("schema export: %v", replies["2"])
	}
	if r := result("3"); r["isError"] != false {
		t.Errorf("admin users list: %v", replies["3"])
	} else {
		equalJSON(t, r["structuredContent"].(map[string]any)["body"].(map[string]any)["data"], []any{}, "no users")
	}
	r4 := result("4")
	equalJSON(t, r4["structuredContent"], map[string]any{"status": 401, "body": map[string]any{"error": "invalid_credentials", "message": "Invalid email or password."}}, "login")
	if r4["isError"] != true {
		t.Error("a 401 is an error result")
	}
	contents := result("5")["contents"].([]any)[0].(map[string]any)
	var openapi map[string]any
	_ = json.Unmarshal([]byte(contents["text"].(string)), &openapi)
	if contents["mimeType"] != "application/json" || openapi["openapi"] != "3.1.0" {
		t.Errorf("manifest resource: %v", contents["mimeType"])
	}
	if result("6")["resourceTemplates"].([]any)[0].(map[string]any)["uriTemplate"] != mcp.ResourceProblems {
		t.Errorf("templates: %v", replies["6"])
	}
	if result("7") == nil {
		t.Error("ping")
	}
	var problem map[string]any
	_ = json.Unmarshal([]byte(result("8")["contents"].([]any)[0].(map[string]any)["text"].(string)), &problem)
	if problem["type"] != "https://polaris.univeros.io/problems/admin/forbidden" || problem["title"] != "Forbidden" {
		t.Errorf("problem: %v", problem)
	}
	if errCode("9") != float64(-32602) || errCode("10") != float64(-32002) || errCode("12") != float64(-32601) {
		t.Errorf("errors: %v %v %v", replies["9"], replies["10"], replies["12"])
	}
	if len(result("11")["resources"].([]any)) != 1 {
		t.Errorf("without Config.Schema only the manifest is listed: %v", replies["11"])
	}
	if errCode("13") != float64(-32602) || errCode("14") != float64(-32602) {
		t.Errorf("unlisted tool / bad arguments: %v %v", replies["13"], replies["14"])
	}
}

func TestTheSchemaResourceComesFromTheHost(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(mcp.New(mcp.Config{BaseURL: base,
		Schema: func(context.Context) (string, error) { return "CREATE TABLE x;", nil }})))
	replies := stdio(t, srv.Polaris, "", nil,
		map[string]any{"jsonrpc": "2.0", "id": 1, "method": "resources/list"},
		map[string]any{"jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": map[string]any{"uri": mcp.ResourceSchema}},
		map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "polaris.auth.jwks"}},
	)
	if n := len(replies["1"]["result"].(map[string]any)["resources"].([]any)); n != 2 {
		t.Errorf("resources: %d", n)
	}
	if text := replies["2"]["result"].(map[string]any)["contents"].([]any)[0].(map[string]any)["text"]; text != "CREATE TABLE x;" {
		t.Errorf("schema: %v", text)
	}
	if replies["3"]["result"].(map[string]any)["isError"] != false {
		t.Errorf("jwks tool: %v", replies["3"])
	}
}

// A tool call has no cookie jar, so the dispatch runs in body mode whatever the host's token
// delivery: the login tool answers the refresh token in its body, even over http and without the
// CSRF header the route would demand (upstream CookieModeTest).
func TestTheLoginToolAnswersTheRefreshTokenInItsBody(t *testing.T) {
	srv := polaristest.New(t,
		polaristest.WithAuth(func(a *config.Auth) { a.Flows.TokenDelivery = config.DeliveryCookie }),
		polaristest.WithPlugins(mcp.New(mcp.Config{BaseURL: "http://localhost"})))
	c := contracttest.NewClient(t, srv.Handler(), nil)
	s := &serverCase{t: t, srv: srv, c: c}
	c.Post("/auth/register", map[string]any{"email": "tool@example.com", "password": password})
	s.login("tool@example.com") // the HTTP route refuses (plaintext, no CSRF header): only the tool signs in
	reply := stdio(t, srv.Polaris, "", nil, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "polaris.auth.login", "arguments": map[string]any{"email": "tool@example.com", "password": password}}})["1"]
	sc := reply["result"].(map[string]any)["structuredContent"].(map[string]any)
	data, _ := sc["body"].(map[string]any)["data"].(map[string]any)
	if sc["status"] != float64(200) || data["refresh_token"] == "" || data["refresh_token"] == nil {
		t.Fatalf("login tool: %v", sc)
	}
}
