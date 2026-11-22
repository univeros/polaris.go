package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// TestWalkthrough boots the example on a real listener (the resources are absolute URLs) and runs
// the README's curl walkthrough: session, OAuth client, token exchange per resource, tool calls.
func TestWalkthrough(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	base := "http://" + srv.Listener.Addr().String()
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
		t.Setenv(name, "")
	}
	if err := devEnv(base); err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB().Close() })
	h, p, err := newServer(ctx, db, base)
	if err != nil {
		t.Fatal(err)
	}
	orgID, err := seed(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	t.Cleanup(srv.Close)

	// 1. Ada's session, scoped to Acme, and an OAuth client that may exchange it.
	session := field(t, do(t, "POST", base+"/auth/login", "", `{"email":"`+demoEmail+`","password":"`+demoPassword+`"}`, 200), "access_token")
	session = field(t, do(t, "POST", base+"/auth/switch-org", session, `{"organization_id":"`+orgID+`"}`, 200), "access_token")
	client := do(t, "POST", base+"/orgs/"+orgID+"/oauth/clients", session,
		`{"name":"Deploy CLI","type":"confidential","grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],"token_endpoint_auth_method":"client_secret_post"}`, 201)
	exchange := func(resource, scope string) string {
		form := url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {field(t, client, "client_id")},
			"client_secret": {field(t, client, "client_secret")}, "subject_token": {session},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {resource}, "scope": {scope},
		}
		resp, err := http.PostForm(base+"/oauth2/token", form)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var tok struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
			t.Fatalf("exchange for %s: %d %v", resource, resp.StatusCode, err)
		}
		return tok.AccessToken
	}

	// 2. The host's MCP server: no token and a session token are 401, a narrow token 403.
	deployCall := `"name":"deploy","arguments":{"service":"billing"},`
	mcpCall(t, base+"/tools/mcp", "", "tools/call", "deploy", deployCall, 401)
	mcpCall(t, base+"/tools/mcp", session, "tools/call", "deploy", deployCall, 401)
	mcpCall(t, base+"/tools/mcp", exchange(base+"/tools/mcp", "org.read"), "tools/call", "deploy", deployCall, 403)
	if got := mcpCall(t, base+"/tools/mcp", exchange(base+"/tools/mcp", "deploy.run"), "tools/call", "deploy", deployCall, 200); !strings.Contains(got, "billing deployed by user") {
		t.Errorf("deploy: %s", got)
	}

	// 3. Polaris's own MCP server lists the routes the token may call.
	if got := mcpCall(t, base+"/mcp", exchange(base+"/mcp", "org.read members.read"), "tools/list", "", "", 200); !strings.Contains(got, "polaris.orgs.members.list") {
		t.Errorf("tools/list: %s", got)
	}
}

// mcpCall posts one MCP 2026-07-28 message and answers the body.
func mcpCall(t *testing.T, endpoint, bearer, method, name, params string, want int) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":{` + params +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", method)
	if name != "" {
		req.Header.Set("Mcp-Name", name)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: %d, want %d: %s", method, endpoint, resp.StatusCode, want, raw)
	}
	return string(raw)
}

// do sends a JSON request and answers the envelope's data.
func do(t *testing.T, method, endpoint, bearer, body string, want int) map[string]any {
	t.Helper()
	req, err := http.NewRequest(method, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Data map[string]any `json:"data"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want || json.Unmarshal(raw, &out) != nil {
		t.Fatalf("%s %s: %d, want %d: %s", method, endpoint, resp.StatusCode, want, raw)
	}
	return out.Data
}

func field(t *testing.T, m map[string]any, name string) string {
	t.Helper()
	s, ok := m[name].(string)
	if !ok || s == "" {
		t.Fatalf("no %s in %v", name, m)
	}
	return s
}
