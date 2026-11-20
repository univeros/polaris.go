package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/anonymous"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/mcp"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

func TestDoctor(t *testing.T) {
	cleanEnv(t)
	r := standalone(t, noEnvFile(t), "doctor", "--json")
	r.want(t, exitFail)
	status := map[string]string{}
	for _, c := range r.json(t)["checks"].([]any) {
		c := c.(map[string]any)
		status[c["name"].(string)] = c["status"].(string)
		if c["status"] == "fail" && c["remedy"] == "" {
			t.Errorf("%s fails without a remedy", c["name"])
		}
	}
	want := map[string]string{"config": "fail", "keys": "skip", "manifest": "pass", "database": "fail", "instance": "skip", "schema": "skip"}
	for name, s := range want {
		if status[name] != s {
			t.Errorf("%s: %s, want %s", name, status[name], s)
		}
	}

	configuredEnv(t)
	t.Setenv("AUTH_JWT_PUBLIC_KEY", "not a key")
	standalone(t, noEnvFile(t), "doctor").want(t, exitFail, "FAIL  keys:", "polaris init --force", "FAIL  instance:", "FAIL  schema:", "polaris migrate")

	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{})))
	hosted(t, srv.Polaris, nil, "doctor").want(t, exitOK, "plugins: audit", "matches the Polaris schema", "Polaris is ready.")
}

func TestHostWithoutAnSQLStore(t *testing.T) {
	srv := polaristest.New(t)
	g := srv.Graph()
	p, err := polarisOver(g.Config().Secrets, g.Auth())
	if err != nil {
		t.Fatal(err)
	}
	hosted(t, p, nil, "schema:diff").want(t, exitFail, "not an SQL store", "sqlstore.Open")
	hosted(t, p, nil, "schema:export", "--target=sql:mysql").want(t, exitOK, "CREATE TABLE `auth_users`")
}

func TestPluginCommands(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), anonymous.New(anonymous.Config{})))
	p := srv.Polaris
	now := time.Now().UTC().Truncate(time.Second)
	if err := srv.Graph().Repos().Users.Insert(ctx, model.User{ID: repository.NewID(), Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}

	hosted(t, p, nil, "audit:prune").want(t, exitOK, "Pruned 0 audit event(s).")
	hosted(t, p, nil, "audit:verify", "--json").want(t, exitOK, `"intact": true`)
	hosted(t, p, nil, "anonymous:prune", "--json").want(t, exitOK, `"pruned": 0`)

	hosted(t, p, nil, "admin:grant", "nobody@example.com", "admin").want(t, exitFail, "no user has the email address", "register the user first")
	first := hosted(t, p, nil, "admin:grant", "  ADA@example.com", "admin", "--json")
	first.want(t, exitOK)
	second := hosted(t, p, nil, "admin:grant", "ada@example.com", "owner", "--expires=2099-01-01", "--json")
	second.want(t, exitOK)
	if a, b := first.json(t), second.json(t); a["id"] != b["id"] || b["role"] != "owner" || b["granted_by"] != "cli" || b["email"] != "ada@example.com" {
		t.Errorf("a re-grant must replace the grant: %v then %v", a, b)
	}

	r := hosted(t, p, nil, "admin:key", "ops", "admin", "--allow=10.0.0.0/8, 203.0.113.7", "--scope=instance", "--json")
	r.want(t, exitOK)
	key := r.json(t)
	if !strings.HasPrefix(key["secret"].(string), admin.KeyPrefix) || len(key["key"].(map[string]any)["ip_allowlist"].([]any)) != 2 {
		t.Errorf("admin:key: %v", key)
	}
	hosted(t, p, nil, "admin:key", "ops", "viewer").want(t, exitFail, `an admin key named "ops" already exists`, "DELETE /admin/keys/")
	hosted(t, p, nil, "admin:key", "other", "viewer").want(t, exitOK, "The key is shown once", admin.KeyPrefix)
	hosted(t, p, nil, "admin:key", strings.Repeat("x", 121), "viewer").want(t, exitFail, "1 to 120 characters")

	bare := polaristest.New(t).Polaris
	for _, cmd := range [][]string{{"audit:prune"}, {"audit:verify"}, {"anonymous:prune"}, {"admin:grant", "a@example.com", "admin"}, {"admin:key", "k", "admin"}, {"mcp"}} {
		hosted(t, bare, nil, cmd...).want(t, exitFail, "plugin is not enabled", "--plugins=")
	}
}

func TestPluginCommandsStandalone(t *testing.T) {
	configuredEnv(t)
	env := noEnvFile(t)
	standalone(t, env, "migrate", "--plugins=audit").want(t, exitOK)
	standalone(t, env, "audit:verify", "--plugins=audit").want(t, exitOK, "Chain intact: 0 event(s) checked")
	standalone(t, env, "audit:verify").want(t, exitFail, "the audit plugin is not enabled")
}

func TestMCPServesTheCLICommandsAsTools(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(mcp.New(mcp.Config{BaseURL: contracttest.Issuer})))
	var in strings.Builder
	for _, m := range []map[string]any{
		{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}}},
		{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
		{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "polaris.schema.export", "arguments": map[string]any{"target": "sql:sqlite", "drop": true, "json": false}}},
		{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "polaris.doctor", "arguments": map[string]any{"json": true}}},
		{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "polaris.manifest", "arguments": map[string]any{"format": "yaml"}}},
	} {
		b, _ := json.Marshal(m)
		in.Write(append(b, '\n'))
	}
	r := hosted(t, srv.Polaris, strings.NewReader(in.String()), "mcp")
	r.want(t, exitOK)
	replies := map[float64]map[string]any{}
	lines := bufio.NewScanner(strings.NewReader(r.stdout))
	lines.Buffer(nil, 4<<20)
	for lines.Scan() {
		var m map[string]any
		if err := json.Unmarshal(lines.Bytes(), &m); err != nil {
			t.Fatalf("stdout is not the protocol stream: %q", lines.Text())
		}
		replies[m["id"].(float64)] = m["result"].(map[string]any)
	}
	var props map[string]any
	for _, tool := range replies[1]["tools"].([]any) {
		if tool := tool.(map[string]any); tool["name"] == "polaris.schema.export" {
			props = tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
		}
	}
	if props["drop"].(map[string]any)["type"] != "boolean" || props["target"].(map[string]any)["type"] != "string" || props["dsn"] != nil {
		t.Errorf("schema:export tool schema: %v", props)
	}
	text := func(id float64) string {
		return replies[id]["content"].([]any)[0].(map[string]any)["text"].(string)
	}
	if replies[2]["isError"] != false || !strings.HasPrefix(text(2), `DROP TABLE IF EXISTS "auth_membership_roles"`) {
		t.Errorf("schema.export: %v", replies[2])
	}
	if replies[3]["isError"] != false || !strings.Contains(text(3), `\"ready\": true`) && !strings.Contains(text(3), `"ready": true`) {
		t.Errorf("doctor: %v", replies[3])
	}
	if replies[4]["isError"] != true || !strings.Contains(text(4), "unknown format") {
		t.Errorf("manifest yaml: %v", replies[4])
	}

	hosted(t, srv.Polaris, strings.NewReader(""), "mcp", "--token=pk_live_nope").want(t, exitFail, "--token")
}

// polarisOver builds an instance over the in-memory store.
func polarisOver(secrets config.Secrets, auth config.Auth) (*polaris.Polaris, error) {
	return polaris.New(polaris.Config{Secrets: secrets, Auth: auth, DB: memstore.New(schema.Core()...)})
}
