package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/wiring"
)

// The JSON-RPC edges of the 2026-07-28 profile (upstream's SDK behaviour) and the schema folding.

func testPlugin(t *testing.T) *Plugin {
	t.Helper()
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), New(Config{BaseURL: "https://auth.polaris.test"})))
	return Of(srv.Graph())
}

func profileHeaders(method, name string) http.Header {
	h := http.Header{"Mcp-Protocol-Version": {ProtocolVersion}, "Mcp-Method": {method}}
	if name != "" {
		h.Set("Mcp-Name", name)
	}
	return h
}

func message(method string, params map[string]any, meta bool) []byte {
	if params == nil {
		params = map[string]any{}
	}
	if meta {
		params["_meta"] = map[string]any{metaProtocolVersion: ProtocolVersion, metaClientCapabilities: map[string]any{}}
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	return b
}

func TestTheStatelessProfileAnswersItsErrors(t *testing.T) {
	p := testPlugin(t)
	ctx := context.Background()
	wrongVersion := profileHeaders("tools/list", "")
	wrongVersion.Set("Mcp-Protocol-Version", "2027-01-01")
	oldMeta := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2027-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	cases := []struct {
		name   string
		body   []byte
		h      http.Header
		status int
		code   int
	}{
		{"not JSON", []byte("{"), nil, 400, codeParse},
		{"not an object", []byte("[1]"), nil, 400, codeInvalidRequest},
		{"no method", []byte(`{"jsonrpc":"2.0","id":1}`), nil, 400, codeInvalidRequest},
		{"a float id", []byte(`{"jsonrpc":"2.0","id":1.5,"method":"tools/list"}`), nil, 400, codeInvalidRequest},
		{"no _meta", message("tools/list", nil, false), profileHeaders("tools/list", ""), 400, codeInvalidParams},
		{"no version in _meta", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{}}}`), nil, 400, codeInvalidParams},
		{"no capabilities in _meta", []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"x"}}}`), nil, 400, codeInvalidParams},
		{"no version header", message("tools/list", nil, true), http.Header{}, 400, codeHeaderMismatch},
		{"a contradicting header", message("tools/list", nil, true), wrongVersion, 400, codeHeaderMismatch},
		{"an unsupported version", oldMeta, http.Header{"Mcp-Protocol-Version": {"2027-01-01"}}, 400, codeUnsupportedVersion},
		{"no method header", message("tools/list", nil, true), http.Header{"Mcp-Protocol-Version": {ProtocolVersion}}, 400, codeHeaderMismatch},
		{"another method header", message("tools/list", nil, true), profileHeaders("tools/call", ""), 400, codeHeaderMismatch},
		{"no name header", message("tools/call", map[string]any{"name": "x"}, true), profileHeaders("tools/call", ""), 400, codeHeaderMismatch},
		{"another name", message("tools/call", map[string]any{"name": "x"}, true), profileHeaders("tools/call", "y"), 400, codeHeaderMismatch},
		{"bad base64 name", message("tools/call", map[string]any{"name": "x"}, true), profileHeaders("tools/call", "=?base64?!!?="), 400, codeHeaderMismatch},
		{"a removed method", message("ping", nil, true), profileHeaders("ping", ""), 404, codeMethodNotFound},
		{"an unknown method", message("nope", nil, true), profileHeaders("nope", ""), 404, codeMethodNotFound},
		{"an unknown tool", message("tools/call", map[string]any{"name": "x"}, true), profileHeaders("tools/call", "=?base64?eA==?="), 400, codeInvalidParams},
		{"an unknown resource", message("resources/read", map[string]any{"uri": "polaris://x"}, true), profileHeaders("resources/read", "polaris://x"), 400, codeResourceNotFound},
	}
	for _, tc := range cases {
		status, body := p.stateless(ctx, tc.body, tc.h, caller{})
		var reply struct {
			Error struct{ Code int } `json:"error"`
		}
		_ = json.Unmarshal(body, &reply)
		if status != tc.status || reply.Error.Code != tc.code {
			t.Errorf("%s: %d %s", tc.name, status, body)
		}
	}
	for name, tc := range map[string]struct {
		body   string
		status int
	}{
		"a notification":         {`{"jsonrpc":"2.0","method":"notifications/cancelled"}`, 202},
		"a removed notification": {`{"jsonrpc":"2.0","method":"notifications/initialized"}`, 400},
	} {
		if status, body := p.stateless(ctx, []byte(tc.body), nil, caller{}); status != tc.status || body != nil {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	if status, _ := p.stateless(ctx, make([]byte, maxBodySize+1), nil, caller{}); status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d", status)
	}
}

func TestTheStatelessProfileStampsItsResults(t *testing.T) {
	p := testPlugin(t)
	status, body := p.stateless(context.Background(), message("server/discover", nil, true), profileHeaders("server/discover", ""), caller{})
	var reply struct {
		Result map[string]any `json:"result"`
	}
	_ = json.Unmarshal(body, &reply)
	if status != 200 || reply.Result["resultType"] != "complete" || reply.Result["cacheScope"] != "private" ||
		reply.Result["supportedVersions"].([]any)[0] != ProtocolVersion {
		t.Fatalf("discover: %d %s", status, body)
	}
	status, body = p.stateless(context.Background(), message("resources/list", nil, true), profileHeaders("resources/list", ""), caller{})
	if status != 200 || json.Unmarshal(body, &reply) != nil || reply.Result["ttlMs"] != float64(0) {
		t.Fatalf("resources/list: %d %s", status, body)
	}
}

func TestSchemasFoldTheQueryAndPathParameters(t *testing.T) {
	p := testPlugin(t)
	s := p.schemas()["polaris.audit.organization"]
	got, _ := json.Marshal(s.input)
	want := `"id":{"type":"string","description":"path parameter"}`
	if !json.Valid(got) || !strings.Contains(string(got), want) || !strings.Contains(string(got), `"limit":{"type":"integer","description":"query parameter"}`) ||
		!strings.Contains(string(got), `"required":["id"]`) {
		t.Errorf("audit.organization input: %s", got)
	}
	me, _ := json.Marshal(p.schemas()["polaris.auth.me"].input)
	if string(me) != `{"type":"object","properties":[]}` {
		t.Errorf("auth.me input: %s", me)
	}
	out, _ := json.Marshal(p.schemas()["polaris.auth.me"].output)
	if !strings.Contains(string(out), `"email":{"type":"string"}`) {
		t.Errorf("auth.me output: %s", out)
	}
	if fallback := outputSchema(&manifest.Route{}, nil); fallback == nil {
		t.Error("no operation still has an output schema")
	}
}

func TestDispatchHelpers(t *testing.T) {
	if decoded(nil) != nil || decoded([]byte("plain")) != "plain" || decoded([]byte("null")) != "null" {
		t.Error("decoded")
	}
	for v, want := range map[any]string{"a": "a", json.Number("3"): "3", 1.5: "1.5", true: "1", false: "", nil: ""} {
		if got := scalar(v); got != want {
			t.Errorf("scalar(%v) = %q", v, got)
		}
	}
	if text("x") != "x" || text(map[string]any{"a": 1}) != "{\n    \"a\": 1\n}" {
		t.Error("text")
	}
	if d := definition(wiring.Tool{}); d["inputSchema"] == nil {
		t.Error("a tool without a schema gets an object schema")
	}
}
