package agents_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// BenchmarkExecute is POST /agents/execute end to end on SQLite: agent authentication, grant and
// budget check, input schema validation, the capability handler, the hash-chained receipt and the
// audit record, in one transaction. "delegated_token" presents an access token from the RFC 8693
// exchange; "private_key_jwt" signs a fresh EdDSA request JWT (htm, htu, body_hash, unique jti)
// per call, the signing included in the time.
func BenchmarkExecute(b *testing.B) {
	p := agents.New(agents.Config{Capabilities: capabilities(), ApprovalURL: approveURL,
		AutoApprove: map[string]agents.Budget{agents.RiskLow: {}}}) // unbudgeted: the loop never exhausts it
	srv := polaristest.New(b, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}),
		oauth.New(oauth.Config{BaseURL: base, ConsentURL: "https://app.polaris.test/consent", DeviceURL: "https://app.polaris.test/device", PollInterval: -1}), p),
		polaristest.WithAuth(func(a *config.Auth) { a.RateLimits.Authenticated.Limit, a.RateLimits.TokenRefresh.Limit = 1<<30, 1<<30 }))
	a := &agentsCase{t: b, srv: srv, c: contracttest.NewClient(b, srv.Handler(), nil), plugin: p, ctx: context.Background()}
	_, session := a.login("ada@example.com")
	orgID, session := a.organization(session, "Acme")
	body := map[string]any{"capability": "members.list", "arguments": map[string]any{}}
	delegated := str(a.registerAgent(session, map[string]any{"name": "Delegated", "auth": "delegated_token", "organization_id": orgID, "capabilities": []any{"members.list"}})["id"])
	tok := str(a.json(a.exchangeFor(delegated, session))["access_token"])
	key := newKey("EdDSA")
	signed := str(a.registerAgent(session, map[string]any{"name": "Signed", "auth": "private_key_jwt", "jwk": key.jwk(), "capabilities": []any{"members.list"}})["id"])

	b.Run("delegated_token", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if resp := a.bearer(tok, http.MethodPost, "/agents/execute", body); resp.StatusCode != http.StatusOK {
				b.Fatalf("execute: %d %v", resp.StatusCode, a.json(resp))
			}
		}
	})
	b.Run("private_key_jwt", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if resp := a.signed(key, signed, http.MethodPost, "/agents/execute", body, nil); resp.StatusCode != http.StatusOK {
				b.Fatalf("execute: %d %v", resp.StatusCode, a.json(resp))
			}
		}
	})
}
