package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// The shapes the unit tests share.

const mountPath = "/api"

func configurationDoc(mount string) map[string]any {
	u := func(p string) string { return mount + p }
	return map[string]any{
		"version": "1.0-draft", "provider_name": "Polaris test", "description": "The unit tests", "issuer": "https://auth.polaris.test",
		"default_location": u("/agents/execute"), "algorithms": []string{"ES256", "EdDSA"}, "modes": []string{"delegated", "autonomous"},
		"approval_methods": []string{"device_authorization", "ciba", "in_app"}, "approval_strengths": map[string]string{"low": "session", "medium": "session", "high": "step_up"},
		"endpoints": map[string]any{
			"register": u("/agents/register"), "enroll": u("/agents/enroll"), "capabilities": u("/agents/capabilities"),
			"execute": u("/agents/execute"), "request_capability": u("/agents/grants/request"), "status": u("/agents/session"),
			"revoke": u("/agents"), "grants": u("/agents/grants"), "approvals": u("/agents/approvals"), "receipts": u("/agents/receipts"),
			"token": u("/oauth2/token"), "mcp": u("/mcp"), "ignored": 3,
		},
		"token_endpoint": u("/oauth2/token"),
	}
}

func grant(fields map[string]any) map[string]any {
	g := map[string]any{
		"id": "g1", "agent_id": "a1", "capability": "demo.echo", "constraints": []any{}, "budget": map[string]any{"kind": "count", "total": 100, "remaining": 100, "field": nil},
		"status": "active", "granted_by": nil, "approved_via": "auto", "approval_id": nil, "expires_at": nil,
		"created_at": "2026-10-10T10:00:00+00:00", "updated_at": "2026-10-10T10:00:00+00:00",
	}
	for k, v := range fields {
		g[k] = v
	}
	return g
}

func approvalFixture() Approval {
	return Approval{ID: "ap1", Method: "in_app", Strength: "session", ExpiresIn: 60, Interval: 5}
}

func ptr[T any](v T) *T { return &v }

func receiptFixture() Receipt {
	return Receipt{ID: "r1", AgentID: "a1", Seq: 1, GrantID: ptr("g1"), Capability: ptr("demo.echo"), InputHash: "ab", Outcome: "success",
		BudgetBefore: ptr(100), BudgetAfter: ptr(99), CreatedAt: "2026-10-10T10:00:00+00:00"}
}

// recorded is one request the fake server saw.
type recorded struct {
	Method, URL string
	Header      http.Header
	Body        string
}

// fakeServer answers queued responses in turn (the last one again when the queue runs out) and
// keeps every request. The discovery document is served out of turn.
type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	queue    []answer
	served   int
	requests []recorded
}

type answer struct {
	status int
	body   any
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) mount() string { return f.URL + mountPath }

func (f *fakeServer) answer(status int, body any) *fakeServer {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, answer{status, body})
	return f
}

func (f *fakeServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, recorded{r.Method, "http://" + r.Host + r.URL.RequestURI(), r.Header.Clone(), string(body)})
	if strings.HasSuffix(r.URL.Path, DiscoveryPath) {
		f.mu.Unlock()
		writeJSON(w, 200, configurationDoc(f.mount()))
		return
	}
	next := answer{200, map[string]any{}}
	if len(f.queue) > 0 {
		next = f.queue[min(f.served, len(f.queue)-1)]
	}
	f.served++
	f.mu.Unlock()
	writeJSON(w, next.status, next.body)
}

func (f *fakeServer) last() recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests[len(f.requests)-1]
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	ct := "application/json"
	if status >= 400 {
		ct = "application/problem+json"
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// testAgent is an Agent on the fake server's configuration, without a discovery round trip.
func testAgent(t *testing.T, f *fakeServer, opts ...Option) *Agent {
	t.Helper()
	config, err := Discover(t.Context(), f.mount(), f.Client())
	if err != nil {
		t.Fatal(err)
	}
	a, err := build(config, append([]Option{WithHTTPClient(f.Client())}, opts...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// decodeJWT is the header and claims of a compact JWS, unverified.
func decodeJWT(t *testing.T, jws string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", jws)
	}
	for i, out := range []*map[string]any{&header, &claims} {
		data, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(data, out) != nil {
			t.Fatalf("segment %d of %q", i, jws)
		}
	}
	return header, claims
}

// rawHeader is the header segment as sent, to check member order.
func rawHeader(t *testing.T, jws string) string {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// verifiesWith reports whether the JWS signature verifies with the public JWK.
func verifiesWith(jws string, jwk JWK) bool {
	parts := strings.Split(jws, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	return verifySignature(jwk.Alg, jwk, []byte(parts[0]+"."+parts[1]), sig)
}

func bearer(r recorded) string { return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") }

// fakeClock is a clock the fake sleep advances.
type fakeClock struct {
	now   time.Time
	slept []time.Duration
}

func (c *fakeClock) waiter() waiter {
	return waiter{now: func() time.Time { return c.now }, sleep: func(ctx context.Context, d time.Duration) error {
		c.slept = append(c.slept, d)
		c.now = c.now.Add(d)
		return ctx.Err()
	}}
}
