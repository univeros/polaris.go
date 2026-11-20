package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// Port of PolarisAgentTest.

func registered() map[string]any {
	return map[string]any{"id": "agent-1", "owner_type": "user", "owner_id": "u1", "name": "Bot", "mode": "delegated", "host_id": "h1", "auth": "private_key_jwt",
		"status": "active", "created_at": "2026-10-10T10:00:00+00:00", "updated_at": "2026-10-10T10:00:00+00:00", "grants": []any{grant(nil)}, "approval": nil}
}

func jsonBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(r.Body), &out); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	return out
}

func sameJSON(t *testing.T, got any, want string) {
	t.Helper()
	g, _ := json.Marshal(got)
	var a, b any
	_ = json.Unmarshal(g, &a)
	if err := json.Unmarshal([]byte(want), &b); err != nil {
		t.Fatal(err)
	}
	ga, _ := json.Marshal(a)
	gb, _ := json.Marshal(b)
	if string(ga) != string(gb) {
		t.Fatalf("got %s\nwant %s", ga, gb)
	}
}

func TestPolarisAgent(t *testing.T) {
	t.Run("testItDiscoversTheConfigurationUnderTheMountOrAtTheDocumentsUrl", func(t *testing.T) {
		f := newFakeServer(t)
		config, err := Discover(t.Context(), f.mount()+"/", f.Client())
		if err != nil {
			t.Fatal(err)
		}
		got := []string{config.Mount, config.TokenEndpoint, config.MCPEndpoint(), config.ProviderName, config.Issuer, config.ApprovalStrengths["high"]}
		if !slices.Equal(got, []string{f.mount(), f.mount() + "/oauth2/token", f.mount() + "/mcp", "Polaris test", "https://auth.polaris.test", "step_up"}) {
			t.Fatalf("configuration %v", got)
		}
		if _, ok := config.Endpoints["ignored"]; ok {
			t.Fatal("a non-string endpoint kept")
		}
		a, err := New(t.Context(), f.mount()+DiscoveryPath, WithHTTPClient(f.Client()))
		if err != nil || a.Configuration().Mount != f.mount() || a.ID() != "" {
			t.Fatalf("New: %v", err)
		}
		if f.requests[0].URL != f.mount()+DiscoveryPath || f.requests[1].URL != f.mount()+DiscoveryPath {
			t.Fatalf("calls %v", f.requests)
		}

		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"issuer": "x"}) }))
		defer other.Close()
		if _, err := Discover(t.Context(), other.URL, nil); !errors.Is(err, ErrNotConfiguration) {
			t.Fatalf("not a configuration: %v", err)
		}
	})

	t.Run("testItEnrolsWithTheHostsTokenAndItsPublicJwkThenSignsEveryCallForItsExactUrlAndBody", func(t *testing.T) {
		key, _ := GenerateKey(ES256)
		f := newFakeServer(t)
		f.answer(201, map[string]any{"data": registered()}).
			answer(200, map[string]any{"data": map[string]any{"hello": "world"}, "receipt": map[string]any{"id": "r1", "seq": 1, "hash": "h"}}).
			answer(200, map[string]any{"data": map[string]any{"grants": []any{grant(nil)}}})
		sdk := testAgent(t, f, WithKey(key))
		if sdk.ID() != "" {
			t.Fatal("bound before enrolling")
		}

		bot, enrolled, err := sdk.Enroll(t.Context(), "peh_token", Registration{Name: "Bot", Mode: Delegated, OrganizationID: "dropped"})
		if err != nil {
			t.Fatal(err)
		}
		if enrolled.Grants[0].Capability != "demo.echo" || enrolled.Grants[0].Budget.Remaining != 100 || bot.ID() != "agent-1" || sdk.ID() != "" {
			t.Fatalf("enrolled %+v", enrolled)
		}
		r := f.last()
		if r.Method != "POST" || r.URL != f.mount()+"/agents/enroll" || r.Header.Get("Authorization") != "Bearer peh_token" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request %+v", r)
		}
		jwk, _ := json.Marshal(key.PublicJWK())
		sameJSON(t, jsonBody(t, r), fmt.Sprintf(`{"name":"Bot","mode":"delegated","auth":"private_key_jwt","jwk":%s}`, jwk))

		executed, err := bot.Execute(t.Context(), "demo.echo", map[string]string{"hello": "world"}, "demo.echo")
		if err != nil {
			t.Fatal(err)
		}
		var data struct{ Hello string }
		if json.Unmarshal(executed.Data, &data) != nil || data.Hello != "world" || executed.Receipt.ID != "r1" {
			t.Fatalf("executed %+v", executed)
		}
		r = f.last()
		if r.Body != `{"capability":"demo.echo","arguments":{"hello":"world"}}` {
			t.Fatalf("body %s", r.Body)
		}
		h, c := decodeJWT(t, bearer(r))
		sum := sha256.Sum256([]byte(r.Body))
		if h["typ"] != "agent+jwt" || c["sub"] != "agent-1" || c["aud"] != f.mount()+"/agents/execute" || c["htm"] != "POST" || c["body_hash"] != b64(sum[:]) || fmt.Sprint(c["capabilities"]) != "[demo.echo]" {
			t.Fatalf("claims %v", c)
		}
		if !verifiesWith(bearer(r), key.PublicJWK()) {
			t.Fatal("does not verify with the public JWK")
		}

		if _, err := bot.Session(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, c = decodeJWT(t, bearer(f.last()))
		if c["aud"] != f.mount()+"/agents/session" || c["htm"] != "GET" || c["body_hash"] != nil {
			t.Fatalf("session claims %v", c)
		}
		f.answer(200, map[string]any{"data": map[string]any{}, "receipt": map[string]any{}})
		for _, args := range []any{nil, map[string]any(nil), struct{}{}} {
			if _, err := bot.Execute(t.Context(), "demo.echo", args); err != nil {
				t.Fatal(err)
			}
			if body := f.last().Body; body != `{"capability":"demo.echo","arguments":{}}` {
				t.Fatalf("empty arguments are an object: %s", body)
			}
		}
		if _, err := sdk.Execute(t.Context(), "demo.echo", nil); !errors.Is(err, ErrNotRegistered) {
			t.Fatalf("unbound: %v", err)
		}
		if _, err := bot.Execute(t.Context(), "demo.echo", func() {}); err == nil {
			t.Fatal("unencodable arguments")
		}
	})

	t.Run("testItRegistersThroughTheOwnerWithASecretWhenItHasNoKeyAndAsksForGrantsInAapsShape", func(t *testing.T) {
		f := newFakeServer(t)
		reg := registered()
		reg["auth"], reg["client_secret"] = "client_secret", "pcs_x"
		f.answer(201, map[string]any{"data": reg}).answer(200, map[string]any{"agent_id": "agent-1", "agent_capability_grants": []any{}, "approval": nil})
		sdk := testAgent(t, f)
		bot, rec, err := sdk.Register(t.Context(), "owner-token", Registration{Name: "Bot", Mode: Autonomous, OrganizationID: "o1", Capabilities: []CapabilityRequest{{Name: "demo.echo"}}})
		if err != nil || rec.ClientSecret != "pcs_x" || bot.clientSecret != "pcs_x" {
			t.Fatalf("registered %+v, %v", rec, err)
		}
		sameJSON(t, jsonBody(t, f.last()), `{"name":"Bot","mode":"autonomous","organization_id":"o1","capabilities":["demo.echo"],"auth":"client_secret"}`)

		asked, err := bot.WithToken("access").RequestGrants(t.Context(), GrantRequest{
			Capabilities:    []CapabilityRequest{{Name: "org.rename", Constraints: map[string]any{"name": map[string]any{"pattern": "Acme.*"}}}},
			PreferredMethod: "device_authorization", Reason: "Rename",
		})
		if err != nil || asked.AgentID != "agent-1" || asked.Approval != nil {
			t.Fatalf("asked %+v, %v", asked, err)
		}
		r := f.last()
		if r.Method != "POST" || r.URL != f.mount()+"/agents/grants/request" || r.Header.Get("Authorization") != "Bearer access" {
			t.Fatalf("request %+v", r)
		}
		sameJSON(t, jsonBody(t, r), `{"capabilities":[{"name":"org.rename","constraints":{"name":{"pattern":"Acme.*"}}}],"preferred_method":"device_authorization","reason":"Rename"}`)
		if _, err := bot.Execute(t.Context(), "demo.echo", nil); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("no key and no access token: %v", err)
		}
		if _, _, err := sdk.Register(t.Context(), "owner-token", Registration{Name: "Bot", Mode: Autonomous, Auth: PrivateKeyJWT}); !errors.Is(err, ErrNoCredential) {
			t.Fatalf("private_key_jwt without a key: %v", err)
		}
	})

	t.Run("testItMintsTokensWithAnAssertionWithTheSecretAndByExchange", func(t *testing.T) {
		key, _ := GenerateKey(EdDSA)
		f := newFakeServer(t)
		f.answer(200, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600})
		tok, err := testAgent(t, f, WithKey(key), WithID("agent-1")).Token(t.Context(), TokenRequest{Scope: "members.read", Resource: f.mount() + "/mcp"})
		if err != nil || tok.AccessToken != "at" || tok.ExpiresIn != 3600 {
			t.Fatalf("token %+v, %v", tok, err)
		}
		r := f.last()
		form, _ := url.ParseQuery(r.Body)
		if r.Method != "POST" || r.URL != f.mount()+"/oauth2/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Fatalf("request %+v", r)
		}
		if form.Get("grant_type") != "client_credentials" || form.Get("scope") != "members.read" || form.Get("resource") != f.mount()+"/mcp" || form.Get("client_assertion_type") != AssertionType || form.Has("audience") {
			t.Fatalf("form %v", form)
		}
		_, c := decodeJWT(t, form.Get("client_assertion"))
		if c["iss"] != "agent-1" || c["sub"] != "agent-1" || c["aud"] != f.mount()+"/oauth2/token" || !verifiesWith(form.Get("client_assertion"), key.PublicJWK()) {
			t.Fatalf("assertion %v", c)
		}

		if _, err := testAgent(t, f, WithID("agent-1"), WithClientSecret("pcs_x")).Token(t.Context(), TokenRequest{SubjectToken: "user-access"}); err != nil {
			t.Fatal(err)
		}
		r = f.last()
		form, _ = url.ParseQuery(r.Body)
		if r.Header.Get("Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("agent-1:pcs_x")) {
			t.Fatalf("basic %q", r.Header.Get("Authorization"))
		}
		if form.Get("grant_type") != TokenExchange || form.Get("subject_token") != "user-access" || form.Get("subject_token_type") != AccessTokenType || form.Has("client_assertion") {
			t.Fatalf("exchange %v", form)
		}

		if _, err := testAgent(t, f, WithID("agent-1")).Token(t.Context(), TokenRequest{SubjectToken: "user-access", Audience: "x"}); err != nil {
			t.Fatal(err)
		}
		if form, _ = url.ParseQuery(f.last().Body); form.Get("client_id") != "agent-1" || form.Get("audience") != "x" {
			t.Fatalf("public client %v", form)
		}
		if _, err := testAgent(t, f).Token(t.Context(), TokenRequest{}); !errors.Is(err, ErrNotRegistered) {
			t.Fatalf("no id: %v", err)
		}
	})

	t.Run("testARefusalIsThrownWithItsProblemDocument", func(t *testing.T) {
		f := newFakeServer(t)
		f.answer(403, map[string]any{"type": "https://polaris.univeros.io/problems/agents/constraint_violated", "title": "Forbidden", "status": 403, "detail": "amount is above 50", "error": "constraint_violated",
			"violations": []any{map[string]any{"field": "amount", "constraint": "max", "actual": 60}}})
		_, err := testAgent(t, f, WithID("agent-1")).WithToken("at").Execute(t.Context(), "credits.spend", map[string]int{"amount": 60})
		var refused *Error
		if !errors.As(err, &refused) || refused.Status != 403 || refused.Code != "constraint_violated" || !errors.Is(err, ErrConstraintViolated) || errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("refusal %v", err)
		}
		p := refused.Problem
		if p == nil || p.Type != "https://polaris.univeros.io/problems/agents/constraint_violated" || p.Status != 403 || len(p.Violations) != 1 || p.Violations[0].Field != "amount" || p.Violations[0].Actual != 60.0 {
			t.Fatalf("problem %+v", p)
		}
		if !strings.Contains(err.Error(), "amount is above 50") || !strings.Contains(err.Error(), "403") {
			t.Fatalf("message %q", err)
		}
	})
}

func TestRefusalsWithoutAProblemDocument(t *testing.T) {
	for _, tc := range []struct {
		body       string
		code, text string
		problem    bool
	}{
		{`{"error":"unauthorized","message":"Sign in."}`, "unauthorized", "Sign in.", false},
		{`{"type":"t","error":"slow_down","message":"m"}`, "slow_down", "m", true},
		{`<html>bad gateway</html>`, "request_failed", "<html>bad gateway</html>", false},
	} {
		e := refusal("GET", "https://x.test/a", 502, []byte(tc.body))
		if e.Code != tc.code || !strings.HasSuffix(e.Error(), tc.text) || (e.Problem != nil) != tc.problem {
			t.Fatalf("%s: %+v %q", tc.body, e, e.Error())
		}
	}
}

func TestCapabilitiesAuthenticateOnlyWhenTheAgentCan(t *testing.T) {
	f := newFakeServer(t)
	listing := map[string]any{"data": map[string]any{"capabilities": []any{
		map[string]any{"name": "members.list", "description": "Count", "input": map[string]any{"type": "object", "properties": []any{}}, "permission": "members.read", "risk": "low", "grant_status": "active"},
		map[string]any{"name": "invite", "permission": "members.invite", "risk": "medium", "location": "https://host.polaris.test/invite", "grant_status": "none"},
	}}}
	f.answer(200, listing)
	key, _ := GenerateKey(ES256)
	caps, err := testAgent(t, f, WithKey(key)).Capabilities(t.Context())
	if err != nil || len(caps) != 2 || caps[1].Location != "https://host.polaris.test/invite" || f.last().Header.Get("Authorization") != "" {
		t.Fatalf("anonymous listing %+v, %v", caps, err)
	}
	if _, err := testAgent(t, f, WithKey(key), WithID("agent-1")).Capabilities(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, c := decodeJWT(t, bearer(f.last())); c["aud"] != f.mount()+"/agents/capabilities" {
		t.Fatalf("claims %v", c)
	}
	f2 := newFakeServer(t)
	f2.answer(200, map[string]any{"data": map[string]any{}})
	if caps, err := testAgent(t, f2).Capabilities(t.Context()); err != nil || caps == nil || len(caps) != 0 {
		t.Fatalf("empty listing %v, %v", caps, err)
	}
}

func TestWaitForApprovalPollsTheSession(t *testing.T) {
	f := newFakeServer(t)
	session := func(status string) map[string]any {
		return map[string]any{"data": map[string]any{"agent": registered(), "mode": "delegated", "owner": map[string]any{"type": "user", "id": "u1"}, "host": map[string]any{"id": "h1", "name": "Laptop"},
			"authenticated_via": "jwt", "grants": []any{grant(map[string]any{"id": "g2", "status": status, "approval_id": "ap1"})}}}
	}
	f.answer(200, session("pending")).answer(429, map[string]any{"error": "too_many_requests"}).answer(200, session("active"))
	key, _ := GenerateKey(EdDSA)
	a := testAgent(t, f, WithKey(key), WithID("agent-1"))
	clock := &fakeClock{now: time.Unix(1000, 0)}
	a.waiter = clock.waiter()
	grants, err := a.WaitForApproval(t.Context(), approvalFixture())
	if err != nil || len(grants) != 1 || grants[0].ID != "g2" || len(clock.slept) != 3 {
		t.Fatalf("grants %+v, %v, slept %v", grants, err, clock.slept)
	}
	s, err := a.Session(t.Context())
	if err != nil || s.Host.Name != "Laptop" || s.Owner.ID != "u1" || s.Agent.ID != "agent-1" || s.Grants[0].CreatedAt.Year() != 2026 {
		t.Fatalf("session %+v, %v", s, err)
	}
	f.answer(401, map[string]any{"type": "t", "error": "invalid_jwt", "detail": "no"})
	if _, err := a.WaitForApproval(t.Context(), approvalFixture()); !errors.Is(err, ErrInvalidJWT) {
		t.Fatalf("refused poll: %v", err)
	}
}

func TestVerifyReceiptFetchesTheJWKSOnce(t *testing.T) {
	server := newServerKey(t, "RS256", "server-key")
	first := signed(t, server, receiptFixture())
	f := newFakeServer(t)
	f.answer(200, map[string]any{"keys": []any{server.jwk}})
	a := testAgent(t, f)
	for range 2 {
		got, err := a.WithToken("x").VerifyReceipt(t.Context(), first, nil)
		if err != nil || !got.Valid {
			t.Fatalf("%+v, %v", got, err)
		}
	}
	jwksCalls := 0
	for _, r := range f.requests {
		if strings.HasSuffix(r.URL, "/api/auth/.well-known/jwks.json") {
			jwksCalls++
		}
	}
	if jwksCalls != 1 {
		t.Fatalf("%d JWKS fetches", jwksCalls)
	}
	f2 := newFakeServer(t)
	f2.answer(500, map[string]any{"error": "server_error"})
	if _, err := testAgent(t, f2).VerifyReceipt(t.Context(), first, nil); err == nil {
		t.Fatal("JWKS failure")
	}
}

func TestDoSignsARequestToACapabilitysLocation(t *testing.T) {
	key, _ := GenerateKey(ES256)
	var seen *http.Request
	var seenBody string
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		buf, _ := io.ReadAll(r.Body)
		seenBody = string(buf)
		w.Header().Set("X-Polaris-Receipt", "r9")
		w.WriteHeader(201)
	}))
	defer host.Close()
	f := newFakeServer(t)
	a := testAgent(t, f, WithKey(key), WithID("agent-1"), WithHTTPClient(host.Client()))

	body := `{"email":"x@acme.test"}`
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, host.URL+"/invite?via=agent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 || resp.Header.Get("X-Polaris-Receipt") != "r9" || seenBody != body || req.Header.Get("Authorization") != "" {
		t.Fatalf("status %d body %q", resp.StatusCode, seenBody)
	}
	jwt := strings.TrimPrefix(seen.Header.Get("Authorization"), "Bearer ")
	_, c := decodeJWT(t, jwt)
	sum := sha256.Sum256([]byte(body))
	if c["aud"] != host.URL+"/invite" || c["htu"] != host.URL+"/invite" || c["htm"] != "POST" || c["body_hash"] != b64(sum[:]) || !verifiesWith(jwt, key.PublicJWK()) {
		t.Fatalf("claims %v", c)
	}

	get, _ := http.NewRequest(http.MethodGet, host.URL+"/report", nil)
	if resp, err = a.WithToken("at").Do(get); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.Header.Get("Authorization") != "Bearer at" {
		t.Fatalf("access token: %q", seen.Header.Get("Authorization"))
	}
	if _, err := testAgent(t, f).Do(get); !errors.Is(err, ErrNoCredential) {
		t.Fatalf("no credential: %v", err)
	}
}

func TestNewFailsWithTheFix(t *testing.T) {
	for _, u := range []string{"app.example.com/auth", "ftp://x", "https://"} {
		if _, err := New(t.Context(), u); err == nil || !strings.Contains(err.Error(), "absolute http(s) URL") {
			t.Fatalf("%s: %v", u, err)
		}
	}
	f := newFakeServer(t)
	if _, err := New(t.Context(), f.mount(), WithRequestTTL(10*time.Minute)); err == nil || !strings.Contains(err.Error(), "300s") {
		t.Fatalf("ttl: %v", err)
	}
	if a, err := New(t.Context(), f.mount(), WithHTTPClient(nil)); err != nil || a.client != http.DefaultClient {
		t.Fatalf("nil client: %v", err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if _, err := New(t.Context(), closed.URL); err == nil {
		t.Fatal("unreachable server")
	}
	notJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("hello")) }))
	defer notJSON.Close()
	var refused *Error
	if _, err := New(t.Context(), notJSON.URL); !errors.As(err, &refused) || refused.Code != "request_failed" || !strings.Contains(err.Error(), "did not answer JSON") {
		t.Fatalf("not JSON: %v", err)
	}
}

func TestRequestGrantsSendsAListAndReturnsTheRefusal(t *testing.T) {
	f := newFakeServer(t)
	f.answer(409, map[string]any{"type": "t", "error": "agents_conflict", "detail": "five approvals wait"})
	_, err := testAgent(t, f, WithID("agent-1")).WithToken("at").RequestGrants(t.Context(), GrantRequest{})
	var refused *Error
	if !errors.As(err, &refused) || refused.Code != "agents_conflict" || f.last().Body != `{"capabilities":[]}` {
		t.Fatalf("%v, body %s", err, f.last().Body)
	}
}
