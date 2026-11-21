package agents_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// The environment of upstream's AgentsTestCase (over OAuthTestCase).
const (
	phpLifecycle = `Polaris\Agents\Tests\Functional\AgentsLifecycleTest`
	phpTokens    = `Polaris\Agents\Tests\Functional\AgentTokensTest`
	phpSecurity  = `Polaris\Agents\Tests\Functional\AgentsSecurityTest`
	password     = "correct horse battery staple"
	base         = "https://auth.polaris.test"
	approveURL   = "https://app.polaris.test/agents/approve"
	location     = "https://host.polaris.test/invite"
	exchangeType = "urn:ietf:params:oauth:token-type:access_token"
)

// capabilities are the suite's: one low (auto-approved), one high (step-up), one at a location,
// one spent by an amount budget.
func capabilities() []agents.Capability {
	schema := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": append([]string{}, required...), "additionalProperties": false}
	}
	str := map[string]any{"type": "string"}
	return []agents.Capability{
		{Name: "members.list", Description: "Count the members", Input: schema(map[string]any{}), Permission: "members.read", Risk: agents.RiskLow,
			Handler: func(_ context.Context, c agents.Call) (any, error) {
				return map[string]any{"members": 1, "agent": c.Agent.ID}, nil
			}},
		{Name: "org.rename", Description: "Rename the organization", Input: schema(map[string]any{"name": str}, "name"), Permission: "org.update", Risk: agents.RiskHigh,
			Handler: func(_ context.Context, c agents.Call) (any, error) {
				return map[string]any{"renamed": c.Arguments["name"]}, nil
			}},
		{Name: "audit.export", Description: "Export the audit log", Input: schema(map[string]any{"format": str}), Permission: "audit.read",
			Handler: func(_ context.Context, c agents.Call) (any, error) {
				f, ok := c.Arguments["format"]
				if !ok {
					f = "json"
				}
				return map[string]any{"format": f}, nil
			}},
		{Name: "credits.spend", Description: "Spend credits", Input: schema(map[string]any{"amount": map[string]any{"type": "number"}}, "amount"), Permission: "roles.manage",
			Handler: func(_ context.Context, c agents.Call) (any, error) {
				return map[string]any{"spent": c.Arguments["amount"]}, nil
			}},
		{Name: "invite", Description: "Invite a member at the host", Input: schema(map[string]any{"email": str}, "email"), Permission: "members.invite", Location: location},
	}
}

// agentsCase is one ported test: a booted server with audit, admin, oauth and agents, and a client
// replaying the test's fixture.
type agentsCase struct {
	t      testing.TB
	srv    *polaristest.Server
	c      *contracttest.Client
	plugin *agents.Plugin
	ctx    context.Context
}

func boot(t *testing.T) (*polaristest.Server, *agents.Plugin) {
	p := agents.New(agents.Config{Capabilities: capabilities(), ApprovalURL: approveURL, ProviderName: "Polaris test", Description: "The agents functional suite"})
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}),
		oauth.New(oauth.Config{BaseURL: base, ConsentURL: "https://app.polaris.test/consent", DeviceURL: "https://app.polaris.test/device", PollInterval: -1}), p))
	return srv, p
}

func run(t *testing.T, phpClass string, tests map[string]func(*agentsCase)) {
	t.Helper()
	dir := contracttest.Fixtures(t, "agents")
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			srv, p := boot(t)
			fx := contracttest.For(t, dir, phpClass, name)
			test(&agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx), plugin: p, ctx: context.Background()})
		})
	}
}

func (a *agentsCase) json(resp *http.Response) map[string]any { return contracttest.JSON(a.t, resp) }

func (a *agentsCase) data(resp *http.Response) map[string]any {
	m, _ := a.json(resp)["data"].(map[string]any)
	return m
}

func (a *agentsCase) list(resp *http.Response) []any {
	l, _ := a.json(resp)["data"].([]any)
	return l
}

func (a *agentsCase) login(email string) (string, string) {
	a.t.Helper()
	a.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var registered event.UserRegistered
	for _, e := range a.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			registered = r
		}
	}
	a.c.Post("/auth/email/verify", map[string]any{"token": registered.VerificationToken})
	access, _ := a.data(a.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return registered.UserID, access
}

func (a *agentsCase) organization(access, name string) (string, string) {
	a.t.Helper()
	orgID, _ := a.data(a.c.Post("/orgs", map[string]any{"name": name}, contracttest.Bearer(access)))["id"].(string)
	switched := a.c.Post("/auth/switch-org", map[string]any{"organization_id": orgID}, contracttest.Bearer(access))
	tok, _ := a.data(switched)["access_token"].(string)
	return orgID, tok
}

// registerAgent registers an agent for the session (defaults: Bot, delegated, client_secret).
func (a *agentsCase) registerAgent(session string, fields map[string]any) map[string]any {
	a.t.Helper()
	body := map[string]any{"name": "Bot", "mode": "delegated", "auth": "client_secret"}
	for k, v := range fields {
		body[k] = v
	}
	created := a.c.Post("/agents/register", body, contracttest.Bearer(session))
	if created.StatusCode != 201 {
		a.t.Fatalf("register: %d %v", created.StatusCode, a.json(created))
	}
	return a.data(created)
}

// signed sends a JSON request signed with the agent's key for the exact URL.
func (a *agentsCase) signed(k *agentKey, id, method, path string, body any, claims map[string]any) *http.Response {
	var raw []byte
	var opts []contracttest.Option
	if body != nil {
		raw, _ = json.Marshal(body)
		opts = append(opts, contracttest.Header("Content-Type", "application/json"))
	}
	opts = append(opts, contracttest.Bearer(k.requestJWT(id, base+path, claims, nil)))
	return a.c.Do(a.c.NewRequest(method, base+path, raw, opts...))
}

// bearer sends a JSON request with any bearer to the full URL.
func (a *agentsCase) bearer(tok, method, path string, body any) *http.Response {
	var raw []byte
	opts := []contracttest.Option{}
	if body != nil {
		raw, _ = json.Marshal(body)
		opts = append(opts, contracttest.Header("Content-Type", "application/json"))
	}
	if tok != "" {
		opts = append(opts, contracttest.Bearer(tok))
	}
	return a.c.Do(a.c.NewRequest(method, base+path, raw, opts...))
}

func (a *agentsCase) form(path string, fields map[string]string, opts ...contracttest.Option) *http.Response {
	values := url.Values{}
	for k, v := range fields {
		values.Set(k, v)
	}
	return a.c.Form(base+path, values, opts...)
}

// agentsProblem asserts an agents problem document; code defaults to the protocol rule.
func (a *agentsCase) agentsProblem(resp *http.Response, status int, typ, code, message string) map[string]any {
	a.t.Helper()
	body := a.json(resp)
	if code == "" {
		code = "agents_" + typ
		if slices.Contains([]string{"invalid_jwt", "aud_mismatch", "agent_inactive", "capability_not_found", "capability_not_granted", "constraint_violated", "budget_exhausted", "unknown_constraint_operator"}, typ) {
			code = typ
		}
	}
	if resp.StatusCode != status || resp.Header.Get("Content-Type") != "application/problem+json" ||
		body["type"] != "https://polaris.univeros.io/problems/agents/"+typ || body["error"] != code {
		a.t.Errorf("%s: want %d %s/%s, got %d %v", message, status, typ, code, resp.StatusCode, body)
	}
	return body
}

// problem asserts an oauth problem.
func (a *agentsCase) problem(resp *http.Response, status int, code, message string) {
	a.t.Helper()
	body := a.json(resp)
	if resp.StatusCode != status || body["error"] != code {
		a.t.Errorf("%s: want %d %s, got %d %v", message, status, code, resp.StatusCode, body)
	}
}

func (a *agentsCase) status(resp *http.Response, want int, message string) {
	a.t.Helper()
	if resp.StatusCode != want {
		a.t.Errorf("%s: want %d, got %d %v", message, want, resp.StatusCode, a.json(resp))
	}
}

func (a *agentsCase) equal(got, want any, message string) {
	a.t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		a.t.Errorf("%s: got %s, want %s", message, g, w)
	}
}

// audited reads the audit store for names, newest first.
func (a *agentsCase) audited(names ...string) []audit.Event {
	a.t.Helper()
	page, err := audit.Of(a.srv.Graph()).Store().Read(a.ctx, audit.Query{Names: names, Limit: 100})
	if err != nil {
		a.t.Fatal(err)
	}
	return page.Events
}

func (a *agentsCase) grantOwner(userID string) {
	a.t.Helper()
	if _, err := admin.Of(a.srv.Graph()).Grants().Grant(a.ctx, admin.Grant{UserID: userID, Role: admin.RoleOwner}); err != nil {
		a.t.Fatal(err)
	}
}

func str(v any) string { s, _ := v.(string); return s }

func obj(v any) map[string]any { m, _ := v.(map[string]any); return m }

func at(v any, i int) map[string]any {
	l, _ := v.([]any)
	if i >= len(l) {
		return nil
	}
	return obj(l[i])
}

func column(v any, key string) []any {
	out := []any{}
	l, _ := v.([]any)
	for _, item := range l {
		out = append(out, obj(item)[key])
	}
	return out
}

func basic(id, secret string) contracttest.Option {
	return contracttest.Header("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
}

// claims decodes a JWT's payload, unverified.
func claims(jwt string) map[string]any {
	parts := bytes.Split([]byte(jwt), []byte("."))
	if len(parts) != 3 {
		return map[string]any{}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(parts[1]))
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// agentKey is what an agent holds in the tests: a P-256 (ES256) or Ed25519 (EdDSA) key.
type agentKey struct {
	alg string
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
}

func newKey(alg string) *agentKey {
	k := &agentKey{alg: alg}
	if alg == "EdDSA" {
		_, k.ed, _ = ed25519.GenerateKey(rand.Reader)
		return k
	}
	k.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k
}

func (k *agentKey) jwk() map[string]any {
	if k.alg == "EdDSA" {
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(k.ed.Public().(ed25519.PublicKey))}
	}
	pad := func(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return b64(b) }
	return map[string]any{"kty": "EC", "crv": "P-256", "x": pad(k.ec.X), "y": pad(k.ec.Y)}
}

func (k *agentKey) kid() string {
	tp, _ := oauth.Thumbprint(k.jwk())
	return tp
}

func (k *agentKey) sign(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	if k.alg == "EdDSA" {
		return input + "." + b64(ed25519.Sign(k.ed, []byte(input)))
	}
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, k.ec, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

func jti() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b64(b)
}

// requestJWT is an agent+jwt for the URL; claims and headers override or add.
func (k *agentKey) requestJWT(agentID, u string, extra, headers map[string]any) string {
	now := time.Now().Unix()
	payload := map[string]any{"sub": agentID, "aud": u, "iat": now, "exp": now + 120, "jti": jti()}
	for n, v := range extra {
		payload[n] = v
	}
	header := map[string]any{"typ": "agent+jwt", "alg": k.alg}
	for n, v := range headers {
		header[n] = v
	}
	return k.sign(header, payload)
}

// assertion is a private_key_jwt client assertion signed with the agent's key and kid.
func (k *agentKey) assertion(agentID, audience string) string {
	now := time.Now().Unix()
	return k.sign(map[string]any{"typ": "JWT", "alg": k.alg, "kid": k.kid()},
		map[string]any{"iss": agentID, "sub": agentID, "aud": audience, "jti": jti(), "iat": now, "exp": now + 300})
}

func bodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return b64(sum[:])
}

var _ = fmt.Sprint
