package agents_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
)

// An agent signs in and acts within its grants: the host declares two capabilities (one run by a
// handler at POST /agents/execute, one at a host route guarded by Protect), an owner registers an
// agent with its public key, the policy approves the low-risk grants, and the agent calls both
// with signed request JWTs. Every execution writes a signed receipt.
func Example() {
	ctx := context.Background()
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"

	// 1. Declare the capabilities: plain Go funcs, or a host route (Location) guarded by Protect.
	ag := agents.New(agents.Config{Capabilities: []agents.Capability{
		{Name: "members.count", Description: "Count the members", Permission: "members.read", Risk: agents.RiskLow,
			Handler: func(ctx context.Context, call agents.Call) (any, error) {
				return map[string]any{"members": 1}, nil
			}},
		{Name: "invite", Description: "Invite a member", Permission: "members.invite", Risk: agents.RiskLow,
			Location: "https://app.example.com/invitations",
			Input:    map[string]any{"type": "object", "properties": map[string]any{"email": map[string]any{"type": "string"}}, "required": []string{"email"}}},
	}})
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(), // sqlstore.Open(...) in production
		Plugins: []polaris.Plugin{oauth.New(oauth.Config{}), ag},
	})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := p.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	// 2. Mount Polaris and protect the host route bound to its capability: the grant, constraints
	// and budget are checked before the handler runs.
	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // every Polaris route, /.well-known/agent-configuration included
	mux.Handle("POST /invitations", ag.Protect("invite", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call, _ := agents.CallFrom(r.Context())
		fmt.Fprintf(w, "invited %s, %d invitations left", call.Arguments["email"], *call.Grant.BudgetRemaining)
	})))

	// The owner: a user with an organization, signed in (POST /auth/login in a real flow).
	g := p.Graph()
	now := time.Now()
	_ = g.Repos().Users.Insert(ctx, model.User{ID: "user-1", Email: "ada@example.com", EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now})
	org, _ := p.Orgs().Create(ctx, "user-1", "Acme", "")
	session, _ := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: "user-1", OrganizationID: org.ID, Roles: []string{"owner"}, EmailVerified: true}, token.ClientContext{})

	// 3. The owner registers the agent with its public key; the low-risk grants are approved by policy.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registered := call(mux, "POST", "https://app.example.com/agents/register", session.AccessToken, map[string]any{
		"name": "Inviter", "mode": "delegated", "auth": "private_key_jwt", "jwk": publicJWK(key),
		"capabilities": []string{"members.count", "invite"},
	})
	agentID := registered["data"].(map[string]any)["id"].(string)

	// 4. The agent executes, signing each request for the exact URL it calls.
	executed := call(mux, "POST", "https://app.example.com/agents/execute", signRequest(key, agentID, "https://app.example.com/agents/execute"),
		map[string]any{"capability": "members.count", "arguments": map[string]any{}})
	fmt.Println(executed["data"], executed["receipt"].(map[string]any)["seq"])

	body, _ := json.Marshal(map[string]any{"email": "bob@example.com"})
	r := httptest.NewRequest("POST", "https://app.example.com/invitations", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+signRequest(key, agentID, "https://app.example.com/invitations"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	fmt.Println(w.Code, w.Body.String(), w.Header().Get(agents.ReceiptHeader) != "")
	// Output:
	// map[members:1] 1
	// 200 invited bob@example.com, 99 invitations left true
}

func call(h http.Handler, method, url, bearer string, body any) map[string]any {
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, url, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

// publicJWK and signRequest are what the Go agent SDK does for an agent.
func publicJWK(k *ecdsa.PrivateKey) map[string]any {
	pad := func(n *big.Int) string {
		b := make([]byte, 32)
		n.FillBytes(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return map[string]any{"kty": "EC", "crv": "P-256", "x": pad(k.X), "y": pad(k.Y)}
}

func signRequest(k *ecdsa.PrivateKey, agentID, aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	header, _ := json.Marshal(map[string]any{"typ": agents.RequestJWTType, "alg": "ES256"})
	now := time.Now().Unix()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	claims, _ := json.Marshal(map[string]any{"sub": agentID, "aud": aud, "iat": now, "exp": now + 60, "jti": enc(jti)})
	input := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, k, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc(sig)
}

// Discovery chooses the document at the one well-known path an origin has. With DiscoveryAgentAuth a
// client of the Agent Auth Protocol (@auth/agent) finds the server there; the Go agent SDK finds
// Polaris's own document at /agents/configuration.
func ExampleConfig_discovery() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"
	ag := agents.New(agents.Config{
		Discovery: agents.DiscoveryAgentAuth,
		Capabilities: []agents.Capability{{Name: "members.count", Description: "Count the members", Permission: "members.read", Risk: agents.RiskLow,
			Handler: func(context.Context, agents.Call) (any, error) { return map[string]any{"members": 1}, nil }}},
	})
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(), // sqlstore.Open(...) in production
		Plugins: []polaris.Plugin{oauth.New(oauth.Config{}), ag},
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, path := range []string{"/.well-known/agent-configuration", "/agents/configuration", "/capability/list"} {
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		var doc struct {
			Issuer       string
			Endpoints    map[string]string
			Capabilities []map[string]any
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			log.Fatal(err)
		}
		fmt.Println(path, doc.Issuer, doc.Endpoints["capabilities"], doc.Capabilities)
	}
	// Output:
	// /.well-known/agent-configuration https://app.example.com /capability/list []
	// /agents/configuration https://app.example.com https://app.example.com/agents/capabilities []
	// /capability/list   [map[description:Count the members name:members.count]]
}
