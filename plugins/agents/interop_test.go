package agents_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/univeros/polaris-go/agent"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/agents"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/oauth"
	"github.com/univeros/polaris-go/polaristest"
)

// The Go agent SDK walks the protocol against this server: enrol through a host, ask for a
// grant the policy approves, execute with signed request JWTs, read the session and verify the
// receipt chain locally (the WP5 acceptance walkthrough). It runs with each access-token signer:
// with EdDSA the receipts are Ed25519-signed and the SDK reads the key from the OKP JWKS.
func TestTheGoAgentSDKWalksThrough(t *testing.T) {
	for _, signer := range []config.Signer{config.SignerRS256, config.SignerEdDSA} {
		t.Run(string(signer), func(t *testing.T) { walkThrough(t, signer) })
	}
}

func walkThrough(t *testing.T, signer config.Signer) {
	var handler http.Handler
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer web.Close()
	opts := []polaristest.Option{polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}),
		oauth.New(oauth.Config{BaseURL: web.URL}), agents.New(agents.Config{Capabilities: capabilities()}))}
	if signer == config.SignerEdDSA {
		pub, priv, _ := ed25519.GenerateKey(nil)
		opts = append(opts,
			polaristest.WithAuth(func(a *config.Auth) { a.AccessToken.Signer = signer }),
			polaristest.WithSecrets(func(s *config.Secrets) { s.JWTPrivateKey, s.JWTPublicKey = string(priv), string(pub) }))
	}
	srv := polaristest.New(t, opts...)
	handler = srv.Handler()
	if alg := srv.Graph().JWKS().Keys[0].Alg; alg != string(signer) {
		t.Fatalf("JWKS alg %s", alg)
	}

	ctx := context.Background()
	a := &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), ctx: ctx}
	_, session := a.login("ada@example.com")
	_, session = a.organization(session, "Acme")
	host := a.data(a.c.Post("/agents/hosts", map[string]any{"name": "Laptop"}, contracttest.Bearer(session)))

	key, err := agent.GenerateKey(agent.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := agent.New(ctx, web.URL, agent.WithKey(key))
	if err != nil {
		t.Fatal(err)
	}
	bot, enrolled, err := sdk.Enroll(ctx, str(host["enrollment_token"]), agent.Registration{Name: "Go walkthrough", Mode: agent.Delegated})
	if err != nil {
		t.Fatal(err)
	}
	if enrolled.PublicJWK == nil || enrolled.PublicJWK.Kid != key.KID() {
		t.Fatalf("enrolled %+v", enrolled)
	}
	asked, err := bot.RequestGrants(ctx, agent.GrantRequest{Capabilities: []agent.CapabilityRequest{{Name: "members.list"}}, Reason: "walkthrough"})
	if err != nil || asked.Approval != nil {
		t.Fatalf("grants %+v %v", asked, err)
	}
	first, err := bot.Execute(ctx, "members.list", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := bot.Execute(ctx, "members.list", nil)
	if err != nil || second.Receipt.Seq != first.Receipt.Seq+1 {
		t.Fatalf("second %+v %v", second, err)
	}
	if me, err := bot.Session(ctx); err != nil || me.AuthenticatedVia != "jwt" {
		t.Fatalf("session %+v %v", me, err)
	}
	if _, err := bot.Execute(ctx, "org.rename", map[string]any{"name": "X"}); err == nil {
		t.Error("an ungranted capability is refused")
	}

	resp := a.c.Get("/agents/"+bot.ID()+"/receipts", contracttest.Bearer(session))
	var chain struct {
		Data []agent.Receipt `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chain); err != nil || len(chain.Data) != 2 {
		t.Fatalf("chain %+v %v", chain, err)
	}
	var previous *agent.Receipt
	for i, r := range chain.Data {
		got, err := bot.VerifyReceipt(ctx, r, previous)
		if err != nil || !got.Valid {
			t.Fatalf("receipt %d: %+v %v", i, got, err)
		}
		previous = &chain.Data[i]
	}
}
