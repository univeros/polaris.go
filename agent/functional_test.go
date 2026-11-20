package agent_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/univeros/polaris-go/agent"
)

// TestWalkthrough is upstream's tests/Functional/WalkthroughTest against a real Polaris server
// (PHP today; the Go server once plugins/agents is ported, when it will boot one with polaristest
// instead). It runs when these are set, and is skipped otherwise:
//
//	POLARIS_AGENT_SERVER      where Polaris is mounted, e.g. https://app.example.com/auth
//	POLARIS_ENROLLMENT_TOKEN  a host's peh_ token (POST /agents/hosts)
//	POLARIS_AGENT_CAPABILITY  a capability the policy auto-approves (default demo.echo)
//	POLARIS_OWNER_TOKEN       optional: the owner's access token, to list and verify the receipts
func TestWalkthrough(t *testing.T) {
	server, enrollment := os.Getenv("POLARIS_AGENT_SERVER"), os.Getenv("POLARIS_ENROLLMENT_TOKEN")
	if server == "" || enrollment == "" {
		t.Skip("set POLARIS_AGENT_SERVER and POLARIS_ENROLLMENT_TOKEN to run against a Polaris server")
	}
	capability := os.Getenv("POLARIS_AGENT_CAPABILITY")
	if capability == "" {
		capability = "demo.echo"
	}
	t.Run("testAnAgentEnrolsGetsItsGrantExecutesAndVerifiesItsReceiptChain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
		defer cancel()
		key, err := agent.GenerateKey(agent.EdDSA)
		if err != nil {
			t.Fatal(err)
		}
		a, err := agent.New(ctx, server, agent.WithKey(key))
		if err != nil {
			t.Fatal(err)
		}
		bot, enrolled, err := a.Enroll(ctx, enrollment, agent.Registration{Name: "Go walkthrough", Mode: agent.Delegated})
		if err != nil {
			t.Fatal(err)
		}
		if enrolled.PublicJWK == nil || enrolled.PublicJWK.Kid != key.KID() || enrolled.PublicJWK.Alg != "EdDSA" {
			t.Fatalf("enrolled %+v", enrolled)
		}
		asked, err := bot.RequestGrants(ctx, agent.GrantRequest{Capabilities: []agent.CapabilityRequest{{Name: capability}}, Reason: "The walkthrough"})
		if err != nil {
			t.Fatal(err)
		}
		if asked.Approval != nil {
			t.Logf("approve at %s", asked.Approval.VerificationURIComplete)
			if _, err := bot.WaitForApproval(ctx, *asked.Approval); err != nil {
				t.Fatal(err)
			}
		}
		first, err := bot.Execute(ctx, capability, map[string]string{"message": "hello"})
		if err != nil {
			t.Fatal(err)
		}
		second, err := bot.Execute(ctx, capability, map[string]string{"message": "again"})
		if err != nil || second.Receipt.Seq != first.Receipt.Seq+1 {
			t.Fatalf("second execution %+v, %v", second, err)
		}
		me, err := bot.Session(ctx)
		if err != nil || me.AuthenticatedVia != "jwt" {
			t.Fatalf("session %+v, %v", me, err)
		}

		owner := os.Getenv("POLARIS_OWNER_TOKEN")
		if owner == "" {
			return
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, bot.Configuration().Mount+"/agents/"+bot.ID()+"/receipts", nil)
		req.Header.Set("Authorization", "Bearer "+owner)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var chain struct {
			Data []agent.Receipt `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&chain); err != nil || len(chain.Data) < 2 {
			t.Fatalf("chain %+v, %v", chain, err)
		}
		var previous *agent.Receipt
		for i, r := range chain.Data {
			got, err := bot.VerifyReceipt(ctx, r, previous)
			if err != nil || !got.Valid {
				t.Fatalf("receipt %d: %+v, %v", i, got, err)
			}
			previous = &chain.Data[i]
		}
	})
}
