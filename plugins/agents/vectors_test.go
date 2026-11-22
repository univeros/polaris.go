package agents

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Stored digests are found again only under the pepper context they were written with
// (testdata/vectors/pepper.json, docs/stored-formats.md): renaming one strands every stored row.
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	if hostPepper != "agent_host" {
		t.Errorf("stored format changed: %q, recorded %q", hostPepper, "agent_host")
	}
}

// The receipt chains the agent SDK verifies (agent/testdata/receipt-chains.json, recorded from
// this plugin) hash here to the same bytes: receipts already issued keep verifying on the server
// and in every SDK only while hashOf reproduces them (docs/stored-formats.md).
func TestRecordedReceiptChainsHashAsTheyWereIssued(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "agent", "testdata", "receipt-chains.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Chains []struct {
			Alg      string `json:"alg"`
			Receipts []struct {
				ID           string  `json:"id"`
				AgentID      string  `json:"agent_id"`
				Seq          int64   `json:"seq"`
				GrantID      *string `json:"grant_id"`
				Capability   *string `json:"capability"`
				InputHash    string  `json:"input_hash"`
				Outcome      string  `json:"outcome"`
				BudgetBefore *int64  `json:"budget_before"`
				BudgetAfter  *int64  `json:"budget_after"`
				PrevHash     *string `json:"prev_hash"`
				Hash         string  `json:"hash"`
				CreatedAt    string  `json:"created_at"`
			} `json:"receipts"`
		} `json:"chains"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Chains) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	for _, c := range v.Chains {
		prev := ""
		for i, r := range c.Receipts {
			at, err := time.Parse(receiptTime, r.CreatedAt)
			if err != nil {
				t.Fatal(err)
			}
			got := hashOf(Receipt{ID: r.ID, AgentID: r.AgentID, Seq: r.Seq, GrantID: str(r.GrantID), Capability: str(r.Capability),
				InputHash: r.InputHash, Outcome: r.Outcome, BudgetBefore: r.BudgetBefore, BudgetAfter: r.BudgetAfter,
				PrevHash: str(r.PrevHash), CreatedAt: at})
			if got != r.Hash {
				t.Errorf("%s receipt %d: hash %s, recorded %s", c.Alg, i, got, r.Hash)
			}
			if str(r.PrevHash) != prev {
				t.Errorf("%s receipt %d: prev_hash %q, want %q", c.Alg, i, str(r.PrevHash), prev)
			}
			prev = r.Hash
		}
	}
}
