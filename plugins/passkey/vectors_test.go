package passkey

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// testdata/vectors/passkey.json holds registrations recorded once (ES256 and RS256), the row each
// one stored, and an assertion of that credential. Every release must store the same row from the
// registration and verify the assertion against the stored row: users' passkeys live in that row
// and nowhere else (docs/stored-formats.md).
func TestPasskeyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "passkey.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		RPID  string `json:"rp_id"`
		Cases []struct {
			Name         string `json:"name"`
			Registration string `json:"registration"`
			Assertion    string `json:"assertion"`
			UserHandle   string `json:"user_handle"`
			Stored       struct {
				CredentialID   string   `json:"credential_id"`
				PublicKey      string   `json:"public_key"`
				Counter        uint32   `json:"counter"`
				AAGUID         string   `json:"aaguid"`
				Transports     []string `json:"transports"`
				BackupEligible bool     `json:"backup_eligible"`
				BackedUp       bool     `json:"backed_up"`
			} `json:"stored"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Cases) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	s := settings{rpID: v.RPID, userVerification: UVRequired}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			st := c.Stored
			reg, ok := parseCredential(c.Registration)
			if !ok {
				t.Fatal("registration does not parse")
			}
			a, err := s.attest(reg)
			if err != nil {
				t.Fatal(err)
			}
			got := attested{credentialID: st.CredentialID, publicKey: st.PublicKey, counter: st.Counter, aaguid: st.AAGUID,
				transports: st.Transports, backupEligible: st.BackupEligible, backedUp: st.BackedUp, userVerified: true}
			if !reflect.DeepEqual(a, got) {
				t.Fatalf("stored row\n got %+v\nwant %+v", a, got)
			}
			pk := record{CredentialID: st.CredentialID, PublicKey: st.PublicKey, Counter: int64(st.Counter), BackupEligible: st.BackupEligible}
			asr, ok := parseCredential(c.Assertion)
			if !ok {
				t.Fatal("assertion does not parse")
			}
			if _, err := s.assert(asr, pk, c.UserHandle); err != nil {
				t.Fatalf("the recorded assertion no longer verifies: %v", err)
			}
			pk.Counter = 1 << 20
			if _, err := s.assert(asr, pk, c.UserHandle); err == nil {
				t.Fatal("a counter that did not move forward verifies")
			}
		})
	}
}
