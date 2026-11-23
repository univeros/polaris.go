package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

// serverKey is a server key pair (RS256, core's default, or EdDSA/ES256) with its public JWK as the
// JWKS lists it.
type serverKey struct {
	alg    string
	signer crypto.Signer
	jwk    JWK
}

func newServerKey(t *testing.T, alg, kid string) serverKey {
	t.Helper()
	switch alg {
	case "RS256":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return serverKey{alg, k, JWK{Kty: "RSA", Use: "sig", Alg: alg, Kid: kid, N: b64(k.N.Bytes()), E: b64(big.NewInt(int64(k.E)).Bytes())}}
	case "ES256":
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, _ := NewKey(k, kid)
		return serverKey{alg, k, key.PublicJWK()}
	default:
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		key, _ := NewKey(k, kid)
		return serverKey{alg, k, key.PublicJWK()}
	}
}

// signReceipt is a receipt+jwt as the server's Receipts::sign makes it, over the given hash.
func (s serverKey) signReceipt(t *testing.T, r Receipt, hash, kid string) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"typ": ReceiptType, "alg": s.alg, "kid": kid})
	payload, _ := json.Marshal(map[string]any{"iss": "https://auth.polaris.test", "iat": 1760090400.25, "receipt_hash": hash, "receipt_id": r.ID, "agent_id": r.AgentID, "seq": r.Seq})
	input := b64(header) + "." + b64(payload)
	var sig []byte
	switch k := s.signer.(type) {
	case *rsa.PrivateKey:
		d := sha256.Sum256([]byte(input))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	case *ecdsa.PrivateKey:
		key, _ := NewKey(k, kid)
		sig, _ = key.sign([]byte(input))
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(input))
	}
	return input + "." + b64(sig)
}

func signed(t *testing.T, s serverKey, r Receipt) Receipt {
	r.Hash = ReceiptHash(r)
	r.Signature = s.signReceipt(t, r, r.Hash, "server-key")
	return r
}

func TestReceipts(t *testing.T) {
	t.Run("testItCanonicalisesAndHashesAsTheServerDoes", func(t *testing.T) {
		r := receiptFixture()
		r.Capability = ptr("café/échec")
		if got := ReceiptHash(r); got != "9b5f1f690cca6b3b9dd055a71d13ebd6f8a0a7efcd529befc560383e477f836d" {
			t.Fatalf("hash %s: not the vector every SDK computes", got)
		}
		if got, want := string(asciiJSON([]byte("{\"a\":\"\u00e9\U0001F600/<\"}"))), `{"a":"`+"\\"+`u00e9`+"\\"+`ud83d`+"\\"+`ude00/<"}`; got != want {
			t.Fatalf("ASCII escaping: %s", got)
		}
	})

	for _, alg := range []string{"RS256", "EdDSA", "ES256"} {
		t.Run("testItVerifiesAChainAgainstTheJwksAndDetectsATamperedReceipt/"+alg, func(t *testing.T) {
			server := newServerKey(t, alg, "server-key")
			keys := []JWK{{Kty: "RSA", Use: "sig", Alg: "RS256", Kid: "other", N: "AQAB", E: "AQAB"}, server.jwk}
			valid := Verification{Valid: true, Checks: Checks{true, true, true}}
			first := signed(t, server, receiptFixture())
			if got := VerifyReceipt(first, keys, nil); got != valid {
				t.Fatalf("first: %+v", got)
			}
			second := receiptFixture()
			second.ID, second.Seq, second.PrevHash, second.BudgetBefore, second.BudgetAfter = "r2", 2, ptr(first.Hash), ptr(99), ptr(98)
			second = signed(t, server, second)
			if got := VerifyReceipt(second, keys, &first); got != valid {
				t.Fatalf("second: %+v", got)
			}
			if !VerifyReceipt(second, keys, nil).Checks.Chain {
				t.Fatal("without the previous receipt only the link's presence is checked")
			}

			tampered := first
			tampered.BudgetAfter = ptr(1)
			if got := VerifyReceipt(tampered, keys, nil); got != (Verification{Checks: Checks{Chain: true}}) {
				t.Fatalf("tampered: %+v", got)
			}
			if got := VerifyReceipt(second, keys, &tampered).Checks; got != (Checks{true, true, false}) {
				t.Fatalf("the successor still links: %+v", got)
			}

			forger := newServerKey(t, alg, "server-key")
			check := func(name string, r Receipt, prev *Receipt) {
				if VerifyReceipt(r, keys, prev).Checks.Signature {
					t.Fatalf("%s: signature verifies", name)
				}
			}
			r := first
			r.Signature = forger.signReceipt(t, first, first.Hash, "server-key")
			check("another key", r, nil)
			r.Signature = server.signReceipt(t, first, first.Hash, "unknown")
			check("an unknown kid", r, nil)
			r = second
			r.Signature = first.Signature
			check("a signature of another receipt", r, &first)
			r = first
			r.Signature = "not.a.jws"
			check("garbage", r, nil)
			r.Signature = ""
			check("none", r, nil)
			r = first
			r.PrevHash = ptr("x")
			if got := VerifyReceipt(r, keys, nil).Checks; got != (Checks{}) {
				t.Fatalf("a first receipt claiming a predecessor: %+v", got)
			}
		})
	}
}

func TestASignatureMustNameItsTypeAndAKeyOfItsAlgorithm(t *testing.T) {
	server := newServerKey(t, "RS256", "server-key")
	r := signed(t, server, receiptFixture())
	wrongAlg := server.jwk
	wrongAlg.Alg = "RS512"
	if VerifyReceipt(r, []JWK{wrongAlg}, nil).Checks.Signature {
		t.Fatal("a key whose alg is not the header's")
	}
	if _, err := verifyJWS(r.Signature, RequestJWTType, []JWK{server.jwk}); err == nil {
		t.Fatal("a receipt+jwt verified as an agent+jwt")
	}
	// The claims are one JSON object: what follows it would be signed and unread.
	for payload, ok := range map[string]bool{`{"receipt_hash":"x"}`: true, `{"receipt_hash":"x"}0`: false, `{"receipt_hash":"x"}{}`: false, `null`: false} {
		input := b64([]byte(`{"typ":"`+ReceiptType+`","alg":"RS256","kid":"server-key"}`)) + "." + b64([]byte(payload))
		d := sha256.Sum256([]byte(input))
		sig, _ := rsa.SignPKCS1v15(rand.Reader, server.signer.(*rsa.PrivateKey), crypto.SHA256, d[:])
		if _, err := verifyJWS(input+"."+b64(sig), ReceiptType, []JWK{server.jwk}); (err == nil) != ok {
			t.Fatalf("%s: %v", payload, err)
		}
	}
	asEC := server.jwk
	asEC.Kty = "EC"
	if VerifyReceipt(r, []JWK{asEC}, nil).Checks.Signature {
		t.Fatal("an RS256 signature against an EC key")
	}
}

// receiptChains is testdata/receipt-chains.json: known-answer receipt chains, RS256 and EdDSA,
// signed by an earlier server release. Receipts already issued must keep verifying.
type receiptChains struct {
	Chains []struct {
		Alg      string    `json:"alg"`
		JWKS     []JWK     `json:"jwks"`
		Receipts []Receipt `json:"receipts"`
	} `json:"chains"`
}

func TestReceiptsSignedByAnEarlierServerVerify(t *testing.T) {
	data, err := os.ReadFile("testdata/receipt-chains.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors receiptChains
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Chains) == 0 {
		t.Fatal("no chains")
	}
	for _, chain := range vectors.Chains {
		var previous *Receipt
		for i, r := range chain.Receipts {
			if got := VerifyReceipt(r, chain.JWKS, previous); !got.Valid {
				t.Fatalf("%s receipt %d: %+v", chain.Alg, i, got)
			}
			tampered := r
			tampered.InputHash = "00"
			if VerifyReceipt(tampered, chain.JWKS, previous).Valid {
				t.Fatalf("%s receipt %d tampered still valid", chain.Alg, i)
			}
			previous = &chain.Receipts[i]
		}
	}
}
