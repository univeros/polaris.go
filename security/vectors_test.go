package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Known-answer vectors: testdata/vectors/{argon2id,pepper,encrypter}.json hold hashes, digests and
// payloads recorded once (the generator field names the implementation that made them) that every
// version of Polaris must keep verifying, so stored passwords, secrets and ciphertexts stay
// readable across releases.

type argon2Hash struct {
	Password    string `json:"password"`
	Hash        string `json:"hash"`
	NeedsRehash bool   `json:"needs_rehash"`
}

type argon2Vectors struct {
	Generator string       `json:"generator"`
	Hashes    []argon2Hash `json:"hashes"`
}

type pepperCase struct {
	Context string `json:"context"`
	Value   string `json:"value"`
	Hash    string `json:"hash"`
}

type pepperVectors struct {
	Generator string       `json:"generator"`
	AppKey    string       `json:"app_key"`
	Cases     []pepperCase `json:"cases"`
}

type encrypterCase struct {
	AppKey    string `json:"app_key"`
	Plaintext string `json:"plaintext"`
	Payload   string `json:"payload"`
}

type encrypterVectors struct {
	Generator string          `json:"generator"`
	Cases     []encrypterCase `json:"cases"`
}

func TestArgon2idVectors(t *testing.T) {
	var v argon2Vectors
	readVector(t, "argon2id.json", &v)
	if len(v.Hashes) == 0 {
		t.Fatal("no vectors")
	}
	h := Argon2id{}
	for _, e := range v.Hashes {
		if !h.Verify(e.Password, e.Hash) {
			t.Errorf("recorded hash of %q does not verify: %s", e.Password, e.Hash)
		}
		if h.Verify(e.Password+"x", e.Hash) {
			t.Errorf("wrong password verifies against %s", e.Hash)
		}
		if got := h.NeedsRehash(e.Hash); got != e.NeedsRehash {
			t.Errorf("NeedsRehash(%s) = %v, recorded %v", e.Hash, got, e.NeedsRehash)
		}
	}
}

func TestPepperVectors(t *testing.T) {
	var v pepperVectors
	readVector(t, "pepper.json", &v)
	p, err := NewPepper(v.AppKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v.Cases {
		if got := p.Hash(c.Context, c.Value); got != c.Hash {
			t.Errorf("Hash(%q, %q) = %s, want %s", c.Context, c.Value, got, c.Hash)
		}
		if !p.Matches(c.Context, c.Value, c.Hash) {
			t.Errorf("Matches rejects the recorded digest for %q", c.Value)
		}
	}
}

func TestEncrypterVectors(t *testing.T) {
	var v encrypterVectors
	readVector(t, "encrypter.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Cases {
		e, err := NewXChaCha20Poly1305(c.AppKey)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := e.Decrypt(c.Payload); err != nil || got != c.Plaintext {
			t.Errorf("Decrypt(recorded payload) = %q, %v; want %q", got, err, c.Plaintext)
		}
	}
}

func readVector(t testing.TB, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
