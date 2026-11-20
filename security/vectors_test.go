package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Cross-language vectors (spec §6.3). testdata/vectors/{argon2id,pepper,encrypter}.json come
// from scripts/vectors.php; with POLARIS_UPDATE_VECTORS=1 these tests also write go-*.json,
// which scripts/verify-vectors.php checks with upstream's classes.

const vectorAppKey = "polaris-cross-language-vector-app-key-0123456789"

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

func TestPHPArgon2idVectors(t *testing.T) {
	var v argon2Vectors
	readVector(t, "argon2id.json", &v)
	if len(v.Hashes) == 0 {
		t.Fatal("no vectors")
	}
	h := Argon2id{}
	out := argon2Vectors{Generator: "go"}
	for _, e := range v.Hashes {
		if !h.Verify(e.Password, e.Hash) {
			t.Errorf("PHP hash of %q does not verify: %s", e.Password, e.Hash)
		}
		if h.Verify(e.Password+"x", e.Hash) {
			t.Errorf("wrong password verifies against %s", e.Hash)
		}
		if got := h.NeedsRehash(e.Hash); got != e.NeedsRehash {
			t.Errorf("NeedsRehash(%s) = %v, PHP says %v", e.Hash, got, e.NeedsRehash)
		}
	}
	// Go-made hashes for PHP to verify: default cost, a low cost, two lanes.
	for _, g := range []struct {
		hasher Argon2id
		pw     string
	}{
		{Argon2id{}, "correct horse battery staple"},
		{Argon2id{Memory: 8192, Time: 1, Threads: 1}, ""},
		{Argon2id{Memory: 8192, Time: 1, Threads: 1}, "pässwörd 🔑"},
		{Argon2id{Memory: 16, Time: 2, Threads: 2}, "two-lanes"},
	} {
		hash, err := g.hasher.Hash(g.pw)
		if err != nil {
			t.Fatal(err)
		}
		out.Hashes = append(out.Hashes, argon2Hash{g.pw, hash, Argon2id{}.NeedsRehash(hash)})
	}
	writeGoVector(t, "go-argon2id.json", out)
}

func TestPHPPepperVectors(t *testing.T) {
	var v pepperVectors
	readVector(t, "pepper.json", &v)
	p, err := NewPepper(v.AppKey)
	if err != nil {
		t.Fatal(err)
	}
	out := pepperVectors{Generator: "go", AppKey: vectorAppKey}
	for _, c := range v.Cases {
		if got := p.Hash(c.Context, c.Value); got != c.Hash {
			t.Errorf("Hash(%q, %q) = %s, PHP %s", c.Context, c.Value, got, c.Hash)
		}
		if !p.Matches(c.Context, c.Value, c.Hash) {
			t.Errorf("Matches rejects PHP digest for %q", c.Value)
		}
	}
	goPepper, _ := NewPepper(vectorAppKey)
	for _, c := range []pepperCase{{"refresh", "go-refresh-token", ""}, {"otp", "654321", ""}, {"", "", ""}, {"invite", "ünïcødé ✓", ""}} {
		c.Hash = goPepper.Hash(c.Context, c.Value)
		out.Cases = append(out.Cases, c)
	}
	writeGoVector(t, "go-pepper.json", out)
}

func TestPHPEncrypterVectors(t *testing.T) {
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
			t.Errorf("Decrypt(PHP payload) = %q, %v; want %q", got, err, c.Plaintext)
		}
	}
	out := encrypterVectors{Generator: "go"}
	for _, c := range []encrypterCase{
		{AppKey: vectorAppKey, Plaintext: "JBSWY3DPEHPK3PXP"},
		{AppKey: vectorAppKey, Plaintext: ""},
		{AppKey: vectorAppKey, Plaintext: "üñí©ødé 🔐"},
		{AppKey: "k", Plaintext: "short key"},
	} {
		e, _ := NewXChaCha20Poly1305(c.AppKey)
		payload, err := e.Encrypt(c.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		c.Payload = payload
		out.Cases = append(out.Cases, c)
	}
	writeGoVector(t, "go-encrypter.json", out)
}

func readVector(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name))
	if err != nil {
		t.Fatalf("%v (run: php scripts/vectors.php)", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

// writeGoVector writes testdata/vectors/<name> when POLARIS_UPDATE_VECTORS=1.
func writeGoVector(t *testing.T, name string, v any) {
	t.Helper()
	if os.Getenv("POLARIS_UPDATE_VECTORS") != "1" {
		return
	}
	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("..", "testdata", "vectors", name), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
