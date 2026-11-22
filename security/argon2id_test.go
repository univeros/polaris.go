package security

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// Low cost keeps the suite fast; production uses the documented defaults.
func testHasher() Argon2id { return Argon2id{Memory: 8192, Time: 1, Threads: 1} }

func TestArgon2idHashesAndVerifies(t *testing.T) {
	h := testHasher()
	hash, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if hash == "correct horse battery staple" || !strings.HasPrefix(hash, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("unexpected hash %q", hash)
	}
	parts := strings.Split(hash, "$")
	if len(parts[4]) != 22 || len(parts[5]) != 43 {
		t.Fatalf("want 16-byte salt and 32-byte hash, unpadded: %q", hash)
	}
	if !h.Verify("correct horse battery staple", hash) {
		t.Fatal("correct password rejected")
	}
	if h.Verify("wrong password", hash) {
		t.Fatal("wrong password accepted")
	}
}

func TestArgon2idHashesAreSaltedAndUnique(t *testing.T) {
	h := testHasher()
	a, _ := h.Hash("same")
	b, _ := h.Hash("same")
	if a == b {
		t.Fatal("two hashes of the same password are equal")
	}
}

func TestArgon2idRejectsEmptyHashOnVerify(t *testing.T) {
	if testHasher().Verify("anything", "") {
		t.Fatal("empty hash verified")
	}
}

func TestArgon2idFreshHashDoesNotNeedRehash(t *testing.T) {
	h := testHasher()
	hash, _ := h.Hash("secret")
	if h.NeedsRehash(hash) {
		t.Fatal("fresh hash needs rehash")
	}
}

func TestArgon2idRehashNeededWhenAlgorithmDiffers(t *testing.T) {
	b, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if !testHasher().NeedsRehash(string(b)) {
		t.Fatal("bcrypt hash should need rehash")
	}
	if !testHasher().NeedsRehash("$argon2i$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g") {
		t.Fatal("argon2i hash should need rehash")
	}
}

func TestArgon2idRehashNeededWhenCostIncreases(t *testing.T) {
	weak, _ := testHasher().Hash("secret")
	stronger := Argon2id{Memory: 16384, Time: 2, Threads: 1}
	if !stronger.NeedsRehash(weak) {
		t.Fatal("weaker hash should need rehash")
	}
}

func TestArgon2idDefaults(t *testing.T) {
	m, ti, p := Argon2id{}.params()
	if m != 65536 || ti != 4 || p != 1 {
		t.Fatalf("defaults = %d,%d,%d", m, ti, p)
	}
	if (Argon2id{}).NeedsRehash("$argon2id$v=19$m=65536,t=4,p=1$x$y") {
		t.Fatal("default-cost hash needs rehash")
	}
}

func TestArgon2idRejectsMemoryBelowEightKiBPerLane(t *testing.T) {
	_, err := Argon2id{Memory: 7, Time: 1, Threads: 1}.Hash("x")
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("err = %v", err)
	}
}

// NeedsRehash reads each parameter as a signed decimal (scanArgon2Params), so leading zeros
// and whitespace still compare equal, and a missing field compares as 0.
func TestArgon2idNeedsRehashReadsParamsLeniently(t *testing.T) {
	h := Argon2id{}
	for hash, want := range map[string]bool{
		"$argon2id$v=19$m=065536,t=4,p=1$x$y": false,
		"$argon2id$v=19$m= 65536,t=4,p=1":     false,
		"$argon2id$v=19$m=65536,t=4":          true,
		"$argon2id$v=16$m=65536,t=4,p=1$x$y":  true,
		"$argon2id$":                          true,
		"":                                    true,
	} {
		if got := h.NeedsRehash(hash); got != want {
			t.Errorf("NeedsRehash(%q) = %v, want %v", hash, got, want)
		}
	}
}

func TestArgon2idVerifyRejectsMalformedPHC(t *testing.T) {
	h := Argon2id{Memory: 8, Time: 1, Threads: 1}
	hash, err := h.Hash("x")
	if err != nil {
		t.Fatal(err)
	}
	if !h.Verify("x", hash) {
		t.Fatal("valid hash rejected")
	}
	// Each mutation is one libargon2's verifier rejects too.
	for _, bad := range []string{
		strings.Replace(hash, "m=8,", "m=08,", 1),
		strings.Replace(hash, "$v=19", "", 1),
		strings.Replace(hash, "$v=19", "$v=20", 1),
		strings.Replace(hash, "t=1", "t=0", 1),
		strings.Replace(hash, "p=1", "p=0", 1),
		strings.Replace(hash, "m=8,", "m=7,", 1),
		strings.Replace(hash, "m=8,", "m=-8,", 1),
		hash + "$",
		hash + "=",
		hash + "\n",
		strings.Replace(hash, "$argon2id$", "$argon2d$", 1),
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaGhhc2g", // salt shorter than 8 bytes
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGE",    // hash shorter than 4 bytes
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ",        // no hash
		"$argon2id$v=19$m=8,t=1,p=256$c2FsdHNhbHQ$aGFzaGhhc2g",
		"$argon2id$v=19$m=99999999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2g",
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2h", // non-zero trailing bits
		"plain",
	} {
		if h.Verify("x", bad) {
			t.Errorf("Verify accepted %q", bad)
		}
	}
}

func TestArgon2idVerifiesArgon2iAndBcrypt(t *testing.T) {
	// A recorded $argon2i$ hash of "x" (m=8,t=1,p=1), as earlier releases may have stored.
	if !(Argon2id{}).Verify("x", "$argon2i$v=19$m=8,t=1,p=1$dEtlNWhTRm5ObTRYZElQYQ$uEPcootO282FcqCsbkCMSSw5mDUS1xNQuqEFslOK2Ws") {
		t.Fatal("argon2i hash rejected")
	}
	b, _ := bcrypt.GenerateFromPassword([]byte(strings.Repeat("a", 72)), bcrypt.MinCost)
	y2 := "$2y$" + string(b[4:])
	for pw, want := range map[string]bool{
		strings.Repeat("a", 72):       true,
		strings.Repeat("a", 72) + "b": true, // crypt_blowfish reads 72 bytes
		strings.Repeat("a", 71):       false,
	} {
		if got := (Argon2id{}).Verify(pw, y2); got != want {
			t.Errorf("bcrypt Verify(len %d) = %v", len(pw), got)
		}
	}
	if (Argon2id{}).Verify(strings.Repeat("a", 72), "$2x$"+string(b[4:])) {
		t.Fatal("$2x$ (bug-compatible mode) is not emulated and must not match")
	}
	nul, _ := bcrypt.GenerateFromPassword([]byte("x"), bcrypt.MinCost)
	if !(Argon2id{}).Verify("x\x00tail", string(nul)) {
		t.Fatal("crypt_blowfish stops at NUL; the hash must verify")
	}
}
