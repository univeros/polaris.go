package security

import (
	"errors"
	"strings"
	"testing"
)

type importedHash struct {
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Source   string `json:"source"`
}

type importedVectors struct {
	Generator string         `json:"generator"`
	Hashes    []importedHash `json:"hashes"`
}

func readImported(t testing.TB) []importedHash {
	t.Helper()
	var v importedVectors
	readVector(t, "imported-hashes.json", &v)
	if len(v.Hashes) == 0 {
		t.Fatal("no vectors")
	}
	return v.Hashes
}

// Every published vector verifies with its password, refuses another, passes CheckHash and asks
// for a rehash, so the first sign-in moves the account to Argon2id.
func TestImportedHashVectors(t *testing.T) {
	h := Argon2id{}
	for _, e := range readImported(t) {
		t.Run(e.Source, func(t *testing.T) {
			if err := h.CheckHash(e.Hash); err != nil {
				t.Fatalf("CheckHash: %v", err)
			}
			if !h.Verify(e.Password, e.Hash) {
				t.Errorf("published hash of %q does not verify: %s", e.Password, e.Hash)
			}
			if h.Verify(e.Password+"x", e.Hash) {
				t.Errorf("wrong password verifies against %s", e.Hash)
			}
			if !h.NeedsRehash(e.Hash) {
				t.Errorf("NeedsRehash(%s) = false", e.Hash)
			}
		})
	}
}

// The formats Verify read before keep verifying and pass CheckHash.
func TestCheckHashAcceptsTheRecordedVectors(t *testing.T) {
	var v argon2Vectors
	readVector(t, "argon2id.json", &v)
	for _, e := range v.Hashes {
		if err := (Argon2id{}).CheckHash(e.Hash); err != nil {
			t.Errorf("CheckHash(%s): %v", e.Hash, err)
		}
	}
}

func TestCheckHashRefuses(t *testing.T) {
	const b64key = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA"
	key32 := strings.Repeat("A", 43) // 32 bytes
	cases := map[string]string{
		"empty":                    "",
		"unknown scheme":           "md5$seasalt$3f86d0d3d465b7b458c231bf3555c0e3",
		"plaintext":                "correct horse battery staple",
		"bcrypt $2x$":              "$2x$04$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R6",
		"bcrypt truncated":         "$2y$04$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvy",
		"bcrypt bad alphabet":      "$2y$04$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R!",
		"bcrypt cost above bound":  "$2y$17$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R6",
		"argon2 memory above":      "$argon2id$v=19$m=2097152,t=1,p=1$bUYzTm9mWW43bTZQUEdXbA$WtYzRo2Q5O8qSxYuylpCw4QMA3XX99Rzs8QCmwjLxO4",
		"argon2 work above":        "$argon2id$v=19$m=1048576,t=5,p=1$bUYzTm9mWW43bTZQUEdXbA$WtYzRo2Q5O8qSxYuylpCw4QMA3XX99Rzs8QCmwjLxO4",
		"argon2 version 16":        "$argon2id$v=16$m=8192,t=1,p=1$bUYzTm9mWW43bTZQUEdXbA$WtYzRo2Q5O8qSxYuylpCw4QMA3XX99Rzs8QCmwjLxO4",
		"argon2 short salt":        "$argon2id$v=19$m=8192,t=1,p=1$bUYz$WtYzRo2Q5O8qSxYuylpCw4QMA3XX99Rzs8QCmwjLxO4",
		"django fields missing":    "pbkdf2_sha256$1800000$seasalt",
		"django fields extra":      "pbkdf2_sha256$1800000$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=$x",
		"django iterations zero":   "pbkdf2_sha256$0$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django iterations low":    "pbkdf2_sha256$999$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django iterations high":   "pbkdf2_sha256$5000001$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django iterations huge":   "pbkdf2_sha256$99999999999999999999999$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django leading zero":      "pbkdf2_sha256$01800000$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django signed iterations": "pbkdf2_sha256$+1800000$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django salt truncated":    "pbkdf2_sha256$1800000$sea$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"django hash truncated":    "pbkdf2_sha256$1800000$seasalt$sXv9FzN4gEo6/P8G",
		"django hash not base64":   "pbkdf2_sha256$1800000$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniN*=",
		"django sha1 unsupported":  "pbkdf2_sha1$1800000$seasalt2$MEx5Z/KZ384PO7zdMHxMvXH2k3g=",
		"django scrypt N not pow2": "scrypt$16383$seasalt$8$5$" + strings.Repeat("A", 86) + "==",
		"django scrypt memory":     "scrypt$1048576$seasalt$8$1$" + strings.Repeat("A", 86) + "==",
		"django scrypt p high":     "scrypt$16384$seasalt$8$17$" + strings.Repeat("A", 86) + "==",
		"django scrypt fields":     "scrypt$16384$seasalt$8$" + strings.Repeat("A", 86) + "==",
		"passlib sha1 unsupported": "$pbkdf2$1212$OB.dtnSEXZK8U5cgxU/GYQ$y5LKPOplRmok7CZp/aqVDVg8zGI",
		"passlib rounds low":       "$pbkdf2-sha256$999$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
		"passlib salt empty":       "$pbkdf2-sha256$1212$$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
		"passlib key too long":     "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$" + strings.Repeat("A", 88),
		"passlib PHC params":       "$pbkdf2-sha256$i=1212,l=32$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ",
		"scrypt salt empty":        "$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI",
		"scrypt memory low":        "$scrypt$ln=8,r=8,p=1$wlhLyXmP8b53bm1NKYVQqg$mTpvG8lzuuDk+DWz8HZIB6Vum6erDuUm0As5yU+VxWA",
		"scrypt memory high":       "$scrypt$ln=20,r=8,p=1$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt ln overflow":       "$scrypt$ln=64,r=8,p=1$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt r zero":            "$scrypt$ln=14,r=0,p=1$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt p high":            "$scrypt$ln=14,r=8,p=17$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt work high":         "$scrypt$ln=17,r=8,p=16$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt p missing":         "$scrypt$ln=14,r=8$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt params reordered":  "$scrypt$r=8,ln=14,p=1$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt trailing param":    "$scrypt$ln=14,r=8,p=1,x=1$U29kaXVtQ2hsb3JpZGU$" + key32,
		"scrypt hash truncated":    "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbN",
		"scrypt trailing field":    "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$" + key32 + "$",
		"firebase no key":          "$firebase-scrypt$ln=14,r=8,sep=Bw==$42xEC+ixf3L2lw==$" + b64key,
		"firebase short key":       "$firebase-scrypt$ln=14,r=8,sep=Bw==,key=QUFB$42xEC+ixf3L2lw==$QUFB",
		"firebase length mismatch": "$firebase-scrypt$ln=14,r=8,sep=Bw==,key=" + b64key + "$42xEC+ixf3L2lw==$" + key32,
		"firebase memory low":      "$firebase-scrypt$ln=9,r=8,sep=Bw==,key=" + b64key + "$42xEC+ixf3L2lw==$" + b64key,
		"firebase salt truncated":  "$firebase-scrypt$ln=14,r=8,sep=Bw==,key=" + b64key + "$QQ$" + b64key,
		"too long":                 "$scrypt$ln=14,r=8,p=1$" + strings.Repeat("A", maxImportedLen) + "$" + key32,
	}
	h := Argon2id{}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			err := h.CheckHash(hash)
			if !errors.Is(err, ErrUnsupportedHash) {
				t.Fatalf("CheckHash(%q) = %v, want ErrUnsupportedHash", hash, err)
			}
			if !strings.Contains(err.Error(), "pbkdf2_sha256$") || !strings.Contains(err.Error(), "$firebase-scrypt$") {
				t.Errorf("the error does not name the supported formats: %v", err)
			}
		})
	}
}

// A hash CheckHash refuses for a bad parameter never verifies, so a row that slipped past the
// import (written to the database directly) cannot cost more than the bounds allow.
func TestVerifyRefusesOutOfBoundImportedHashes(t *testing.T) {
	h := Argon2id{}
	for _, hash := range []string{
		"pbkdf2_sha256$999$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
		"$scrypt$ln=4,r=1,p=1$$d9ZXYjhleyA7GcpCwYoEl/FrSETjB0ro39/6P+3iFEI",
		"$scrypt$ln=30,r=8,p=1$U29kaXVtQ2hsb3JpZGU$" + strings.Repeat("A", 43),
	} {
		if h.Verify("", hash) || h.Verify("password", hash) {
			t.Errorf("Verify accepted %s", hash)
		}
	}
}

func TestParseImportedBoundsHold(t *testing.T) {
	for _, e := range readImported(t) {
		if strings.HasPrefix(e.Hash, "$2") {
			continue // bcrypt: verified by golang.org/x/crypto/bcrypt, not parseImported
		}
		p, err := parseImported(e.Hash)
		if err != nil {
			t.Fatalf("%s: %v", e.Hash, err)
		}
		if p.derive == nil || len(p.want) < importedMinKey {
			t.Fatalf("%s: parsed %+v", e.Hash, p)
		}
	}
}

func FuzzCheckHash(f *testing.F) {
	for _, e := range readImported(f) {
		f.Add(e.Hash)
	}
	for _, s := range []string{"", "$", "$$$$", "pbkdf2_sha256$$$", "scrypt$$$$$", "$scrypt$ln=,r=,p=$$",
		"$firebase-scrypt$ln=14,r=8,sep=,key=$$", "$2y$04$", "$argon2id$v=19$m=8,t=1,p=1$$"} {
		f.Add(s)
	}
	h := Argon2id{}
	f.Fuzz(func(t *testing.T, hash string) {
		err := h.CheckHash(hash)
		if err != nil && !errors.Is(err, ErrUnsupportedHash) {
			t.Fatalf("CheckHash(%q) = %v, not ErrUnsupportedHash", hash, err)
		}
		p, perr := parseImported(hash)
		if perr != nil {
			return
		}
		if err != nil {
			t.Fatalf("parsed %q but CheckHash refused it: %v", hash, err)
		}
		if len(p.want) < importedMinKey || len(p.want) > importedMaxKey || p.derive == nil {
			t.Fatalf("parsed %q out of bounds: key %d", hash, len(p.want))
		}
	})
}
