package security

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func testPepper(t *testing.T) *Pepper {
	t.Helper()
	p, err := NewPepper("application-key-for-tests-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPepperProducesHexSha256Digest(t *testing.T) {
	hash := testPepper(t).Hash("refresh", "token-value")
	if len(hash) != 64 || !isHex(hash) || strings.ToLower(hash) != hash {
		t.Fatalf("hash = %q", hash)
	}
}

func TestPepperIsDeterministicForSameInputs(t *testing.T) {
	if first, second := testPepper(t).Hash("otp", "123456"), testPepper(t).Hash("otp", "123456"); first != second {
		t.Fatal("not deterministic")
	}
}

func TestPepperDiffersByContextAndValue(t *testing.T) {
	p := testPepper(t)
	if p.Hash("refresh", "same-value") == p.Hash("otp", "same-value") {
		t.Fatal("contexts share a key")
	}
	if p.Hash("otp", "111111") == p.Hash("otp", "222222") {
		t.Fatal("values collide")
	}
}

func TestPepperMatches(t *testing.T) {
	p := testPepper(t)
	hash := p.Hash("recovery", "abcde-fghij")
	if !p.Matches("recovery", "abcde-fghij", hash) {
		t.Fatal("own hash rejected")
	}
	if p.Matches("recovery", "wrong-code", hash) || p.Matches("otp", "abcde-fghij", hash) {
		t.Fatal("wrong value or context accepted")
	}
	// hash_equals is case-sensitive: upper-case hex passes ctype_xdigit but never matches.
	if p.Matches("recovery", "abcde-fghij", strings.ToUpper(hash)) {
		t.Fatal("upper-case digest accepted")
	}
}

func TestPepperMatchesRejectsMalformedHash(t *testing.T) {
	p := testPepper(t)
	for _, bad := range []string{"", "not-hex-zzz", p.Hash("otp", "value")[:63]} {
		if p.Matches("otp", "value", bad) {
			t.Errorf("Matches accepted %q", bad)
		}
	}
}

func TestPepperRejectsShortApplicationKeys(t *testing.T) {
	for _, key := range []string{"", "only-31-bytes-0123456789abcdef0"} {
		if _, err := NewPepper(key); !errors.Is(err, ErrInvalidAppKey) {
			t.Errorf("NewPepper(%d bytes) err = %v", len(key), err)
		}
	}
}

func TestSecretsAreRedactedInLogs(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	enc, _ := NewXChaCha20Poly1305("application-key-for-tests-0123456789")
	log.Info("x", "pepper", testPepper(t), "encrypter", enc)
	for _, v := range []any{testPepper(t), enc} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(verb, v); out != "[REDACTED]" {
				t.Fatalf("%s of %T = %s", verb, v, out)
			}
		}
	}
	if strings.Contains(buf.String(), "application-key") || strings.Count(buf.String(), "[REDACTED]") != 2 {
		t.Fatalf("log leaked or did not redact: %s", buf.String())
	}
}
