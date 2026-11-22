package security

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

const encrypterTestKey = "base64:0123456789abcdef0123456789abcdef"

func testEncrypter(t *testing.T, key string) *XChaCha20Poly1305 {
	t.Helper()
	e, err := NewXChaCha20Poly1305(key)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEncrypterRoundTripsAndNeverRepeatsCiphertext(t *testing.T) {
	e := testEncrypter(t, encrypterTestKey)
	first, err := e.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := e.Encrypt("JBSWY3DPEHPK3PXP")
	if got, err := e.Decrypt(first); err != nil || got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("Decrypt = %q, %v", got, err)
	}
	if first == second {
		t.Fatal("a fresh nonce per call")
	}
	raw, _ := base64.StdEncoding.DecodeString(first)
	if raw[0] != 0x01 || len(raw) != 1+24+16+16 {
		t.Fatalf("layout: version %x, length %d", raw[0], len(raw))
	}
}

func TestEncrypterRejectsTamperedPayload(t *testing.T) {
	e := testEncrypter(t, encrypterTestKey)
	payload, _ := e.Encrypt("secret")
	raw, _ := base64.StdEncoding.DecodeString(payload)
	raw[len(raw)-1] ^= 1
	if _, err := e.Decrypt(base64.StdEncoding.EncodeToString(raw)); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v", err)
	}
}

func TestEncrypterRejectsPayloadFromAnotherKey(t *testing.T) {
	payload, _ := testEncrypter(t, encrypterTestKey).Encrypt("secret")
	if _, err := testEncrypter(t, "another-key").Decrypt(payload); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("err = %v", err)
	}
}

func TestEncrypterRejectsMalformedPayload(t *testing.T) {
	e := testEncrypter(t, encrypterTestKey)
	for _, bad := range []string{
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x02", 60))), // wrong version
		base64.StdEncoding.EncodeToString([]byte("\x01short")),                // too short
		"!!!not base64!!!",
		"",
	} {
		if _, err := e.Decrypt(bad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Decrypt(%q) err = %v", bad, err)
		}
	}
}

func TestEncrypterRequiresAKey(t *testing.T) {
	if _, err := NewXChaCha20Poly1305(""); !errors.Is(err, ErrInvalidAppKey) {
		t.Fatalf("err = %v", err)
	}
}

func TestEncrypterAcceptsWhitespaceAndOptionalPadding(t *testing.T) {
	e := testEncrypter(t, encrypterTestKey)
	payload, _ := e.Encrypt("seed")
	unpadded := strings.TrimRight(payload, "=")
	wrapped := payload[:10] + "\r\n \t" + payload[10:]
	for _, p := range []string{unpadded, wrapped} {
		if got, err := e.Decrypt(p); err != nil || got != "seed" {
			t.Errorf("Decrypt(%q) = %q, %v", p, got, err)
		}
	}
}

// What stored payloads may hold: whitespace anywhere, padding optional but exact, non-zero
// trailing bits.
func TestDecodeBase64Lenient(t *testing.T) {
	for in, want := range map[string]string{
		"YQ": "a", "YQ==": "a", "Y Q==": "a", "YQ==\n": "a", "Y\tQ": "a", "YR==": "a",
		"YWI": "ab", "YWI=": "ab", "": "",
	} {
		got, ok := decodeBase64Lenient(in)
		if !ok || string(got) != want {
			t.Errorf("%q = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"Y", "YQ=", "YQ===", "YWJj=", "Y\vQ", "Y\fQ", "Y\x00Q", "YW=J", "Y-Q", "Y_Q", "YQ==YQ==", "Y=Q="} {
		if _, ok := decodeBase64Lenient(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}
