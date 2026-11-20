package passkey

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// The verifier's refusals, one by one, against payloads the software authenticator builds.

func testSettings(t *testing.T, uv string) settings {
	t.Helper()
	s, err := Config{Origins: []string{unitOrigin}, UserVerification: uv}.settings()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func parsed(t *testing.T, credential map[string]any) parsedCredential {
	t.Helper()
	c, ok := parseCredential(js(credential))
	if !ok {
		t.Fatal("not a credential")
	}
	return c
}

// withAttestation replaces the attestation object of a registration.
func withAttestation(cred map[string]any, attestation []byte) map[string]any {
	resp := map[string]any{}
	for k, v := range cred["response"].(map[string]any) {
		resp[k] = v
	}
	resp["attestationObject"] = b64(attestation)
	out := map[string]any{}
	for k, v := range cred {
		out[k] = v
	}
	out["response"] = resp
	return out
}

func authDataFor(rpID string, flags byte, counter uint32, tail ...[]byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := binary.BigEndian.AppendUint32(append(h[:], flags), counter)
	for _, t := range tail {
		out = append(out, t...)
	}
	return out
}

func attestedData(credID, cose []byte) []byte {
	out := append(make([]byte, 16), byte(len(credID)>>8), byte(len(credID)))
	return append(append(out, credID...), cose...)
}

func TestAttestationRefusals(t *testing.T) {
	s := testSettings(t, UVRequired)
	a := NewAuthenticator(t)
	options := roundTrip(s.creationOptions([]byte("challenge-bytes"), "user", "ada", "Ada", nil))
	good := a.Create(options, unitOrigin, true)
	if att, err := s.attest(parsed(t, good)); err != nil || !att.userVerified || !att.backupEligible {
		t.Fatalf("%+v %v", att, err)
	}
	none := func(authData []byte) []byte {
		return cborMap(cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(), cborText("authData"), cborBytes(authData))
	}
	full := byte(flagUP | flagUV | flagAT)
	cases := map[string]map[string]any{
		"user verification required": a.Create(options, unitOrigin, false),
		"packed attestation":         withAttestation(good, cborMap(cborText("fmt"), cborText("packed"), cborText("attStmt"), cborMap(), cborText("authData"), cborBytes(authDataFor("app.example", full, 0)))),
		"a statement for none":       withAttestation(good, cborMap(cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(cborText("x"), cborInt(1)), cborText("authData"), cborBytes(nil))),
		"trailing attestation":       withAttestation(good, append(none(authDataFor("app.example", full, 0, attestedData(a.CredentialID, a.coseKey()))), 0)),
		"another relying party":      withAttestation(good, none(authDataFor("evil.example", full, 0, attestedData(a.CredentialID, a.coseKey())))),
		"not present":                withAttestation(good, none(authDataFor("app.example", flagUV|flagAT, 0, attestedData(a.CredentialID, a.coseKey())))),
		"backed up, not eligible":    withAttestation(good, none(authDataFor("app.example", full|flagBS, 0, attestedData(a.CredentialID, a.coseKey())))),
		"no attested data":           withAttestation(good, none(authDataFor("app.example", flagUP|flagUV, 0))),
		"another credential id":      withAttestation(good, none(authDataFor("app.example", full, 0, attestedData([]byte("other"), a.coseKey())))),
		"an EdDSA key":               withAttestation(good, none(authDataFor("app.example", full, 0, attestedData(a.CredentialID, cborMap(cborInt(1), cborInt(1), cborInt(3), cborInt(-8)))))),
		"an off-curve point":         withAttestation(good, none(authDataFor("app.example", full, 0, attestedData(a.CredentialID, cborMap(cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1), cborInt(-2), cborBytes(make([]byte, 32)), cborInt(-3), cborBytes(make([]byte, 32))))))),
		"a short RSA key":            withAttestation(good, none(authDataFor("app.example", full, 0, attestedData(a.CredentialID, cborMap(cborInt(1), cborInt(3), cborInt(3), cborInt(-257), cborInt(-1), cborBytes(make([]byte, 64)), cborInt(-2), cborBytes([]byte{1, 0, 1})))))),
		"trailing auth data":         withAttestation(good, none(authDataFor("app.example", full, 0, attestedData(a.CredentialID, a.coseKey()), []byte{0}))),
		"bad extensions":             withAttestation(good, none(authDataFor("app.example", full|flagED, 0, attestedData(a.CredentialID, a.coseKey()), cborInt(1)))),
		"short auth data":            withAttestation(good, none([]byte{1, 2, 3})),
		"truncated attested data":    withAttestation(good, none(authDataFor("app.example", full, 0, []byte{1, 2}))),
		"truncated credential id":    withAttestation(good, none(authDataFor("app.example", full, 0, append(make([]byte, 16), 0, 9, 1)))),
		"a key that is not CBOR":     withAttestation(good, none(authDataFor("app.example", full, 0, attestedData(a.CredentialID, []byte{0xff})))),
		"not CBOR":                   withAttestation(good, []byte{0x1c}),
	}
	for msg, cred := range cases {
		if _, err := s.attest(parsed(t, cred)); err == nil {
			t.Fatalf("%s: accepted", msg)
		}
	}
	// Extensions after the key are read; the flags are reported.
	withExt := withAttestation(good, none(authDataFor("app.example", full|flagED, 7, attestedData(a.CredentialID, a.coseKey()), cborMap(cborText("credProtect"), cborInt(2)))))
	if att, err := s.attest(parsed(t, withExt)); err != nil || att.counter != 7 || att.backupEligible {
		t.Fatalf("%+v %v", att, err)
	}
	other := parsed(t, good)
	other.json.Type = "password"
	if _, err := s.attest(other); err == nil {
		t.Fatal("type")
	}
	other = parsed(t, good)
	other.clientData.CrossOrigin = true
	if _, err := s.attest(other); err == nil {
		t.Fatal("cross-origin")
	}
	other = parsed(t, good)
	other.json.RawID = b64([]byte("x"))
	if _, err := s.attest(other); err == nil {
		t.Fatal("rawId")
	}
	other = parsed(t, good)
	other.json.Response.AttestationObject = "!!"
	if _, err := s.attest(other); err == nil {
		t.Fatal("base64")
	}
	for _, raw := range []string{"[]", `{"id":"x","response":{"clientDataJSON":"!!"}}`, `{"id":"x","response":{"clientDataJSON":"` + b64([]byte(`{"type":"webauthn.get"}`)) + `"}}`} {
		if _, ok := parseCredential(raw); ok {
			t.Fatalf("%s parsed", raw)
		}
	}
}

func TestAssertionRefusalsAndRS256(t *testing.T) {
	s := testSettings(t, UVPreferred)
	a := NewAuthenticator(t)
	att, err := s.attest(parsed(t, a.Create(roundTrip(s.creationOptions([]byte("c"), "u", "n", "d", nil)), unitOrigin, true)))
	if err != nil {
		t.Fatal(err)
	}
	pk := record{PublicKey: att.publicKey, BackupEligible: true}
	request := roundTrip(s.requestOptions([]byte("c")))
	good := parsed(t, a.Get(request, unitOrigin, "u", false, 0))
	if got, err := s.assert(good, pk, "u"); err != nil || got.userVerified {
		t.Fatalf("%+v %v", got, err)
	}

	mutate := func(f func(*parsedCredential)) parsedCredential {
		c := parsed(t, a.Get(request, unitOrigin, "u", true, 5))
		f(&c)
		return c
	}
	cases := map[string]parsedCredential{
		"type":           mutate(func(c *parsedCredential) { c.json.Type = "x" }),
		"cross-origin":   mutate(func(c *parsedCredential) { c.clientData.CrossOrigin = true }),
		"rawId":          mutate(func(c *parsedCredential) { c.json.RawID = "other" }),
		"user handle":    mutate(func(c *parsedCredential) { h := b64([]byte("v")); c.json.Response.UserHandle = &h }),
		"auth data b64":  mutate(func(c *parsedCredential) { c.json.Response.AuthenticatorData = "!!" }),
		"auth data":      mutate(func(c *parsedCredential) { c.json.Response.AuthenticatorData = b64([]byte{1}) }),
		"signature b64":  mutate(func(c *parsedCredential) { c.json.Response.Signature = "!!" }),
		"signature":      mutate(func(c *parsedCredential) { c.json.Response.Signature = b64([]byte("forged")) }),
		"another client": mutate(func(c *parsedCredential) { c.clientRaw = append(c.clientRaw, ' ') }),
	}
	for msg, c := range cases {
		if _, err := s.assert(c, pk, "u"); err == nil {
			t.Fatalf("%s: accepted", msg)
		}
	}
	if _, err := s.assert(good, record{PublicKey: att.publicKey}, "u"); err == nil {
		t.Fatal("the backup eligibility changed")
	}
	if _, err := s.assert(good, record{PublicKey: "!!", BackupEligible: true}, "u"); err == nil {
		t.Fatal("stored key")
	}
	if _, err := s.assert(parsed(t, a.Get(request, unitOrigin, "u", true, 3)), record{PublicKey: att.publicKey, BackupEligible: true, Counter: 3}, "u"); err == nil {
		t.Fatal("counter")
	}

	// An RS256 credential verifies PKCS #1 v1.5 signatures.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cose := cborMap(cborInt(1), cborInt(3), cborInt(3), cborInt(-257), cborInt(-1), cborBytes(key.N.Bytes()), cborInt(-2), cborBytes([]byte{1, 0, 1}))
	parsedKey, err := parseCOSEKey(cose)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("signed"))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if !parsedKey.verify([]byte("signed"), sig) || parsedKey.verify([]byte("other"), sig) {
		t.Fatal("RS256")
	}
}

func TestCBOR(t *testing.T) {
	v, rest, err := decodeCBOR(append(cborMap(cborText("a"), []byte{0x84, 0xf4, 0xf5, 0xf6, 0x39, 0x01, 0x00}, cborInt(1), cborBytes([]byte("b"))), 0x07))
	m, _ := v.(map[any]any)
	if err != nil || len(rest) != 1 || m["a"].([]any)[3] != int64(-257) || string(m[int64(1)].([]byte)) != "b" || m["a"].([]any)[1] != true {
		t.Fatalf("%v %v %v", v, rest, err)
	}
	if v, _, err := decodeCBOR([]byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}); err != nil || v != int64(1<<32) {
		t.Fatal(v, err)
	}
	for name, bad := range map[string][]byte{
		"empty": nil, "float": {0xf9, 0, 0}, "tag": {0xc0, 0}, "indefinite": {0x9f}, "short string": {0x43, 1},
		"huge uint": {0x1b, 0xff, 0, 0, 0, 0, 0, 0, 0}, "huge negint": {0x3b, 0xff, 0, 0, 0, 0, 0, 0, 0},
		"duplicate key": cborMap(cborInt(1), cborInt(1), cborInt(1), cborInt(2)), "list key": cborMap([]byte{0x80}, cborInt(1)),
		"deep": []byte(strings.Repeat("\x81", 12) + "\x01"), "long list": {0x9a, 0, 1, 0, 0}, "long map": {0xba, 0, 1, 0, 0},
		"truncated head": {0x19, 1}, "map value": {0xa1, 0x01}, "list item": {0x82, 0x01},
	} {
		if _, _, err := decodeCBOR(bad); err == nil {
			t.Fatalf("%s decoded", name)
		}
	}
}

// TestRSAKeySanity: a modulus padded with zero bytes to look 2048-bit, or a public exponent that
// is even or below 3, is not an RS256 key.
func TestRSAKeySanity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := func(n, e []byte) []byte {
		return cborMap(cborInt(1), cborInt(3), cborInt(3), cborInt(-257), cborInt(-1), cborBytes(n), cborInt(-2), cborBytes(e))
	}
	padded := append(make([]byte, 200), key.N.Bytes()[:56]...)
	for name, raw := range map[string][]byte{
		"zero-padded modulus": rsaKey(padded, []byte{1, 0, 1}),
		"exponent 1":          rsaKey(key.N.Bytes(), []byte{1}),
		"even exponent":       rsaKey(key.N.Bytes(), []byte{1, 0, 0}),
	} {
		if _, err := parseCOSEKey(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseCOSEKey(rsaKey(key.N.Bytes(), []byte{1, 0, 1})); err != nil {
		t.Fatalf("a sound key: %v", err)
	}
}
