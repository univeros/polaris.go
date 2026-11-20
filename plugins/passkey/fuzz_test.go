package passkey

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Fuzz targets for the hand-written WebAuthn parsing (decision #35): nothing a browser or an
// attacker sends may panic, and parsing must only accept well-formed input.

const fuzzOrigin = "https://app.polaris.test"

func fuzzSettings(f *testing.F) settings {
	f.Helper()
	s, err := Config{Origins: []string{fuzzOrigin}, UserVerification: UVPreferred}.settings()
	if err != nil {
		f.Fatal(err)
	}
	return s
}

// fuzzCeremony is a real registration and assertion from the software authenticator.
func fuzzCeremony(f *testing.F, s settings) (reg, get map[string]any, pk record) {
	f.Helper()
	a := NewAuthenticator(f)
	reg = roundTrip(a.Create(s.creationOptions(random(32), "user-1", "a@b.test", "A", nil), fuzzOrigin, true))
	c, ok := parseCredential(js(reg))
	if !ok {
		f.Fatal("seed registration does not parse")
	}
	att, err := s.attest(c)
	if err != nil {
		f.Fatal(err)
	}
	pk = record{CredentialID: att.credentialID, PublicKey: att.publicKey, BackupEligible: att.backupEligible}
	get = roundTrip(a.Get(s.requestOptions(random(32)), fuzzOrigin, "user-1", true, 1))
	return reg, get, pk
}

func fuzzResponse(cred map[string]any, field string) []byte {
	raw, _ := unb64(cred["response"].(map[string]any)[field].(string))
	return raw
}

func FuzzCBOR(f *testing.F) {
	s := fuzzSettings(f)
	reg, _, pk := fuzzCeremony(f, s)
	f.Add(fuzzResponse(reg, "attestationObject"))
	cose, _ := unb64(pk.PublicKey)
	f.Add(cose)
	f.Add([]byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0xbf})
	f.Add(bytes.Repeat([]byte{0x81}, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, rest, err := decodeCBOR(b)
		if err == nil && (len(rest) > len(b) || !bytes.Equal(rest, b[len(b)-len(rest):])) {
			t.Fatalf("rest is not a suffix of the input")
		}
		_, _ = parseCOSEKey(b)
	})
}

func FuzzAuthData(f *testing.F) {
	s := fuzzSettings(f)
	reg, get, _ := fuzzCeremony(f, s)
	obj, _, _ := decodeCBOR(fuzzResponse(reg, "attestationObject"))
	f.Add(obj.(map[any]any)["authData"].([]byte))
	f.Add(fuzzResponse(get, "authenticatorData"))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, err := parseAuthData(b)
		if err != nil {
			return
		}
		_ = s.check(a)
		if a.has(flagAT) {
			_, _ = parseCOSEKey(a.publicKey)
		}
	})
}

// FuzzCOSEVerify verifies a signature with any stored key: a hostile key (tiny or zero RSA
// modulus, odd exponent sizes, off-curve points) must be refused or fail, never panic.
func FuzzCOSEVerify(f *testing.F) {
	s := fuzzSettings(f)
	_, get, pk := fuzzCeremony(f, s)
	cose, _ := unb64(pk.PublicKey)
	f.Add(cose, fuzzResponse(get, "signature"))
	f.Add(cborMap(cborInt(1), cborInt(3), cborInt(3), cborInt(-257), cborInt(-1), cborBytes(make([]byte, 256)), cborInt(-2), cborBytes([]byte{1, 0, 1})), []byte{1})
	f.Fuzz(func(t *testing.T, cose, sig []byte) {
		k, err := parseCOSEKey(cose)
		if err != nil {
			return
		}
		_ = k.verify([]byte("signed"), sig)
	})
}

// FuzzCredential runs both ceremonies' verification on arbitrary credential JSON.
func FuzzCredential(f *testing.F) {
	s := fuzzSettings(f)
	reg, get, pk := fuzzCeremony(f, s)
	f.Add(js(reg))
	f.Add(js(get))
	f.Add(`{"id":"","response":{"clientDataJSON":"e30"}}`)
	f.Fuzz(func(t *testing.T, raw string) {
		c, ok := parseCredential(raw)
		if !ok {
			return
		}
		_, _ = s.attest(c)
		_, _ = s.assert(c, pk, "user-1")
	})
}

// FuzzAssertion mutates the signed parts of a real assertion: a changed authenticator data or
// client data must never verify with the original signature.
func FuzzAssertion(f *testing.F) {
	s := fuzzSettings(f)
	_, get, pk := fuzzCeremony(f, s)
	authData, clientData, sig := fuzzResponse(get, "authenticatorData"), fuzzResponse(get, "clientDataJSON"), fuzzResponse(get, "signature")
	f.Add(authData, clientData, sig)
	f.Fuzz(func(t *testing.T, ad, cd, sg []byte) {
		resp := map[string]any{"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sg), "userHandle": b64([]byte("user-1"))}
		cred, _ := json.Marshal(map[string]any{"id": pk.CredentialID, "rawId": pk.CredentialID, "type": "public-key", "response": resp})
		c, ok := parseCredential(string(cred))
		if !ok {
			return
		}
		_, err := s.assert(c, pk, "user-1")
		signedSame := bytes.Equal(ad, authData) && bytes.Equal(cd, clientData)
		if err == nil && !signedSame && bytes.Equal(sg, sig) {
			t.Fatalf("a modified assertion verified with the original signature")
		}
	})
}
