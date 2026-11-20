package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"testing"
)

// Authenticator is a software authenticator (port of upstream's tests/Support/SoftwareAuthenticator):
// a P-256 credential answering the ceremonies with real WebAuthn payloads, "none" attestation.
// Exported to the external tests.
type Authenticator struct {
	key          *ecdsa.PrivateKey
	CredentialID []byte
	// Flags are ORed into the authenticator data flags (UP, BE and BS are always set).
	NoBackup bool
}

// NewAuthenticator makes a fresh credential.
func NewAuthenticator(testing.TB) *Authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err) // crypto/rand does not fail
	}
	return &Authenticator{key: key, CredentialID: random(32)}
}

func (a *Authenticator) flags(userVerified bool) byte {
	f := byte(flagUP | flagBE | flagBS)
	if a.NoBackup {
		f = flagUP
	}
	if userVerified {
		f |= flagUV
	}
	return f
}

// Create answers the creation options from origin: the registration's PublicKeyCredential JSON.
func (a *Authenticator) Create(options map[string]any, origin string, userVerified bool) map[string]any {
	rp, _ := options["rp"].(map[string]any)
	rpID, _ := rp["id"].(string)
	challenge, _ := options["challenge"].(string)
	clientData := clientDataJSON("webauthn.create", challenge, origin)
	rpHash := sha256.Sum256([]byte(rpID))
	authData := append(rpHash[:], a.flags(userVerified)|flagAT, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...)
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(a.CredentialID)))
	authData = append(authData, a.CredentialID...)
	authData = append(authData, a.coseKey()...)
	attestation := cborMap(cborText("fmt"), cborText("none"), cborText("attStmt"), cborMap(), cborText("authData"), cborBytes(authData))
	return a.credential(map[string]any{
		"clientDataJSON": b64(clientData), "attestationObject": b64(attestation), "transports": []any{"internal", "hybrid"},
	})
}

// Get answers the request options from origin for userHandle: the assertion's JSON.
func (a *Authenticator) Get(options map[string]any, origin, userHandle string, userVerified bool, counter uint32) map[string]any {
	rpID, _ := options["rpId"].(string)
	challenge, _ := options["challenge"].(string)
	clientData := clientDataJSON("webauthn.get", challenge, origin)
	rpHash := sha256.Sum256([]byte(rpID))
	authData := binary.BigEndian.AppendUint32(append(rpHash[:], a.flags(userVerified)), counter)
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte(nil), authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		panic(err)
	}
	return a.credential(map[string]any{
		"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(sig), "userHandle": b64([]byte(userHandle)),
	})
}

// GetJSON is Get as the string core's /auth/mfa/verify takes as the code.
func (a *Authenticator) GetJSON(options map[string]any, origin, userHandle string, userVerified bool, counter uint32) string {
	raw, _ := json.Marshal(a.Get(options, origin, userHandle, userVerified, counter))
	return string(raw)
}

func (a *Authenticator) credential(response map[string]any) map[string]any {
	id := b64(a.CredentialID)
	return map[string]any{"id": id, "rawId": id, "type": "public-key", "authenticatorAttachment": "platform",
		"clientExtensionResults": map[string]any{}, "response": response}
}

// coseKey is the public key as a COSE_Key (EC2, P-256, ES256).
func (a *Authenticator) coseKey() []byte {
	raw, err := a.key.PublicKey.Bytes() // 0x04 ‖ x ‖ y
	if err != nil {
		panic(err)
	}
	return cborMap(cborInt(1), cborInt(2), cborInt(3), cborInt(-7), cborInt(-1), cborInt(1), cborInt(-2), cborBytes(raw[1:33]), cborInt(-3), cborBytes(raw[33:]))
}

func clientDataJSON(typ, challenge, origin string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return raw
}

// A CBOR encoder for the authenticator's payloads (definite lengths, keys in the order given).

func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
	}
	return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
}

func cborInt(n int64) []byte {
	if n < 0 {
		return cborHead(1, uint64(-1-n))
	}
	return cborHead(0, uint64(n))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func cborMap(pairs ...[]byte) []byte {
	out := cborHead(5, uint64(len(pairs)/2))
	for _, p := range pairs {
		out = append(out, p...)
	}
	return out
}
