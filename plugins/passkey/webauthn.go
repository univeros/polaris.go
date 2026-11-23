package passkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

// The WebAuthn Level 3 subset the plugin verifies: "none" attestation,
// ES256 and RS256 credentials, the client data (type, challenge, origin, not cross-origin), the
// authenticator data (relying party id hash, user presence, user verification when required,
// consistent backup flags, attested credential data on registration), the assertion signature
// over authenticatorData ‖ SHA-256(clientDataJSON), the user handle, and a signature counter that
// moves forward.

// COSE algorithms offered at registration (pubKeyCredParams).
const (
	algES256 = -7
	algRS256 = -257
)

// Authenticator data flags.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flagED = 0x80
)

const maxCredentialID = 1023

// credentialJSON is the PublicKeyCredential JSON the browser produced (credential.toJSON()).
type credentialJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		AuthenticatorData string   `json:"authenticatorData"`
		Signature         string   `json:"signature"`
		UserHandle        *string  `json:"userHandle"`
		Transports        []string `json:"transports"`
	} `json:"response"`
}

// clientData is what the browser signed.
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// parsedCredential is the credential JSON decoded: its id (as the browser sent it, base64url),
// the client data bytes and fields.
type parsedCredential struct {
	json       credentialJSON
	id         string
	clientRaw  []byte
	clientData clientData
}

// parseCredential decodes what every ceremony starts from; ok false when it is not credential JSON.
func parseCredential(raw string) (parsedCredential, bool) {
	var c credentialJSON
	if json.Unmarshal([]byte(raw), &c) != nil {
		return parsedCredential{}, false
	}
	id := c.ID
	if id == "" {
		id = c.RawID
	}
	clientRaw, err := unb64(c.Response.ClientDataJSON)
	var cd clientData
	if id == "" || err != nil || json.Unmarshal(clientRaw, &cd) != nil || cd.Challenge == "" || cd.Origin == "" {
		return parsedCredential{}, false
	}
	return parsedCredential{json: c, id: id, clientRaw: clientRaw, clientData: cd}, true
}

// authData is the authenticator data.
type authData struct {
	raw          []byte
	rpIDHash     []byte
	flags        byte
	counter      uint32
	aaguid       []byte
	credentialID []byte
	publicKey    []byte // the COSE key as the authenticator encoded it
}

func (a authData) has(flag byte) bool { return a.flags&flag != 0 }

func parseAuthData(b []byte) (authData, error) {
	if len(b) < 37 {
		return authData{}, errInvalid("the authenticator data is too short")
	}
	a := authData{raw: b, rpIDHash: b[:32], flags: b[32], counter: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if a.has(flagAT) {
		if len(rest) < 18 {
			return authData{}, errInvalid("the attested credential data is truncated")
		}
		a.aaguid = rest[:16]
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n > len(rest) {
			return authData{}, errInvalid("the credential id is truncated")
		}
		a.credentialID, rest = rest[:n], rest[n:]
		_, after, err := decodeCBOR(rest)
		if err != nil {
			return authData{}, errInvalid("the credential public key is not CBOR")
		}
		a.publicKey, rest = rest[:len(rest)-len(after)], after
	}
	if a.has(flagED) {
		ext, after, err := decodeCBOR(rest)
		if _, isMap := ext.(map[any]any); err != nil || !isMap {
			return authData{}, errInvalid("the extensions are not a CBOR map")
		}
		rest = after
	}
	if len(rest) != 0 {
		return authData{}, errInvalid("the authenticator data has trailing bytes")
	}
	return a, nil
}

// check is the authenticator data check both ceremonies share.
func (s settings) check(a authData) error {
	want := sha256.Sum256([]byte(s.rpID))
	if !bytes.Equal(a.rpIDHash, want[:]) {
		return errInvalid("the credential was signed for another relying party")
	}
	if !a.has(flagUP) {
		return errInvalid("the user was not present")
	}
	if s.userVerification == UVRequired && !a.has(flagUV) {
		return errInvalid("the user was not verified")
	}
	if !a.has(flagBE) && a.has(flagBS) {
		return errInvalid("the backup flags are inconsistent")
	}
	return nil
}

// attested is a verified registration.
type attested struct {
	credentialID                           string // base64url, as stored
	publicKey                              string // the COSE key, base64url
	counter                                uint32
	aaguid                                 string
	transports                             []string
	backupEligible, backedUp, userVerified bool
}

// attest verifies a registration whose client data (type, challenge, origin) the caller checked.
func (s settings) attest(c parsedCredential) (attested, error) {
	if c.json.Type != "public-key" {
		return attested{}, errInvalid("the credential is not a public key")
	}
	if c.clientData.CrossOrigin {
		return attested{}, errInvalid("the ceremony is cross-origin")
	}
	rawID, err := unb64(c.json.RawID)
	if err != nil || (c.json.ID != "" && c.json.ID != b64(rawID)) {
		return attested{}, errInvalid("rawId is not the credential id")
	}
	objRaw, err := unb64(c.json.Response.AttestationObject)
	if err != nil {
		return attested{}, errInvalid("the attestation object is not base64url")
	}
	obj, rest, err := decodeCBOR(objRaw)
	m, isMap := obj.(map[any]any)
	if err != nil || !isMap || len(rest) != 0 {
		return attested{}, errInvalid("the attestation object is not a CBOR map")
	}
	stmt, _ := m["attStmt"].(map[any]any)
	if m["fmt"] != "none" || stmt == nil || len(stmt) != 0 {
		return attested{}, errInvalid("only the none attestation is accepted")
	}
	raw, _ := m["authData"].([]byte)
	a, err := parseAuthData(raw)
	if err != nil {
		return attested{}, err
	}
	if err := s.check(a); err != nil {
		return attested{}, err
	}
	if !a.has(flagAT) {
		return attested{}, errInvalid("no attested credential data")
	}
	if len(a.credentialID) == 0 || len(a.credentialID) > maxCredentialID || !bytes.Equal(a.credentialID, rawID) {
		return attested{}, errInvalid("the attested credential id is not the credential's")
	}
	if _, err := parseCOSEKey(a.publicKey); err != nil {
		return attested{}, err
	}
	transports := []string{}
	for _, t := range c.json.Response.Transports {
		if t != "" {
			transports = append(transports, t)
		}
	}
	id, _ := uuid.FromBytes(a.aaguid)
	return attested{credentialID: b64(rawID), publicKey: b64(a.publicKey), counter: a.counter, aaguid: id.String(), transports: transports,
		backupEligible: a.has(flagBE), backedUp: a.has(flagBS), userVerified: a.has(flagUV)}, nil
}

// asserted is a verified assertion: the new counter and the flags.
type asserted struct {
	counter                uint32
	backedUp, userVerified bool
}

// assert verifies an assertion of pk (whose client data the caller checked); userHandle is the
// user the ceremony is for, which the authenticator's user handle must name when it sends one.
func (s settings) assert(c parsedCredential, pk record, userHandle string) (asserted, error) {
	if c.json.Type != "public-key" {
		return asserted{}, errInvalid("the credential is not a public key")
	}
	if c.clientData.CrossOrigin {
		return asserted{}, errInvalid("the ceremony is cross-origin")
	}
	if c.json.RawID != "" && c.json.RawID != c.json.ID && c.json.ID != "" {
		return asserted{}, errInvalid("rawId is not the credential id")
	}
	if h := c.json.Response.UserHandle; h != nil && *h != "" {
		decoded, err := unb64(*h)
		if err != nil || string(decoded) != userHandle {
			return asserted{}, errInvalid("the user handle is not the credential's user")
		}
	}
	raw, err := unb64(c.json.Response.AuthenticatorData)
	if err != nil {
		return asserted{}, errInvalid("the authenticator data is not base64url")
	}
	a, err := parseAuthData(raw)
	if err != nil {
		return asserted{}, err
	}
	if err := s.check(a); err != nil {
		return asserted{}, err
	}
	if a.has(flagBE) != pk.BackupEligible {
		return asserted{}, errInvalid("the backup eligibility changed")
	}
	sig, err := unb64(c.json.Response.Signature)
	if err != nil {
		return asserted{}, errInvalid("the signature is not base64url")
	}
	coseRaw, err := unb64(pk.PublicKey)
	if err != nil {
		return asserted{}, errInvalid("the stored public key is unreadable")
	}
	key, err := parseCOSEKey(coseRaw)
	if err != nil {
		return asserted{}, err
	}
	clientHash := sha256.Sum256(c.clientRaw)
	if !key.verify(append(append([]byte(nil), raw...), clientHash[:]...), sig) {
		return asserted{}, errInvalid("the signature does not verify")
	}
	if (a.counter != 0 || pk.Counter != 0) && int64(a.counter) <= pk.Counter {
		return asserted{}, errInvalid("the signature counter did not move forward")
	}
	return asserted{counter: a.counter, backedUp: a.has(flagBS), userVerified: a.has(flagUV)}, nil
}

// coseKey is a credential public key (ES256 on P-256, or RS256).
type coseKey struct {
	ec  *ecdsa.PublicKey
	rsa *rsa.PublicKey
}

func (k coseKey) verify(signed, sig []byte) bool {
	digest := sha256.Sum256(signed)
	if k.ec != nil {
		return ecdsa.VerifyASN1(k.ec, digest[:], sig)
	}
	return rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, digest[:], sig) == nil
}

func parseCOSEKey(raw []byte) (coseKey, error) {
	v, rest, err := decodeCBOR(raw)
	m, ok := v.(map[any]any)
	if err != nil || !ok || len(rest) != 0 {
		return coseKey{}, errInvalid("the public key is not a COSE key")
	}
	kty, alg := m[int64(1)], m[int64(3)]
	switch {
	case kty == int64(2) && alg == int64(algES256):
		x, _ := m[int64(-2)].([]byte)
		y, _ := m[int64(-3)].([]byte)
		if m[int64(-1)] != int64(1) || len(x) != 32 || len(y) != 32 {
			return coseKey{}, errInvalid("an ES256 key is a P-256 point")
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return coseKey{}, errInvalid("the P-256 point is not on the curve")
		}
		return coseKey{ec: key}, nil
	case kty == int64(3) && alg == int64(algRS256):
		n, _ := m[int64(-1)].([]byte)
		e, _ := m[int64(-2)].([]byte)
		if len(e) == 0 || len(e) > 4 {
			return coseKey{}, errInvalid("an RS256 key has a 2048-bit modulus or more")
		}
		// The bit length, not the encoded length: zero padding does not make a key stronger.
		key := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		// Bounded above too: verifying costs what the registered key says, and anyone can ask for it.
		if key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 3 || key.E > 65537 || key.E%2 == 0 {
			return coseKey{}, errInvalid("an RS256 key has a 2048 to 8192-bit modulus and an odd exponent of at most 65537")
		}
		return coseKey{rsa: key}, nil
	}
	return coseKey{}, errInvalid("only ES256 and RS256 credentials are accepted")
}

// creationOptions are the PublicKeyCredentialCreationOptionsJSON the registration route answers.
func (s settings) creationOptions(challenge []byte, userID, userName, displayName string, exclude []string) map[string]any {
	selection := map[string]any{"requireResidentKey": true, "residentKey": "required", "userVerification": s.userVerification}
	if s.attachment != "" {
		selection["authenticatorAttachment"] = s.attachment
	}
	return map[string]any{
		"challenge": b64(challenge),
		"timeout":   s.timeout.Milliseconds(),
		"rp":        map[string]any{"id": s.rpID, "name": s.rpName},
		"user":      map[string]any{"id": b64([]byte(userID)), "name": userName, "displayName": displayName},
		"pubKeyCredParams": []any{
			map[string]any{"type": "public-key", "alg": algES256},
			map[string]any{"type": "public-key", "alg": algRS256},
		},
		"authenticatorSelection": selection,
		"attestation":            "none",
		"excludeCredentials":     descriptors(exclude),
	}
}

// requestOptions are PublicKeyCredentialRequestOptionsJSON, discoverable: no credential named.
func (s settings) requestOptions(challenge []byte) map[string]any {
	return map[string]any{
		"challenge": b64(challenge), "timeout": s.timeout.Milliseconds(), "rpId": s.rpID,
		"allowCredentials": []any{}, "userVerification": s.userVerification,
	}
}

func descriptors(ids []string) []any {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, map[string]any{"type": "public-key", "id": id})
	}
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 decodes base64url with or without padding.
func unb64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
