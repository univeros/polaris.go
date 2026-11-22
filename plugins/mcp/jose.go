package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Algorithms are the asymmetric JWS algorithms accepted for an access token and a DPoP proof, as
// the metadata's dpop_signing_alg_values_supported lists them.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sha256b64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])
}

// thumbprint is the RFC 7638 SHA-256 thumbprint (base64url) of a public JWK, hashing the required
// members as given; ok is false for a key type it cannot name or a missing member.
func thumbprint(jwk map[string]any) (string, bool) {
	var members []string
	switch jwk["kty"] {
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	default:
		return "", false
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range members {
		v, ok := jwk[m].(string)
		if !ok {
			return "", false
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		key, _ := json.Marshal(m)
		value, _ := json.Marshal(v)
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	sum := sha256.Sum256(buf.Bytes())
	return b64(sum[:]), true
}

// integer reads a JSON number PHP decodes as an int (no fraction, no exponent).
func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}
