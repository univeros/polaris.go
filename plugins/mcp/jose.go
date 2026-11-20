package mcp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Algorithms are the asymmetric JWS algorithms accepted for an access token and a DPoP proof, as
// the metadata's dpop_signing_alg_values_supported lists them.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

var compactJWT = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sha256b64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])
}

// jwtHeader decodes a compact JWS's header without verifying it; nil for anything else.
func jwtHeader(raw string) map[string]any {
	seg, _, ok := strings.Cut(raw, ".")
	if !ok || strings.Count(raw, ".") != 2 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
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

// parseJWK reads a JWK object into its public key; an alg it names must be alg.
func parseJWK(m map[string]any, alg string) (any, error) {
	if ka, ok := m["alg"].(string); ok && ka != alg {
		return nil, errors.New("incorrect key for this algorithm")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	pub := k.Public()
	if !pub.Valid() {
		return nil, errors.New("not a usable public key")
	}
	return pub.Key, nil
}

// verifyJWS checks a compact JWS signed with alg by key and returns its claims (numbers as
// json.Number), with firebase/php-jwt's time checks under leeway: nbf and iat not after now, exp
// after now.
func verifyJWS(raw, alg string, key any, now time.Time, leeway time.Duration) (map[string]any, error) {
	if !slices.Contains(Algorithms, alg) {
		return nil, errors.New("algorithm not supported")
	}
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, err
	}
	limit := now.Add(leeway).Unix()
	if v, ok := number(claims["nbf"]); ok && int64(v) > limit {
		return nil, errors.New("not yet valid")
	}
	if v, ok := number(claims["iat"]); ok && int64(v) > limit {
		return nil, errors.New("issued in the future")
	}
	if v, ok := number(claims["exp"]); ok && now.Add(-leeway).Unix() >= int64(v) {
		return nil, errors.New("expired")
	}
	return claims, nil
}

func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
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
