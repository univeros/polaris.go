package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// AccessTokenType is the typ header of the provider's access tokens (RFC 9068).
const AccessTokenType = "at+jwt"

// b64 is unpadded base64url.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sha256b64 is the base64url SHA-256 of s (PKCE S256, DPoP ath, body hashes).
func sha256b64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return b64(sum[:])
}

// JWTHeader decodes the header of a compact JWT without verifying it, nil for anything that is not
// one: enough to tell an access token (typ at+jwt) from a session token before choosing who
// verifies it.
func JWTHeader(raw string) map[string]any {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	return decodeSegment(parts[0])
}

// jwtPayload decodes the payload of a compact JWT without verifying it.
func jwtPayload(raw string) map[string]any {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil
	}
	return decodeSegment(parts[1])
}

func decodeSegment(seg string) map[string]any {
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
	if err != nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if dec.Decode(&out) != nil {
		return nil
	}
	return out
}

// Thumbprint is the RFC 7638 SHA-256 thumbprint (base64url) of a public JWK: the cnf.jkt a
// DPoP-bound token carries. It hashes the required members as given (each string as the key
// holds it, not decoded and normalized).
func Thumbprint(jwk map[string]any) (string, error) {
	var members []string
	switch jwk["kty"] {
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	default:
		return "", refusal(CodeInvalidDPoPProof, "The key type is not supported.")
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range members {
		v, ok := jwk[m].(string)
		if !ok {
			return "", refusal(CodeInvalidDPoPProof, "The key is missing "+m+".")
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`"` + m + `":`)
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return "", err
		}
		buf.Truncate(buf.Len() - 1) // the encoder's newline
	}
	buf.WriteByte('}')
	sum := sha256.Sum256(buf.Bytes())
	return b64(sum[:]), nil
}

// parseJWK reads a JWK object into a public verification key.
func parseJWK(m map[string]any) (*jose.JSONWebKey, error) {
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
	return &pub, nil
}

// verifySigned checks a compact JWS signed with alg by key and returns its claims (numbers as
// json.Number), applying the time checks with leeway: nbf and iat not after now, exp after now.
// The error texts are what the token endpoint has always answered.
func verifySigned(raw, alg string, key *jose.JSONWebKey, now time.Time, leeway time.Duration) (map[string]any, error) {
	if !slices.Contains(asymmetricAlgorithms, alg) {
		return nil, errors.New("algorithm not supported")
	}
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil {
		return nil, errors.New("wrong number of segments or malformed token")
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, errors.New("Signature verification failed")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if dec.Decode(&claims) != nil {
		return nil, errors.New("Syntax error, malformed JSON")
	}
	limit := now.Add(leeway).Unix()
	if v, ok := number(claims["nbf"]); ok && int64(v) > limit {
		return nil, fmt.Errorf("Cannot handle token with nbf prior to %s", time.Unix(int64(v), 0).UTC().Format(time.RFC3339))
	}
	if v, ok := number(claims["iat"]); ok && int64(v) > limit {
		return nil, fmt.Errorf("Cannot handle token with iat prior to %s", time.Unix(int64(v), 0).UTC().Format(time.RFC3339))
	}
	if v, ok := number(claims["exp"]); ok && now.Add(-leeway).Unix() >= int64(v) {
		return nil, errors.New("Expired token")
	}
	return claims, nil
}

// number reads a JSON number claim as a float, so a fractional or exponent time claim is compared
// by its value.
func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// integer reads a JSON number written as a whole number (no fraction, no exponent).
func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := n.Int64()
	return i, err == nil
}
