package agent

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/univeros/polaris.go/internal/strictjson"
)

// The request JWT's protocol values.
const (
	// RequestJWTType is the typ header of a signed request JWT.
	RequestJWTType = "agent+jwt"
	// DefaultRequestTTL is how long a request JWT lives unless WithRequestTTL says otherwise.
	DefaultRequestTTL = 60 * time.Second
	// MaxRequestTTL is the server's requestJwtMaxAge: no request JWT may live longer.
	MaxRequestTTL = 300 * time.Second
	// AssertionType is the client_assertion_type of a private_key_jwt assertion (RFC 7523).
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// jwsHeader is the JOSE header, members in the order typ, alg, kid.
type jwsHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
}

// requestClaims are the request JWT's claims, in a fixed member order.
type requestClaims struct {
	Sub          string   `json:"sub"`
	Aud          string   `json:"aud"`
	Iat          int64    `json:"iat"`
	Exp          int64    `json:"exp"`
	Jti          string   `json:"jti"`
	Htm          string   `json:"htm"`
	Htu          string   `json:"htu"`
	BodyHash     string   `json:"body_hash,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type assertionClaims struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Jti string `json:"jti"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// signRequest is the signed request JWT (typ agent+jwt) for one call: sub = the agent, aud = htu =
// the exact URL (no query or fragment), htm = the method, body_hash = base64url SHA-256 of the
// exact bytes sent (nil body: none), capabilities restricting the grants it may use.
func signRequest(k *Key, agentID, method, url string, body []byte, capabilities []string, ttl time.Duration, now time.Time) (string, error) {
	if ttl < time.Second || ttl > MaxRequestTTL {
		return "", fmt.Errorf("agent: request JWT ttl %s: must be between 1s and %s (300 seconds)", ttl, MaxRequestTTL)
	}
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	aud := canonicalURL(url)
	iat := now.Unix()
	c := requestClaims{Sub: agentID, Aud: aud, Iat: iat, Exp: iat + int64(ttl/time.Second), Jti: jti, Htm: strings.ToUpper(method), Htu: aud, Capabilities: capabilities}
	if body != nil {
		sum := sha256.Sum256(body)
		c.BodyHash = b64(sum[:])
	}
	return signJWS(k, RequestJWTType, c)
}

// signAssertion is the private_key_jwt client assertion (RFC 7523) for the token endpoint:
// iss = sub = the agent, aud = the endpoint, five minutes long.
func signAssertion(k *Key, agentID, tokenEndpoint string, now time.Time) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	iat := now.Unix()
	return signJWS(k, "JWT", assertionClaims{Iss: agentID, Sub: agentID, Aud: tokenEndpoint, Jti: jti, Iat: iat, Exp: iat + int64(MaxRequestTTL/time.Second)})
}

func signJWS(k *Key, typ string, claims any) (string, error) {
	header, err := marshalJSON(jwsHeader{Typ: typ, Alg: string(k.alg), Kid: k.kid})
	if err != nil {
		return "", err
	}
	payload, err := marshalJSON(claims)
	if err != nil {
		return "", err
	}
	input := b64(header) + "." + b64(payload)
	sig, err := k.sign([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64(sig), nil
}

// marshalJSON encodes compact JSON with no HTML escaping and no trailing newline.
func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("agent: encode: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// newJTI is 128 random bits, base64url.
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("agent: jti: %w", err)
	}
	return b64(b), nil
}

// canonicalURL is the URL an aud names: scheme, host, port and path, never the query or fragment.
func canonicalURL(url string) string {
	if i := strings.IndexAny(url, "?#"); i >= 0 {
		return url[:i]
	}
	return url
}

// errBadJWS is every reason a JWS does not verify; callers only need the verdict.
var errBadJWS = errors.New("agent: the JWS does not verify")

// verifyJWS checks a compact JWS against a JWK Set: the
// header's typ must be typ, its kid must name a key (whose alg, when set, must equal the header's),
// and the signature (RS256, ES256 or EdDSA) must verify. It answers the claims, numbers as
// json.Number.
func verifyJWS(token, typ string, keys []JWK) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errBadJWS
	}
	var h jwsHeader
	if decodeSegment(parts[0], &h) != nil || h.Typ != typ || h.Kid == "" {
		return nil, errBadJWS
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errBadJWS
	}
	input := []byte(parts[0] + "." + parts[1])
	for _, k := range keys {
		if k.Kid != h.Kid || (k.Alg != "" && k.Alg != h.Alg) {
			continue
		}
		if !verifySignature(h.Alg, k, input, sig) {
			return nil, errBadJWS
		}
		var claims map[string]any
		if decodeSegment(parts[1], &claims) != nil || claims == nil {
			return nil, errBadJWS
		}
		return claims, nil
	}
	return nil, errBadJWS
}

func verifySignature(alg string, k JWK, input, sig []byte) bool {
	digest := sha256.Sum256(input)
	switch {
	case alg == "RS256" && k.Kty == "RSA":
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return false
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
	case alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256":
		x, err1 := base64.RawURLEncoding.DecodeString(k.X)
		y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 || len(sig) != 64 {
			return false
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return false
		}
		return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case alg == "EdDSA" && k.Kty == "OKP" && k.Crv == "Ed25519":
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		return err == nil && len(x) == ed25519.PublicKeySize && ed25519.Verify(x, input, sig)
	}
	return false
}

func decodeSegment(seg string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return strictjson.Decode(data, out)
}
