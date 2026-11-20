package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK is one signing key of a JWK Set (RFC 7517): RSA (n, e) or, for EdDSA, an RFC 8037 OKP key
// (crv Ed25519, x). Field order is the wire order; an RSA key is byte-identical to upstream's.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
}

// JWKSet is the document served at /auth/.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// PublicKey is a public key published under a kid: a PEM for RS256, the 32 raw bytes of an
// Ed25519 key for EdDSA (what Config.PublicKey takes).
type PublicKey struct {
	KeyID string
	PEM   string
}

// NewJWKSet renders public keys as a JWK Set, in order: during a rotation the active key and
// the retiring one are published side by side (docs/auth/key-rotation.md). A kid given twice
// keeps its first position and its last key, as upstream's kid-keyed array does.
//
// RS256 renders RSA keys as upstream; EdDSA renders RFC 8037 OKP keys (upstream cannot render
// them and fails the request). An unparseable key, or another algorithm, fails with
// ErrInvalidConfig rather than serving a malformed set.
func NewJWKSet(alg Algorithm, keys ...PublicKey) (JWKSet, error) {
	set := JWKSet{Keys: make([]JWK, 0, len(keys))}
	position := make(map[string]int, len(keys))
	render := rsaJWK
	if alg == EdDSA {
		render = okpJWK
	}
	for _, k := range keys {
		jwk, err := render(k, alg)
		if err != nil {
			return JWKSet{}, err
		}
		if i, seen := position[k.KeyID]; seen {
			set.Keys[i] = jwk
			continue
		}
		position[k.KeyID] = len(set.Keys)
		set.Keys = append(set.Keys, jwk)
	}
	return set, nil
}

func rsaJWK(k PublicKey, alg Algorithm) (JWK, error) {
	pub, err := parseRSAPublicKey(k.PEM)
	if err != nil {
		return JWK{}, fmt.Errorf("JWKS rendering currently supports RSA public keys only: %w", err)
	}
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: string(alg),
		Kid: k.KeyID,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}, nil
}

func okpJWK(k PublicKey, alg Algorithm) (JWK, error) {
	pub := []byte(k.PEM)
	if len(pub) != ed25519.PublicKeySize || !ed25519Canonical(pub) || ed25519SmallOrder(pub) {
		return JWK{}, fmt.Errorf("%w: the EdDSA public key %q must be 32 raw bytes of a valid Ed25519 point", ErrInvalidConfig, k.KeyID)
	}
	return JWK{Kty: "OKP", Crv: "Ed25519", Use: "sig", Alg: string(alg), Kid: k.KeyID, X: base64.RawURLEncoding.EncodeToString(pub)}, nil
}
