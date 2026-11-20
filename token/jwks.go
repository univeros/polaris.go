package token

import (
	"encoding/base64"
	"fmt"
	"math/big"
)

// JWK is one RSA signing key of a JWK Set (RFC 7517). Field order is the wire order.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet is the document served at /auth/.well-known/jwks.json.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// PublicKey is a PEM public key published under a kid.
type PublicKey struct {
	KeyID string
	PEM   string
}

// NewJWKSet renders public keys as a JWK Set, in order: during a rotation the active key and
// the retiring one are published side by side (docs/auth/key-rotation.md). A kid given twice
// keeps its first position and its last key, as upstream's kid-keyed array does.
//
// Only RSA keys are supported, as upstream: an unparseable or non-RSA key fails with
// ErrInvalidConfig rather than serving a malformed set.
func NewJWKSet(alg Algorithm, keys ...PublicKey) (JWKSet, error) {
	set := JWKSet{Keys: make([]JWK, 0, len(keys))}
	position := make(map[string]int, len(keys))
	for _, k := range keys {
		jwk, err := rsaJWK(k, alg)
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
