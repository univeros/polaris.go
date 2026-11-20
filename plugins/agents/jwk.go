package agents

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"regexp"

	"github.com/univeros/polaris-go/plugins/oauth"
)

// The algorithms an agent key signs with.
const (
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

var (
	algorithms     = []string{AlgES256, AlgEdDSA}
	coordinate     = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
	kidFormat      = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}
)

// algorithmOf is the JOSE algorithm a key signs with by its type and curve, "" for a key the
// plugin does not take.
func algorithmOf(jwk map[string]any) string {
	_, hasX := jwk["x"]
	_, hasY := jwk["y"]
	switch {
	case jwk["kty"] == "EC" && jwk["crv"] == "P-256" && hasX && hasY && jwk["x"] != nil && jwk["y"] != nil:
		return AlgES256
	case jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519" && hasX && jwk["x"] != nil:
		return AlgEdDSA
	}
	return ""
}

// publicJWK validates an agent's public key (EC P-256 or OKP Ed25519, public part only) and returns
// what is stored: the key members, alg, kid (the agent's, or the RFC 7638 thumbprint) and use sig.
func publicJWK(v any) (map[string]any, error) {
	jwk, ok := v.(map[string]any)
	if !ok {
		return nil, refuse(ErrInvalidInput, "jwk is required for private_key_jwt: the agent's public key as a JWK (EC P-256 or OKP Ed25519).")
	}
	for _, m := range privateMembers {
		if jwk[m] != nil {
			return nil, refuse(ErrInvalidInput, "jwk must be the public part of the key only.")
		}
	}
	alg := algorithmOf(jwk)
	if alg == "" {
		return nil, refuse(ErrInvalidInput, "jwk is an EC key on P-256 (x, y) or an OKP key on Ed25519 (x).")
	}
	for _, c := range []string{"x", "y"} {
		if jwk[c] == nil {
			continue
		}
		if s, ok := jwk[c].(string); !ok || !coordinate.MatchString(s) {
			return nil, refuse(ErrInvalidInput, "jwk coordinates are base64url.")
		}
	}
	if a := jwk["alg"]; a != nil && a != alg {
		return nil, refuse(ErrInvalidInput, "jwk.alg does not match the key type.")
	}
	kid := jwk["kid"]
	if kid != nil {
		if s, ok := kid.(string); !ok || !kidFormat.MatchString(s) {
			return nil, refuse(ErrInvalidInput, "jwk.kid is at most 128 characters.")
		}
	}
	thumbprint, err := oauth.Thumbprint(jwk)
	if err != nil {
		var oe *oauth.Error
		if errors.As(err, &oe) {
			return nil, refuse(ErrInvalidInput, "jwk: "+oe.Description)
		}
		return nil, refuse(ErrInvalidInput, "jwk: the key cannot be read.")
	}
	if _, err := verifierOf(jwk); err != nil {
		return nil, refuse(ErrInvalidInput, "jwk: the key is not a point of its curve.")
	}
	out := map[string]any{"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"]}
	if jwk["y"] != nil {
		out["y"] = jwk["y"]
	}
	if kid == nil {
		kid = thumbprint
	}
	out["alg"], out["kid"], out["use"] = alg, kid, "sig"
	return out, nil
}

// verifierOf returns a function checking a JWS signature over input with the key.
func verifierOf(jwk map[string]any) (func(input, sig []byte) bool, error) {
	decode := func(m string) []byte {
		s, _ := jwk[m].(string)
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		return b
	}
	switch algorithmOf(jwk) {
	case AlgES256:
		x, y := decode("x"), decode("y")
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("agents: P-256 coordinates are 32 bytes")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, err
		}
		return func(input, sig []byte) bool {
			if len(sig) != 64 {
				return false
			}
			sum := sha256.Sum256(input)
			return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}, nil
	case AlgEdDSA:
		x := decode("x")
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("agents: an Ed25519 key is 32 bytes")
		}
		pub := ed25519.PublicKey(x)
		return func(input, sig []byte) bool { return ed25519.Verify(pub, input, sig) }, nil
	}
	return nil, errors.New("agents: unsupported key")
}
