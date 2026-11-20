package token

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// minRSABits is lcobucci/jwt's floor for RSA keys, signing and verifying alike.
const minRSABits = 2048

// signFunc signs a JWS signing input; verifyFunc checks a signature over one.
type (
	signFunc   func(input []byte) ([]byte, error)
	verifyFunc func(input, sig []byte) bool
)

func newVerifier(alg Algorithm, publicKey string) (verifyFunc, error) {
	switch alg {
	case RS256:
		pub, err := parseRSAPublicKey(publicKey)
		if err != nil {
			return nil, err
		}
		if pub.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("%w: the RSA public key has %d bits; at least %d are required", ErrInvalidConfig, pub.N.BitLen(), minRSABits)
		}
		return func(input, sig []byte) bool {
			digest := sha256.Sum256(input)
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil
		}, nil
	case EdDSA:
		pub := []byte(publicKey)
		if len(pub) != ed25519.PublicKeySize || !ed25519Canonical(pub) || ed25519SmallOrder(pub) {
			return nil, fmt.Errorf("%w: the EdDSA public key must be 32 raw bytes of a valid Ed25519 point", ErrInvalidConfig)
		}
		return func(input, sig []byte) bool { return verifyEd25519(pub, input, sig) }, nil
	}
	return nil, unsupportedAlgorithm(alg)
}

func newSigner(alg Algorithm, privateKey string) (signFunc, error) {
	switch alg {
	case RS256:
		priv, err := parseRSAPrivateKey(privateKey)
		if err != nil {
			return nil, err
		}
		return func(input []byte) ([]byte, error) {
			digest := sha256.Sum256(input)
			return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		}, nil
	case EdDSA:
		if len(privateKey) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: the EdDSA private key must be the 64 raw bytes of a libsodium secret key", ErrInvalidConfig)
		}
		priv := ed25519.PrivateKey(privateKey)
		return func(input []byte) ([]byte, error) { return ed25519.Sign(priv, input), nil }, nil
	}
	return nil, unsupportedAlgorithm(alg)
}

func unsupportedAlgorithm(alg Algorithm) error {
	return fmt.Errorf("%w: unsupported access-token signer %q; expected RS256 or EdDSA", ErrInvalidConfig, alg)
}

// parseRSAPublicKey reads what openssl_pkey_get_public reads from PEM: an SPKI public key, a
// PKCS#1 RSA public key or a certificate. Only RSA keys pass.
func parseRSAPublicKey(data string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("%w: the JWT public key is not PEM", ErrInvalidConfig)
	}
	var key any
	var err error
	switch block.Type {
	case "PUBLIC KEY":
		key, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "CERTIFICATE":
		var cert *x509.Certificate
		if cert, err = x509.ParseCertificate(block.Bytes); err == nil {
			key = cert.PublicKey
		}
	default:
		err = fmt.Errorf("unexpected PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the JWT public key could not be parsed: %w", ErrInvalidConfig, err)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: an RSA public key is required, got %T", ErrInvalidConfig, key)
	}
	return pub, nil
}

// parseRSAPrivateKey reads an unencrypted PKCS#1 or PKCS#8 RSA private key PEM.
func parseRSAPrivateKey(data string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, fmt.Errorf("%w: the JWT private key is not PEM", ErrInvalidConfig)
	}
	var key any
	var err error
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		err = fmt.Errorf("unexpected PEM block %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: the JWT private key could not be parsed: %w", ErrInvalidConfig, err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: RS256 needs an RSA private key, got %T", ErrInvalidConfig, key)
	}
	if priv.N.BitLen() < minRSABits {
		return nil, fmt.Errorf("%w: the RSA private key has %d bits; at least %d are required", ErrInvalidConfig, priv.N.BitLen(), minRSABits)
	}
	return priv, nil
}

// verifyEd25519 is libsodium's crypto_sign_verify_detached: on top of Go's RFC 8032 check
// (canonical S), it refuses a small-order R, as upstream does.
func verifyEd25519(pub ed25519.PublicKey, input, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize || ed25519SmallOrder(sig[:32]) {
		return false
	}
	return ed25519.Verify(pub, input, sig)
}

// ed25519Blocklist is libsodium's ge25519_has_small_order list: encodings of the points of
// order 1, 2, 4 and 8, plus the non-canonical encodings of 0 and 1. The sign bit is ignored.
var ed25519Blocklist = [7][32]byte{
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

func ed25519SmallOrder(p []byte) bool {
	var masked [32]byte
	copy(masked[:], p)
	masked[31] &= 0x7f
	found := 0
	for i := range ed25519Blocklist {
		found |= subtle.ConstantTimeCompare(masked[:], ed25519Blocklist[i][:])
	}
	return found == 1
}

// ed25519Canonical is libsodium's ge25519_is_canonical: the encoded y is below p = 2^255-19.
func ed25519Canonical(p []byte) bool {
	if p[31]&0x7f != 0x7f {
		return true
	}
	for i := 30; i > 0; i-- {
		if p[i] != 0xff {
			return true
		}
	}
	return p[0] < 0xed
}
