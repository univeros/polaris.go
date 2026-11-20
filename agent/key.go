package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
)

// Algorithm is the JOSE algorithm an agent signs with.
type Algorithm string

// The algorithms Polaris accepts for an agent's key.
const (
	ES256 Algorithm = "ES256" // ECDSA over P-256 with SHA-256
	EdDSA Algorithm = "EdDSA" // Ed25519
)

// JWK is a JSON Web Key as Polaris exchanges it: an agent's public key (EC P-256 or OKP Ed25519)
// or one of the server's keys in its JWKS (RSA, EC or OKP). It never carries a private part.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

// Key is an agent's key pair. The private part stays here and signs the request JWTs and the
// private_key_jwt assertions; PublicJWK goes to Polaris at registration. Persist it with Export
// and load it back with ImportKey. A Key is safe for concurrent use.
type Key struct {
	alg    Algorithm
	kid    string
	ec     *ecdsa.PrivateKey
	ed     ed25519.PrivateKey
	public JWK
}

// GenerateKey makes a new key pair; its kid is the RFC 7638 thumbprint of the public key.
func GenerateKey(alg Algorithm) (*Key, error) {
	switch alg {
	case ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("agent: generate P-256 key: %w", err)
		}
		return NewKey(k, "")
	case EdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("agent: generate Ed25519 key: %w", err)
		}
		return NewKey(k, "")
	}
	return nil, fmt.Errorf("agent: algorithm %q: use agent.ES256 or agent.EdDSA", alg)
}

// NewKey wraps an existing private key: an *ecdsa.PrivateKey on P-256 (ES256) or an
// ed25519.PrivateKey (EdDSA). An empty kid becomes the RFC 7638 thumbprint.
func NewKey(private crypto.PrivateKey, kid string) (*Key, error) {
	var k Key
	switch p := private.(type) {
	case *ecdsa.PrivateKey:
		if p.Curve != elliptic.P256() {
			return nil, errors.New("agent: the ECDSA key must be on P-256 (ES256)")
		}
		point, err := p.PublicKey.Bytes()
		if err != nil {
			return nil, fmt.Errorf("agent: P-256 public key: %w", err)
		}
		k = Key{alg: ES256, ec: p, public: JWK{Kty: "EC", Crv: "P-256", X: b64(point[1:33]), Y: b64(point[33:])}}
	case ed25519.PrivateKey:
		if len(p) != ed25519.PrivateKeySize {
			return nil, errors.New("agent: an Ed25519 private key is 64 bytes")
		}
		k = Key{alg: EdDSA, ed: p, public: JWK{Kty: "OKP", Crv: "Ed25519", X: b64(p.Public().(ed25519.PublicKey))}}
	default:
		return nil, fmt.Errorf("agent: unsupported private key %T: use *ecdsa.PrivateKey (P-256) or ed25519.PrivateKey", private)
	}
	if kid == "" {
		var err error
		if kid, err = Thumbprint(k.public); err != nil {
			return nil, err
		}
	}
	k.kid = kid
	k.public.Alg, k.public.Kid, k.public.Use = string(k.alg), kid, "sig"
	return &k, nil
}

// storedKey is the stored form, the same as the PHP SDK's AgentKey::toArray(): a key exported by
// one SDK imports in the other.
type storedKey struct {
	Alg    Algorithm `json:"alg"`
	Kid    string    `json:"kid,omitempty"`
	Secret string    `json:"secret"`
	JWK    *JWK      `json:"jwk,omitempty"`
}

// Export is the key with its private part, for the agent's own storage (a secrets manager, a 0600
// file): JSON with alg, kid, secret (the PKCS #8 PEM for ES256, the base64 64-byte Ed25519 secret
// key for EdDSA) and the public jwk. Never send it anywhere else.
func (k *Key) Export() ([]byte, error) {
	s := storedKey{Alg: k.alg, Kid: k.kid, JWK: &k.public}
	if k.ec != nil {
		der, err := x509.MarshalPKCS8PrivateKey(k.ec)
		if err != nil {
			return nil, fmt.Errorf("agent: export key: %w", err)
		}
		s.Secret = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	} else {
		s.Secret = base64.StdEncoding.EncodeToString(k.ed)
	}
	return json.Marshal(s) //nolint:gosec // G117: exporting the key is this method's purpose (the caller stores it as a secret)
}

// ImportKey loads a key from Export's output (or the PHP SDK's AgentKey::toArray() as JSON).
func ImportKey(stored []byte) (*Key, error) {
	var s storedKey
	if err := json.Unmarshal(stored, &s); err != nil || s.Secret == "" {
		return nil, errors.New("agent: a stored key is JSON with alg, secret and an optional kid")
	}
	switch s.Alg {
	case EdDSA:
		raw, err := base64.StdEncoding.DecodeString(s.Secret)
		if err != nil || len(raw) != ed25519.PrivateKeySize {
			return nil, errors.New("agent: the EdDSA secret is a base64 64-byte Ed25519 secret key")
		}
		p := ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])
		if !p.Equal(ed25519.PrivateKey(raw)) {
			return nil, errors.New("agent: the EdDSA secret's public half does not match its seed")
		}
		return NewKey(p, s.Kid)
	case ES256:
		p, err := parseECPEM(s.Secret)
		if err != nil {
			return nil, err
		}
		return NewKey(p, s.Kid)
	}
	return nil, fmt.Errorf("agent: stored key algorithm %q: expected ES256 or EdDSA", s.Alg)
}

func parseECPEM(text string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("agent: the ES256 secret is not a PEM private key")
	}
	if p, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if ec, ok := p.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, errors.New("agent: the PEM is not a P-256 private key")
	}
	ec, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("agent: the PEM is not a P-256 private key")
	}
	return ec, nil
}

// Alg is the algorithm the key signs with.
func (k *Key) Alg() Algorithm { return k.alg }

// KID is the key id: the RFC 7638 thumbprint unless one was given.
func (k *Key) KID() string { return k.kid }

// PublicJWK is the public key with alg, kid and use, as POST /agents/register and /agents/enroll
// take it.
func (k *Key) PublicJWK() JWK { return k.public }

// String never prints the private part.
func (k *Key) String() string { return fmt.Sprintf("agent.Key(%s, kid=%s)", k.alg, k.kid) }

// LogValue keeps the private part out of slog output.
func (k *Key) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alg", string(k.alg)), slog.String("kid", k.kid))
}

// sign is the JWS signature over the signing input: raw r‖s for ES256, Ed25519 for EdDSA.
func (k *Key) sign(input []byte) ([]byte, error) {
	if k.ed != nil {
		return ed25519.Sign(k.ed, input), nil
	}
	digest := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, k.ec, digest[:])
	if err != nil {
		return nil, fmt.Errorf("agent: sign: %w", err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// Thumbprint is the RFC 7638 thumbprint of a public JWK (SHA-256 over its required members,
// base64url).
func Thumbprint(jwk JWK) (string, error) {
	var canonical any
	switch jwk.Kty {
	case "EC":
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return "", errors.New("agent: thumbprint: an EC key needs crv, x and y")
		}
		canonical = map[string]string{"crv": jwk.Crv, "kty": jwk.Kty, "x": jwk.X, "y": jwk.Y}
	case "OKP":
		if jwk.Crv == "" || jwk.X == "" {
			return "", errors.New("agent: thumbprint: an OKP key needs crv and x")
		}
		canonical = map[string]string{"crv": jwk.Crv, "kty": jwk.Kty, "x": jwk.X}
	case "RSA":
		if jwk.N == "" || jwk.E == "" {
			return "", errors.New("agent: thumbprint: an RSA key needs n and e")
		}
		canonical = map[string]string{"e": jwk.E, "kty": jwk.Kty, "n": jwk.N}
	default:
		return "", fmt.Errorf("agent: no thumbprint for key type %q", jwk.Kty)
	}
	// encoding/json sorts map keys, which is RFC 7638's lexicographic order.
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("agent: thumbprint: %w", err)
	}
	sum := sha256.Sum256(data)
	return b64(sum[:]), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
