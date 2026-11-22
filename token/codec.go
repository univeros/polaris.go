package token

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/univeros/polaris.go/clock"
)

// Algorithm is a JWS signing algorithm (JWA name), as advertised in the token header and JWKS.
type Algorithm string

// The supported, asymmetric signing algorithms.
const (
	RS256 Algorithm = "RS256" // RSASSA-PKCS1-v1_5 with SHA-256, PEM keys of at least 2048 bits
	EdDSA Algorithm = "EdDSA" // Ed25519, raw libsodium keys (64-byte secret, 32-byte public)
)

// managedClaims are owned by the Codec: a caller-supplied value is dropped.
var managedClaims = map[string]bool{"iss": true, "aud": true, "iat": true, "exp": true, "nbf": true}

// Config configures a Codec. The keys are the AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY
// values as they are.
type Config struct {
	// Algorithm is RS256 (the default when empty) or EdDSA.
	Algorithm Algorithm
	// PublicKey verifies tokens: a PEM public key (SPKI, PKCS#1 or certificate) for RS256,
	// the 32 raw bytes of an Ed25519 public key for EdDSA. Required.
	PublicKey string
	// PrivateKey signs tokens: an unencrypted PEM private key (PKCS#1 or PKCS#8) for RS256,
	// the 64 raw bytes of a libsodium secret key for EdDSA. Optional: without it the Codec
	// verifies only.
	PrivateKey string
	// KeyID is the kid header of minted tokens.
	KeyID string
	// Issuer is the iss claim minted and required. Required.
	Issuer string
	// Audience, when set, is the aud claim minted and required; when empty, a token naming
	// any audience is refused as an access token.
	Audience string
	// PreviousPublicKey and PreviousKeyID are the retiring key during a rotation
	// (AUTH_JWT_PREVIOUS_PUBLIC_KEY / AUTH_JWT_PREVIOUS_KID): VerifyJWT accepts tokens naming
	// PreviousKeyID with it. Set both or neither. Session tokens (Parse, Verify) never use it.
	PreviousPublicKey string
	PreviousKeyID     string
	// TTL is the lifetime of minted tokens, in whole seconds.
	TTL time.Duration
	// Clock stamps and checks iat/nbf/exp; nil means clock.System.
	Clock clock.Clock
}

// Codec mints and verifies JWTs for one configuration. It is immutable and safe for
// concurrent use; it never logs key material.
type Codec struct {
	alg      Algorithm
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
	clock    clock.Clock
	sign     signFunc // nil when no private key is configured
	verify   verifyFunc
	prevKID  string
	prevVer  verifyFunc // nil outside a rotation
}

// New validates cfg and parses its keys. Errors wrap ErrInvalidConfig and name the fix.
func New(cfg Config) (*Codec, error) {
	if cfg.Algorithm == "" {
		cfg.Algorithm = RS256
	}
	if cfg.PublicKey == "" {
		return nil, fmt.Errorf("%w: the public key must be a non-empty string (set AUTH_JWT_PUBLIC_KEY)", ErrInvalidConfig)
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("%w: the issuer must be a non-empty string", ErrInvalidConfig)
	}
	if cfg.TTL < 0 || cfg.TTL%time.Second != 0 {
		return nil, fmt.Errorf("%w: the TTL must be a non-negative whole number of seconds, got %s", ErrInvalidConfig, cfg.TTL)
	}
	verify, err := newVerifier(cfg.Algorithm, cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	var prevVer verifyFunc
	if (cfg.PreviousPublicKey == "") != (cfg.PreviousKeyID == "") {
		return nil, fmt.Errorf("%w: set both the previous public key and its kid, or neither (AUTH_JWT_PREVIOUS_PUBLIC_KEY, AUTH_JWT_PREVIOUS_KID)", ErrInvalidConfig)
	}
	if cfg.PreviousPublicKey != "" {
		if prevVer, err = newVerifier(cfg.Algorithm, cfg.PreviousPublicKey); err != nil {
			return nil, fmt.Errorf("previous key: %w", err)
		}
	}
	var sign signFunc
	if cfg.PrivateKey != "" {
		if sign, err = newSigner(cfg.Algorithm, cfg.PrivateKey); err != nil {
			return nil, err
		}
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	return &Codec{
		alg: cfg.Algorithm, kid: cfg.KeyID, issuer: cfg.Issuer, audience: cfg.Audience,
		ttl: cfg.TTL, clock: clk, sign: sign, verify: verify, prevKID: cfg.PreviousKeyID, prevVer: prevVer,
	}, nil
}

// now is the clock at the microsecond precision of date claims.
func (c *Codec) now() time.Time { return c.clock.Now().Truncate(time.Microsecond) }

// Issue mints a signed JWT carrying claims. The header is {"typ":"JWT","alg":…,"kid":…};
// the payload starts with the managed iss, iat, nbf, exp (and aud when configured), then
// claims in order. Caller-supplied iss/aud/iat/nbf/exp and empty names are dropped; sub and
// jti must be strings.
func (c *Codec) Issue(claims Claims) (string, error) {
	if c.sign == nil {
		return "", fmt.Errorf("%w: a private key is required to generate a token (set AUTH_JWT_PRIVATE_KEY)", ErrInvalidConfig)
	}
	now := c.now()
	payload := Claims{}.
		With("iss", c.issuer).
		With("iat", encodeInstant(now)).
		With("nbf", encodeInstant(now)).
		With("exp", encodeInstant(now.Add(c.ttl)))
	if c.audience != "" {
		payload = payload.With("aud", c.audience)
	}
	for _, name := range claims.names {
		if name == "" || managedClaims[name] {
			continue
		}
		value := claims.values[name]
		if name == "sub" || name == "jti" {
			if _, ok := value.(string); !ok {
				return "", fmt.Errorf("%w: claim %q must be a string, got %T", errUnencodable, name, value)
			}
		}
		payload = payload.With(name, value)
	}
	return c.signJWT("JWT", payload)
}

// signJWT encodes {"typ":…,"alg":…,"kid":…} and payload and signs them.
func (c *Codec) signJWT(typ string, payload Claims) (string, error) {
	header := Claims{}.With("typ", typ).With("alg", string(c.alg)).With("kid", c.kid)
	headerJSON, err := header.MarshalJSON()
	if err != nil {
		return "", err
	}
	payloadJSON, err := payload.MarshalJSON()
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig, err := c.sign([]byte(input))
	if err != nil {
		return "", fmt.Errorf("token: signing: %w", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify parses raw and checks what every Polaris JWT must pass: structure, the configured
// algorithm and signature, the issuer, the validity window (iat and nbf not in the future,
// exp not reached; absent claims pass) and, when configured, the audience.
//
// It is the check for single-purpose tickets (MFA login, step-up), which carry a purpose
// claim; access tokens go through Parse. Failures wrap ErrInvalidToken.
func (c *Codec) Verify(raw string) (*Token, error) {
	if raw == "" {
		return nil, invalid("could not parse the authorization token")
	}
	seg, err := splitToken(raw)
	if err != nil {
		return nil, err
	}
	if alg, _ := seg.header["alg"].(string); alg != string(c.alg) {
		return nil, invalid("token signer mismatch")
	}
	if !c.verify([]byte(seg.signingInput), seg.signature) {
		return nil, invalid("token signature mismatch")
	}
	if iss, ok := seg.claims["iss"].(string); !ok || iss != c.issuer {
		return nil, invalid("the token was not issued by the given issuers")
	}
	if err := checkWindow(seg.claims, c.now(), 0); err != nil {
		return nil, err
	}
	if c.audience != "" && !permittedFor(seg.claims, c.audience) {
		return nil, invalid("the token is not allowed to be used by this audience")
	}
	return &Token{raw: raw, header: seg.header, claims: seg.claims}, nil
}

// Parse verifies raw as an access token: Verify, then the Polaris rules. A token bearing a
// purpose claim (a single-purpose ticket), a typ header other than JWT (an OAuth at+jwt, an
// ID token, a DPoP proof), an aud claim while no audience is configured, or no iat or exp is
// refused. Failures wrap ErrInvalidToken.
func (c *Codec) Parse(raw string) (*Token, error) {
	tok, err := c.Verify(raw)
	if err != nil {
		return nil, err
	}
	if tok.claims["purpose"] != nil {
		return nil, invalid("a single-purpose token cannot be used as an access token")
	}
	if typ, ok := tok.header["typ"].(string); ok && typ != "" && asciiUpper(typ) != "JWT" {
		return nil, invalid("a %s token cannot be used as an access token", typ)
	}
	if c.audience == "" && tok.claims["aud"] != nil {
		return nil, invalid("a token for an audience cannot be used as an access token here")
	}
	for _, name := range [...]string{"iat", "exp"} {
		if tok.claims[name] == nil {
			return nil, invalid("access token is missing the required %q claim", name)
		}
	}
	return tok, nil
}

// LogValue keeps key material out of logs.
func (c *Codec) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alg", string(c.alg)), slog.String("kid", c.kid), slog.String("iss", c.issuer))
}

// String keeps key material out of fmt output.
func (c *Codec) String() string { return "token.Codec" + c.LogValue().String() }

// GoString keeps key material out of %#v output.
func (c *Codec) GoString() string { return c.String() }

// LogValue keeps the private key out of logs.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(slog.String("alg", string(c.Algorithm)), slog.String("kid", c.KeyID),
		slog.String("iss", c.Issuer), slog.String("aud", c.Audience), slog.Duration("ttl", c.TTL))
}

// String keeps the private key out of fmt output.
func (c Config) String() string { return "token.Config" + c.LogValue().String() }

// GoString keeps the private key out of %#v output.
func (c Config) GoString() string { return c.String() }

// checkWindow checks the validity window: iat and nbf at most now+leeway, exp after
// now-leeway; absent claims pass.
func checkWindow(claims map[string]any, now time.Time, leeway time.Duration) error {
	if iat, ok := claims["iat"].(time.Time); ok && now.Add(leeway).Before(iat) {
		return invalid("the token was issued in the future")
	}
	if nbf, ok := claims["nbf"].(time.Time); ok && now.Add(leeway).Before(nbf) {
		return invalid("the token cannot be used yet")
	}
	if exp, ok := claims["exp"].(time.Time); ok && !now.Add(-leeway).Before(exp) {
		return invalid("the token is expired")
	}
	return nil
}

func permittedFor(claims map[string]any, audience string) bool {
	list, _ := claims["aud"].([]any)
	for _, a := range list {
		if s, ok := a.(string); ok && s == audience {
			return true
		}
	}
	return false
}

// asciiUpper upper-cases ASCII letters only (strings.ToUpper would also map other Unicode).
func asciiUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}
