// Package token mints and verifies Polaris access tokens: asymmetric JWTs (RS256 or EdDSA)
// with a kid header, managed iss/aud/iat/nbf/exp claims and the Polaris claim set, plus the
// JWK Set that publishes the verification keys.
//
// The wire format is frozen (spec §3.3): for the same key, clock and claims, Codec.Issue
// produces the same bytes as upstream's PolarisTokenGenerator (lcobucci/jwt), and Codec.Parse
// accepts and rejects exactly what upstream's PolarisTokenParser does.
package token

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"time"
)

var (
	// ErrInvalidToken reports a token that cannot be parsed or fails verification.
	ErrInvalidToken = errors.New("token: invalid token")
	// ErrInvalidConfig reports unusable token configuration (keys, issuer, algorithm, TTL).
	ErrInvalidConfig = errors.New("token: invalid configuration")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, args...))
}

// Token is a parsed, verified JWT: its raw form and its claims.
//
// Claim values are as upstream's TokenInterface::getMetadata returns them: iat, nbf and exp
// are time.Time (microsecond precision), aud is a []any list, integers are int64, other
// numbers float64, objects map[string]any, arrays []any.
type Token struct {
	raw        string
	header     map[string]any
	claims     map[string]any
	delegation *delegation // set in-process only (Delegate)
}

// Raw returns the compact JWT. It is a bearer credential: never log it.
func (t *Token) Raw() string { return t.raw }

// Header returns the protected header parameter named name, or nil when it is absent.
func (t *Token) Header(name string) any { return t.header[name] }

// Claim returns the claim named name, or nil when it is absent or null.
func (t *Token) Claim(name string) any { return t.claims[name] }

// Claims returns a shallow copy of every claim.
func (t *Token) Claims() map[string]any { return maps.Clone(t.claims) }

// Subject returns the sub claim, or "" when it is absent or not a string.
func (t *Token) Subject() string { s, _ := t.claims["sub"].(string); return s }

// ID returns the jti claim, or "" when it is absent or not a string.
func (t *Token) ID() string { s, _ := t.claims["jti"].(string); return s }

// IssuedAt returns the iat claim, or the zero time when it is absent.
func (t *Token) IssuedAt() time.Time { v, _ := t.claims["iat"].(time.Time); return v }

// ExpiresAt returns the exp claim, or the zero time when it is absent.
func (t *Token) ExpiresAt() time.Time { v, _ := t.claims["exp"].(time.Time); return v }

// LogValue logs the token's identity, never the bearer string.
func (t *Token) LogValue() slog.Value {
	return slog.GroupValue(slog.String("sub", t.Subject()), slog.String("jti", t.ID()))
}

// String prints the token's identity, never the bearer string.
func (t *Token) String() string { return "token.Token" + t.LogValue().String() }

// GoString keeps the bearer string out of %#v output.
func (t *Token) GoString() string { return t.String() }
