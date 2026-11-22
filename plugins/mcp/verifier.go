package mcp

import (
	"github.com/univeros/polaris.go/internal/jwtverify"
)

const (
	// MinJWKSRefetch is how often an unknown kid may make the resource server fetch the issuer's
	// JWK Set again: an unauthenticated JWT naming any kid is not a refetch amplifier.
	MinJWKSRefetch = jwtverify.MinRefetch
	// DefaultJWKSTTL is how long a fetched JWK Set is used before it is fetched again.
	DefaultJWKSTTL = jwtverify.DefaultTTL
)

// errUnavailable is what a client is told when the issuer's keys cannot be read; the reason is
// logged, never answered.
var errUnavailable = jwtverify.ErrUnavailable

// invalid is a refused token or proof; its text is what the client reads.
type invalid = jwtverify.Invalid

var (
	compactJWT = jwtverify.Compact
	jwtHeader  = jwtverify.Header
	parseJWK   = jwtverify.ParseJWK
	verifyJWS  = jwtverify.VerifyJWS
	scopesOf   = jwtverify.Scopes
)
