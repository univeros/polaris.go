package session

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/token"
)

// ErrReservedClaim reports a host claim (Config.Claims) whose name Polaris or a standard reserves,
// or that the token already carries.
var ErrReservedClaim = errors.New("session: reserved claim name")

// reservedClaims are names a host claim may never take: RFC 7519's registered claims, the
// protocol claims of OAuth / OIDC / token exchange / DPoP, and every claim core or a plugin sets.
var reservedClaims = map[string]bool{
	// RFC 7519
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	// OAuth 2.0 / OIDC / RFC 8693 / RFC 9068 / RFC 9449
	"typ": true, "azp": true, "nonce": true, "at_hash": true, "c_hash": true, "acr": true, "amr": true,
	"auth_time": true, "sid": true, "cnf": true, "act": true, "may_act": true, "scope": true,
	"scp": true, "client_id": true, "email_verified": true,
	// Polaris core and plugins
	"org": true, "roles": true, "mfa": true, "delegated": true, "impersonated_by": true, "impersonator_type": true,
	"purpose": true, "mfa_factors": true, "api_key": true, "api_key_rate_limit": true, "agent_id": true,
	"actor_type": true, "receipt_id": true, "receipt_hash": true, "seq": true,
}

// ReservedClaim reports whether a host may not add a claim called name: an empty name, a standard
// or Polaris claim, or any name starting with "polaris".
func ReservedClaim(name string) bool {
	return name == "" || reservedClaims[name] || strings.HasPrefix(strings.ToLower(name), "polaris")
}

// hostClaims appends Config.Claims' claims to claims, in name order, refusing a reserved name or
// one the token already carries.
func (s *Service) hostClaims(ctx context.Context, p token.SessionPrincipal, claims token.Claims) (token.Claims, error) {
	if s.claims == nil {
		return claims, nil
	}
	extra, err := s.claims(ctx, p)
	if err != nil {
		return claims, fmt.Errorf("Claims hook: %w", err)
	}
	for _, name := range slices.Sorted(maps.Keys(extra)) {
		if _, taken := claims.Get(name); taken || ReservedClaim(name) {
			return claims, fmt.Errorf("%w: the Claims hook returned %q; use a namespaced name such as \"app_%s\" or \"https://example.com/%s\"", ErrReservedClaim, name, name, name)
		}
		claims = claims.With(name, extra[name])
	}
	return claims, nil
}
