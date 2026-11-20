package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris-go/clock"
)

const (
	// tokenLeeway is the clock skew allowed on an access token's exp, nbf and iat.
	tokenLeeway = 60 * time.Second
	// MinJWKSRefetch is how often an unknown kid may make the resource server fetch the issuer's
	// JWK Set again: an unauthenticated JWT naming any kid is not a refetch amplifier.
	MinJWKSRefetch = time.Minute
	// DefaultJWKSTTL is how long a fetched JWK Set is used before it is fetched again.
	DefaultJWKSTTL = time.Hour
	maxJWKSBytes   = 64 << 10
)

// errUnavailable is what a client is told when the issuer's keys cannot be read; the reason is
// logged, never answered.
var errUnavailable = errors.New("The token could not be verified against the issuer's keys.")

// verifier checks an access token locally, as a resource server does (RFC 9068 §4): the signature
// by kid, iss, an aud naming this resource, exp and nbf with a minute's leeway. The DPoP binding
// is the caller's to check.
type verifier struct {
	issuer    string
	audiences []string
	clock     clock.Clock
	keys      map[string]any // local keys by kid, when there is no remote set
	jwks      *jwks
}

type invalid string

func (e invalid) Error() string { return string(e) }

func (v *verifier) verify(ctx context.Context, raw string) (map[string]any, error) {
	if !compactJWT.MatchString(raw) {
		return nil, invalid("The token is not a JWT.")
	}
	header := jwtHeader(raw)
	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)
	if kid == "" || !slices.Contains(Algorithms, alg) {
		return nil, invalid("The token needs a kid and an asymmetric alg.")
	}
	// The issuer signs more than access tokens with this key (DPoP proofs, agent request JWTs,
	// receipts, login-MFA tickets): only an at+jwt or a session access token (typ JWT or none) is
	// one, and a single-purpose ticket never is.
	if typHeader, present := header["typ"]; present {
		if typ, _ := typHeader.(string); !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "JWT") {
			return nil, invalid("The token is not an access token.")
		}
	}
	key, err := v.key(ctx, kid, alg)
	if err != nil {
		return nil, err
	}
	claims, err := verifyJWS(raw, alg, key, v.clock.Now(), tokenLeeway)
	if err != nil {
		return nil, invalid("The token does not verify.")
	}
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, invalid("The token is from another issuer.")
	}
	if _, ok := number(claims["exp"]); !ok {
		return nil, invalid("The token has no expiry.")
	}
	if claims["purpose"] != nil {
		return nil, invalid("A single-purpose token is not an access token.")
	}
	if !audienceIncludes(claims["aud"], v.audiences) {
		return nil, invalid("The token is meant for another resource.")
	}
	return claims, nil
}

func audienceIncludes(aud any, accepted []string) bool {
	switch a := aud.(type) {
	case string:
		return slices.Contains(accepted, a)
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && slices.Contains(accepted, s) {
				return true
			}
		}
	}
	return false
}

func (v *verifier) key(ctx context.Context, kid, alg string) (any, error) {
	if v.jwks == nil {
		if key, ok := v.keys[kid]; ok {
			return key, nil
		}
		return nil, invalid("The token names an unknown signing key.")
	}
	for _, fresh := range []bool{false, true} {
		set, err := v.jwks.keys(ctx, fresh)
		if err != nil {
			return nil, err
		}
		for _, jwk := range set {
			if jwk["kid"] == kid {
				key, err := parseJWK(jwk, alg)
				if err != nil {
					return nil, invalid("The token does not verify.")
				}
				return key, nil
			}
		}
	}
	return nil, invalid("The token names an unknown signing key.")
}

// jwks is a remote issuer's JWK Set, fetched from the configured URL alone (never one a token
// names), bounded in size and kept in memory for ttl; an unknown kid fetches it again at most once
// per MinJWKSRefetch, which is how a key rotation reaches the resource server.
type jwks struct {
	url    string
	client *http.Client
	ttl    time.Duration
	clock  clock.Clock
	log    func(msg string, args ...any)

	mu        sync.Mutex // held across a fetch: concurrent misses wait for one request
	set       []map[string]any
	fetchedAt time.Time
	refetched time.Time
}

func (j *jwks) keys(ctx context.Context, fresh bool) ([]map[string]any, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.clock.Now()
	cached := j.set != nil && now.Sub(j.fetchedAt) < j.ttl
	if cached && !fresh {
		return j.set, nil
	}
	if cached {
		if now.Sub(j.refetched) < MinJWKSRefetch {
			return j.set, nil
		}
		j.refetched = now
	}
	set, err := j.fetch(ctx)
	if err != nil {
		j.log("polaris mcp: fetching the issuer's JWK Set failed", "url", j.url, "error", err)
		return nil, err
	}
	j.set, j.fetchedAt = set, now
	return set, nil
}

func (j *jwks) fetch(ctx context.Context) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return nil, errUnavailable
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("%w: status %d, %d bytes", errUnavailable, resp.StatusCode, len(body))
	}
	var doc struct {
		Keys []any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Keys == nil {
		return nil, fmt.Errorf("%w: not a JWK Set", errUnavailable)
	}
	set := make([]map[string]any, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if m, ok := k.(map[string]any); ok {
			set = append(set, m)
		}
	}
	return set, nil
}
