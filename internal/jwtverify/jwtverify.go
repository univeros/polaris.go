// Package jwtverify checks Polaris access tokens the way a resource server does (RFC 9068 §4),
// without the issuer's database: the signature by kid against local keys or a remote JWK Set, the
// typ, iss, aud, exp and nbf. It is the verifier behind plugins/mcp's Protect and package verify.
package jwtverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/univeros/polaris.go/clock"
)

const (
	// Leeway is the clock skew allowed on an access token's exp, nbf and iat.
	Leeway = 60 * time.Second
	// MinRefetch is how often an unknown kid may fetch the issuer's JWK Set again: an
	// unauthenticated JWT naming any kid is not a refetch amplifier.
	MinRefetch = time.Minute
	// DefaultTTL is how long a fetched JWK Set is used before it is fetched again.
	DefaultTTL   = time.Hour
	maxJWKSBytes = 64 << 10
)

// asymmetric are the only JWS algorithms VerifyJWS checks a signature with: never none, never
// an HMAC (a public key must not become a shared secret).
var asymmetric = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

// ErrUnavailable is what a client is told when the issuer's keys cannot be read; the reason is
// logged, never answered.
var ErrUnavailable = errors.New("The token could not be verified against the issuer's keys.")

// Invalid is a refused token; its text is what the client may read.
type Invalid string

func (e Invalid) Error() string { return string(e) }

// Compact matches a compact JWS.
var Compact = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// Verifier checks an access token: a compact JWS signed with one of Algorithms by the key its kid
// names, typ at+jwt or JWT (or absent unless RequireTyp), iss Issuer, an exp, exp and nbf within
// Leeway, no purpose claim (a single-purpose ticket), and an aud naming one of Audiences (with no
// Audiences, no aud at all). Keys are Keys, or JWKS when it is set. Sender constraints (cnf) are
// the caller's to check. Safe for concurrent use once built.
type Verifier struct {
	Issuer     string
	Audiences  []string
	Algorithms []string
	RequireTyp bool
	Clock      clock.Clock
	Keys       map[string]any // local keys by kid
	JWKS       *JWKS          // a remote set; Keys are ignored when set
}

// Verify returns the claims of raw (numbers as json.Number), or an Invalid naming the refusal,
// or an error wrapping ErrUnavailable when the keys cannot be read.
func (v *Verifier) Verify(ctx context.Context, raw string) (map[string]any, error) {
	if !Compact.MatchString(raw) {
		return nil, Invalid("The token is not a JWT.")
	}
	header := Header(raw)
	kid, _ := header["kid"].(string)
	alg, _ := header["alg"].(string)
	if kid == "" || !slices.Contains(v.Algorithms, alg) {
		return nil, Invalid("The token needs a kid and an asymmetric alg.")
	}
	// The issuer signs more than access tokens with this key (DPoP proofs, agent request JWTs,
	// receipts, login-MFA tickets): only an at+jwt or a session access token (typ JWT) is one,
	// and a single-purpose ticket never is.
	if !v.accessTyp(header) {
		return nil, Invalid("The token is not an access token.")
	}
	key, err := v.key(ctx, kid, alg)
	if err != nil {
		return nil, err
	}
	claims, err := VerifyJWS(raw, alg, key, v.Clock.Now(), Leeway)
	if err != nil {
		return nil, Invalid("The token does not verify.")
	}
	if iss, _ := claims["iss"].(string); iss != v.Issuer {
		return nil, Invalid("The token is from another issuer.")
	}
	if _, ok := Number(claims["exp"]); !ok {
		return nil, Invalid("The token has no expiry.")
	}
	if claims["purpose"] != nil {
		return nil, Invalid("A single-purpose token is not an access token.")
	}
	if !v.audience(claims["aud"]) {
		return nil, Invalid("The token is meant for another resource.")
	}
	return claims, nil
}

// accessTyp: typ at+jwt or JWT, in any case; or absent, unless RequireTyp.
func (v *Verifier) accessTyp(header map[string]any) bool {
	h, present := header["typ"]
	if !present {
		return !v.RequireTyp
	}
	typ, _ := h.(string)
	return strings.EqualFold(typ, "at+jwt") || strings.EqualFold(typ, "JWT")
}

// audience: aud names one of Audiences; with none configured, there is no aud.
func (v *Verifier) audience(aud any) bool {
	if len(v.Audiences) == 0 {
		return aud == nil
	}
	return audienceIncludes(aud, v.Audiences)
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

func (v *Verifier) key(ctx context.Context, kid, alg string) (any, error) {
	if v.JWKS == nil {
		if key, ok := v.Keys[kid]; ok {
			return key, nil
		}
		return nil, Invalid("The token names an unknown signing key.")
	}
	for _, fresh := range []bool{false, true} {
		set, err := v.JWKS.keys(ctx, fresh)
		if err != nil {
			return nil, err
		}
		for _, jwk := range set {
			if jwk["kid"] == kid {
				key, err := ParseJWK(jwk, alg)
				if err != nil {
					return nil, Invalid("The token does not verify.")
				}
				return key, nil
			}
		}
	}
	return nil, Invalid("The token names an unknown signing key.")
}

// JWKS is a remote issuer's JWK Set, fetched from URL alone (never one a token names), bounded in
// size and kept in memory for TTL; an unknown kid fetches it again at most once per MinRefetch,
// which is how a key rotation reaches the resource server. When the set cannot be fetched and the
// cached one is older than TTL, verification fails (ErrUnavailable): keys are never used stale.
type JWKS struct {
	URL    string
	Client *http.Client
	TTL    time.Duration
	Clock  clock.Clock
	Log    func(msg string, args ...any) // why a fetch failed

	mu        sync.Mutex // held across a fetch: concurrent misses wait for one request
	set       []map[string]any
	fetchedAt time.Time
	refetched time.Time
}

func (j *JWKS) keys(ctx context.Context, fresh bool) ([]map[string]any, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := j.Clock.Now()
	cached := j.set != nil && now.Sub(j.fetchedAt) < j.TTL
	if cached && !fresh {
		return j.set, nil
	}
	if cached {
		if now.Sub(j.refetched) < MinRefetch {
			return j.set, nil
		}
		j.refetched = now
	}
	set, err := j.fetch(ctx)
	if err != nil {
		j.Log("fetching the issuer's JWK Set failed", "url", j.URL, "error", err)
		return nil, err
	}
	j.set, j.fetchedAt = set, now
	return set, nil
}

func (j *JWKS) fetch(ctx context.Context) ([]map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.URL, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Accept", "application/json")
	resp, err := j.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("%w: status %d, %d bytes", ErrUnavailable, resp.StatusCode, len(body))
	}
	var doc struct {
		Keys []any `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Keys == nil {
		return nil, fmt.Errorf("%w: not a JWK Set", ErrUnavailable)
	}
	set := make([]map[string]any, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		if m, ok := k.(map[string]any); ok {
			set = append(set, m)
		}
	}
	return set, nil
}

// Header decodes a compact JWS's header without verifying it; nil for anything else.
func Header(raw string) map[string]any {
	seg, _, ok := strings.Cut(raw, ".")
	if !ok || strings.Count(raw, ".") != 2 {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return out
}

// ParseJWK reads a JWK object into its public key; an alg it names must be alg.
func ParseJWK(m map[string]any, alg string) (any, error) {
	if ka, ok := m["alg"].(string); ok && ka != alg {
		return nil, errors.New("incorrect key for this algorithm")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var k jose.JSONWebKey
	if err := k.UnmarshalJSON(raw); err != nil {
		return nil, err
	}
	pub := k.Public()
	if !pub.Valid() {
		return nil, errors.New("not a usable public key")
	}
	return pub.Key, nil
}

// VerifyJWS checks a compact JWS signed with alg (an asymmetric algorithm) by key and returns its
// claims (numbers as json.Number), with the time checks under leeway: nbf and iat not after now,
// exp after now.
func VerifyJWS(raw, alg string, key any, now time.Time, leeway time.Duration) (map[string]any, error) {
	if !slices.Contains(asymmetric, alg) {
		return nil, errors.New("algorithm not supported")
	}
	jws, err := jose.ParseSignedCompact(raw, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(alg)})
	if err != nil {
		return nil, err
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil {
		return nil, err
	}
	limit := now.Add(leeway).Unix()
	if v, ok := Number(claims["nbf"]); ok && int64(v) > limit {
		return nil, errors.New("not yet valid")
	}
	if v, ok := Number(claims["iat"]); ok && int64(v) > limit {
		return nil, errors.New("issued in the future")
	}
	if v, ok := Number(claims["exp"]); ok && now.Add(-leeway).Unix() >= int64(v) {
		return nil, errors.New("expired")
	}
	return claims, nil
}

// Number reads a JSON number claim.
func Number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// Scopes reads a scope claim: a space-separated string (OAuth) or a list (a session token).
func Scopes(v any) []string {
	switch s := v.(type) {
	case string:
		return strings.Fields(s)
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
