package agents

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/strictjson"
)

// RequestJWTType is the typ header of an agent's signed request JWT.
const RequestJWTType = "agent+jwt"

const (
	requestLeeway       = 60 * time.Second
	maxRequestJWT       = 8192
	maxJWTCapabilities  = 50
	replayPrefix        = "polaris.agents.jti."
	maxJTI              = 256
	forbiddenKeyHeaders = "jku x5u jwk x5c"
)

var compactJWT = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// peekedJWT is the unverified header and sub of a JWT that claims to be an agent's.
type peekedJWT struct {
	header map[string]any
	sub    string
}

// peekRequestJWT recognises an agent JWT (typ agent+jwt) without verifying it; ok is false for any
// other credential.
func peekRequestJWT(raw string) (peekedJWT, bool) {
	if len(raw) > maxRequestJWT || !compactJWT.MatchString(raw) {
		return peekedJWT{}, false
	}
	parts := strings.Split(raw, ".")
	header := decodeJSONSegment(parts[0])
	if header == nil || header["typ"] != RequestJWTType {
		return peekedJWT{}, false
	}
	sub, _ := decodeJSONSegment(parts[1])["sub"].(string)
	return peekedJWT{header: header, sub: sub}, true
}

func decodeJSONSegment(seg string) map[string]any {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil
	}
	var out map[string]any
	if strictjson.Decode(data, &out) != nil {
		return nil
	}
	return out
}

// requestJWTs verifies signed request JWTs and remembers their jti until they expire.
type requestJWTs struct {
	cache  cache.Cache
	clock  clock.Clock
	maxAge int64 // seconds
	// issuer, when set, is what aud must be, exactly (the Agent Auth Protocol's non-execution routes);
	// empty: the URL called, compared normalised.
	issuer string
	skew   time.Duration // the clock leeway; 0: requestLeeway
}

func (j *requestJWTs) leeway() time.Duration {
	if j.skew > 0 {
		return j.skew
	}
	return requestLeeway
}

// audience reports whether aud names this server as the route wants it named.
func (j *requestJWTs) audience(aud, url string) bool {
	if j.issuer != "" {
		return aud == j.issuer
	}
	return !strings.ContainsAny(aud, "?#") && normalizeURL(aud) == normalizeURL(url)
}

// verify checks raw for this request (method, the URL called, the raw body) and the agent, and
// returns the capabilities claim (nil when the JWT does not restrict them).
func (j *requestJWTs) verify(ctx context.Context, raw string, a Agent, method, url string, body []byte) ([]string, error) {
	peeked, ok := peekRequestJWT(raw)
	if !ok {
		return nil, invalidJWT("The credential is not an agent JWT (typ agent+jwt).")
	}
	for _, h := range strings.Fields(forbiddenKeyHeaders) {
		if peeked.header[h] != nil {
			return nil, invalidJWT("The JWT must not carry a key or a key URL; the agent's registered key verifies it.")
		}
	}
	if a.PublicJWK == nil {
		return nil, invalidJWT("The agent has no registered key; it authenticates with an access token.")
	}
	alg, _ := peeked.header["alg"].(string)
	if !slices.Contains(algorithms, alg) || alg != algorithmOf(a.PublicJWK) {
		return nil, invalidJWT("alg must be ES256 or EdDSA and match the agent's key.")
	}
	claims, err := j.decode(raw, a.PublicJWK)
	if err != nil {
		return nil, invalidJWT("The JWT does not verify: " + err.Error())
	}
	if err := j.checkClaims(claims, a, method, url, body); err != nil {
		return nil, err
	}
	if err := j.once(ctx, a, claims); err != nil {
		return nil, err
	}
	caps, has := claims["capabilities"].([]any)
	if !has {
		return nil, nil
	}
	return strings_(caps), nil
}

// decode verifies the signature and the time claims, with the leeway: nbf and iat not after
// now, exp after now.
func (j *requestJWTs) decode(raw string, jwk map[string]any) (map[string]any, error) {
	verify, err := verifierOf(jwk)
	if err != nil {
		return nil, errors.New("the agent's key could not be read")
	}
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !verify([]byte(parts[0]+"."+parts[1]), sig) {
		return nil, errors.New("the signature does not verify")
	}
	claims := decodeJSONSegment(parts[1])
	if claims == nil {
		return nil, errors.New("the claims are not a JSON object")
	}
	now := j.clock.Now()
	limit := now.Add(j.leeway()).Unix()
	if v, ok := number(claims["nbf"]); ok && int64(v) > limit {
		return nil, fmt.Errorf("the token is not valid before %s", time.Unix(int64(v), 0).UTC().Format(time.RFC3339))
	}
	if v, ok := number(claims["iat"]); ok && int64(v) > limit {
		return nil, fmt.Errorf("the token was issued in the future (%s)", time.Unix(int64(v), 0).UTC().Format(time.RFC3339))
	}
	if v, ok := number(claims["exp"]); ok && float64(now.Add(-j.leeway()).Unix()) >= v {
		return nil, errors.New("the token has expired")
	}
	return claims, nil
}

func (j *requestJWTs) checkClaims(claims map[string]any, a Agent, method, url string, body []byte) error {
	if claims["sub"] != a.ID {
		return invalidJWT("sub must be the agent's id.")
	}
	iat, okI := wholeNumber(claims["iat"])
	exp, okE := wholeNumber(claims["exp"])
	if !okI || !okE || exp <= iat {
		return invalidJWT("iat and exp are required, exp after iat.")
	}
	if exp-iat > j.maxAge {
		return invalidJWT(fmt.Sprintf("exp - iat must be at most %d seconds.", j.maxAge))
	}
	aud, ok := claims["aud"].(string)
	if !ok || !j.audience(aud, url) {
		return refuse(ErrAudMismatch, "aud must be the exact URL called (scheme, host, port, path; no query).")
	}
	if v, has := claims["htm"]; has && v != nil {
		if s, ok := v.(string); !ok || !strings.EqualFold(s, method) {
			return invalidJWT("htm does not match the request method.")
		}
	}
	if v, has := claims["htu"]; has && v != nil {
		if s, ok := v.(string); !ok || normalizeURL(s) != normalizeURL(url) {
			return invalidJWT("htu does not match the request URL.")
		}
	}
	if v, has := claims["body_hash"]; has && v != nil {
		sum := sha256.Sum256(body)
		if s, ok := v.(string); !ok || s != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return invalidJWT("body_hash does not match the request body.")
		}
	}
	if v, has := claims["capabilities"]; has && v != nil {
		list, ok := v.([]any)
		if !ok || len(list) > maxJWTCapabilities || len(strings_(list)) != len(list) {
			return invalidJWT("capabilities is a list of capability names.")
		}
	}
	return nil
}

// once accepts a jti once per agent until the JWT expires.
func (j *requestJWTs) once(ctx context.Context, a Agent, claims map[string]any) error {
	jti, _ := claims["jti"].(string)
	if jti == "" || len(jti) > maxJTI {
		return invalidJWT("jti is required.")
	}
	sum := sha256.Sum256([]byte(a.ID + "|" + jti))
	key := replayPrefix + hex.EncodeToString(sum[:])
	exp, _ := wholeNumber(claims["exp"])
	ttl := exp - j.clock.Now().Unix() + int64(requestLeeway/time.Second)
	ttl = min(j.maxAge+2*int64(requestLeeway/time.Second), max(int64(requestLeeway/time.Second), ttl))
	// Add is atomic across replicas sharing the cache, so two replicas cannot both accept one jti
	// (a get then set could).
	fresh, err := j.cache.Add(ctx, key, []byte("1"), time.Duration(ttl)*time.Second)
	if err != nil {
		return err
	}
	if !fresh {
		return invalidJWT("The JWT was already used (jti).")
	}
	return nil
}

func invalidJWT(detail string) *Error { return refuse(ErrInvalidJWT, detail) }
