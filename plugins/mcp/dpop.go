package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const (
	dpopHeader       = "DPoP"
	dpopTyp          = "dpop+jwt"
	dpopMaxAge       = 300
	dpopReplayPrefix = "polaris.mcp.dpop."
)

// dpopProofs is the resource server's side of DPoP (RFC 9449 §4.3): the proof is a JWT signed by
// the key in its own header, bound to the method and URL called (without query) and to the access
// token presented (ath), at most five minutes old, its jti used once. Its own check, so this
// package does not need the oauth plugin; the replay keys are apart from the provider's.
type dpopProofs struct {
	cache cache.Cache
	clock clock.Clock
}

// thumbprint returns the RFC 7638 thumbprint of the key that signed a valid proof.
func (d *dpopProofs) thumbprint(ctx context.Context, proof, method, url, accessToken string) (string, error) {
	if !compactJWT.MatchString(proof) {
		return "", invalid("The DPoP proof is not a JWT.")
	}
	header := jwtHeader(proof)
	alg, _ := header["alg"].(string)
	if header["typ"] != dpopTyp || !slices.Contains(Algorithms, alg) {
		return "", invalid("The DPoP proof needs typ dpop+jwt and an asymmetric alg.")
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok || jwk["d"] != nil || jwk["p"] != nil || jwk["q"] != nil {
		return "", invalid("The DPoP proof must carry its public key in jwk, and only the public part.")
	}
	thumb, ok := thumbprint(jwk)
	if !ok {
		return "", invalid("The DPoP key type is not supported.")
	}
	now := d.clock.Now()
	key, err := parseJWK(jwk, alg)
	var claims map[string]any
	if err == nil {
		claims, err = verifyJWS(proof, alg, key, now, 0)
	}
	if err != nil {
		return "", invalid("The DPoP proof does not verify.")
	}
	jti, _ := claims["jti"].(string)
	iat, isInt := integer(claims["iat"])
	if age := now.Unix() - iat; jti == "" || !isInt || age > dpopMaxAge || age < -dpopMaxAge {
		return "", invalid("The DPoP proof needs jti and a recent iat.")
	}
	htu, _ := claims["htu"].(string)
	if claims["htm"] != strings.ToUpper(method) || htu == "" || withoutQuery(htu) != withoutQuery(url) {
		return "", invalid("The DPoP proof is bound to another method or URL.")
	}
	ath, _ := claims["ath"].(string)
	if subtle.ConstantTimeCompare([]byte(ath), []byte(sha256b64(accessToken))) != 1 {
		return "", invalid("The DPoP proof is not bound to the access token presented.")
	}
	sum := sha256.Sum256([]byte(thumb + "|" + jti))
	fresh, err := d.claim(ctx, dpopReplayPrefix+hex.EncodeToString(sum[:]))
	if err != nil {
		return "", err
	}
	if !fresh {
		return "", invalid("The DPoP proof was already used.")
	}
	return thumb, nil
}

// claim records key; false when it was already recorded. Add is atomic across replicas sharing
// the cache, so two replicas cannot both accept one proof (a get then set could).
func (d *dpopProofs) claim(ctx context.Context, key string) (bool, error) {
	return d.cache.Add(ctx, key, []byte("1"), 2*dpopMaxAge*time.Second)
}

func withoutQuery(u string) string {
	u, _, _ = strings.Cut(u, "?")
	return u
}
