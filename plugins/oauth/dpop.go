package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const (
	// DPoPHeader carries a DPoP proof.
	DPoPHeader       = "DPoP"
	dpopTyp          = "dpop+jwt"
	dpopMaxAge       = 300
	dpopReplayPrefix = "polaris.oauth.dpop."
)

var compactJWT = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

// onceGuard records single-use values (DPoP jti, assertion jti) in the cache with its atomic
// Add, so a value is accepted once even by replicas sharing the cache (a get then a set would let
// two replicas both accept it).
type onceGuard struct {
	cache cache.Cache
}

// claim records key for ttl; false when it was already recorded.
func (g *onceGuard) claim(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return g.cache.Add(ctx, key, []byte("1"), ttl)
}

// dpop verifies DPoP proofs (RFC 9449).
type dpop struct {
	once  *onceGuard
	clock clock.Clock
}

func dpopInvalid(description string) *Error { return refusal(CodeInvalidDPoPProof, description) }

// verify returns the thumbprint of the key that signed a valid proof for method on url (and for
// accessToken when given), "" when no proof was sent.
func (d *dpop) verify(ctx context.Context, proof, method, url, accessToken string) (string, error) {
	if proof == "" {
		return "", nil
	}
	if !compactJWT.MatchString(proof) {
		return "", dpopInvalid("The proof is not a JWT.")
	}
	header := JWTHeader(proof)
	alg, _ := header["alg"].(string)
	if header == nil || header["typ"] != dpopTyp || !slices.Contains(asymmetricAlgorithms, alg) {
		return "", dpopInvalid("The proof needs typ dpop+jwt and an asymmetric alg.")
	}
	jwk, ok := header["jwk"].(map[string]any)
	if !ok || jwk["d"] != nil || jwk["p"] != nil || jwk["q"] != nil {
		return "", dpopInvalid("The proof must carry its public key in jwk, and only the public part.")
	}
	key, err := parseJWK(jwk)
	if err != nil {
		return "", dpopInvalid("The key could not be read.")
	}
	if ka, ok := jwk["alg"].(string); ok && ka != alg {
		return "", dpopInvalid("The proof does not verify: the key's alg is not the token's alg")
	}
	now := d.clock.Now()
	claims, err := verifySigned(proof, alg, key, now, 0)
	if err != nil {
		return "", dpopInvalid("The proof does not verify: " + err.Error())
	}
	jti, _ := claims["jti"].(string)
	iat, isInt := integer(claims["iat"])
	if jti == "" || !isInt {
		return "", dpopInvalid("The proof needs jti and iat.")
	}
	if age := now.Unix() - iat; age > dpopMaxAge || age < -dpopMaxAge {
		return "", dpopInvalid(fmt.Sprintf("The proof is older than %d seconds, or from the future.", dpopMaxAge))
	}
	htu, _ := claims["htu"].(string)
	if claims["htm"] != strings.ToUpper(method) || htu == "" || canonicalURL(htu) != canonicalURL(url) {
		return "", dpopInvalid("The proof is bound to another method or URL.")
	}
	if accessToken != "" && claims["ath"] != sha256b64(accessToken) {
		return "", dpopInvalid("The proof is not bound to the access token presented.")
	}
	thumbprint, err := Thumbprint(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(thumbprint + "|" + jti))
	fresh, err := d.once.claim(ctx, dpopReplayPrefix+hex.EncodeToString(sum[:]), 2*dpopMaxAge*time.Second)
	if err != nil {
		return "", err
	}
	if !fresh {
		return "", dpopInvalid("The proof was already used.")
	}
	return thumbprint, nil
}

// canonicalURL is the htu form of a URL: without query or fragment (RFC 9449 §4.3).
func canonicalURL(u string) string {
	u, _, _ = strings.Cut(u, "?")
	u, _, _ = strings.Cut(u, "#")
	return u
}
