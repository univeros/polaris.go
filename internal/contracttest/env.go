package contracttest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"time"

	"github.com/univeros/polaris.go/clock"
)

// The environment every recorded test ran in. The Go server these tests replay against must be
// built with the same values.
//
// Clocks: the application uses the real wall clock. Only the rate limiter's clock is frozen, at
// the instant the server boots, so a test's requests never straddle a fixed-window boundary: see
// NewRateClock. Recorded values that depend on the time (timestamps,
// X-RateLimit-Reset/Remaining, Retry-After, JWTs) are masked or dropped by the comparison.
//
// Signing keys: a fresh 2048-bit RSA pair per process; nothing in the fixtures depends on its
// value (JWTs, kid, n and e are masked). No recorded test signs with an EdDSA key. See TestRSAKey.
//
// Request defaults: requests carry no remote address (the client IP resolves to "unknown") and no
// User-Agent unless a test sets them; Client reproduces this.
//
// Configuration flags, all off by default (a flag is on for "1", "true" or "on"). Only these
// tests turn one on, then reboot the server:
//
//   - AUTH_ACCESS_TOKEN_DENYLIST=1: DenylistEndpointsTest::testLogoutEverywhereKillsTheLiveAccessTokenInstantly.
//   - AUTH_PASSWORD_BREACH_CHECK: never on in a functional test.
//
// Auth config overrides (merged over the environment's): CookieModeTest of core, mcp
// and multi-session set `flows.token_delivery: cookie`; none of them has a fixture.
const (
	// AppKey is APP_KEY.
	AppKey = "app-key-for-functional-tests-0123"
	// Issuer is AUTH_ISSUER, the `iss` of every token.
	Issuer = "https://auth.polaris.test"
	// Audience is AUTH_AUDIENCE: unset, so the auth config's audience is null (no `aud` check).
	Audience = ""
	// PreviousKID is AUTH_JWT_PREVIOUS_KID in JwksEndpointTest::testRotationOverlapPublishesBothKeys,
	// which also sets AUTH_JWT_PREVIOUS_PUBLIC_KEY to the primary key's public half (TestRSAKey
	// again) and reboots. AUTH_JWT_KID is never set: the kid is derived from the key.
	PreviousKID = "retiring-key"
	// RSAKeyBits is the size of the test RSA key.
	RSAKeyBits = 2048
)

// RateLimit is one rate-limit group's budget: Limit requests per fixed Window.
type RateLimit struct {
	Limit  int
	Window time.Duration
}

// RateLimits returns the budgets the suite runs with: the default rate limits (no test overrides
// one), keyed by the `auth.rate_limits` group name. The fixtures keep X-RateLimit-Limit, so these are contractual.
func RateLimits() map[string]RateLimit {
	return map[string]RateLimit{
		"login":           {10, 300 * time.Second},
		"register":        {5, 3600 * time.Second},
		"password_forgot": {5, 3600 * time.Second},
		"token_refresh":   {60, 60 * time.Second},
		"mfa_enroll":      {5, 3600 * time.Second},
		"mfa_confirm":     {10, 300 * time.Second},
		"mfa_send":        {5, 600 * time.Second},
		"token_consume":   {10, 300 * time.Second},
		"authenticated":   {600, 60 * time.Second},
	}
}

// NewRateClock returns the rate limiter's clock as the suite builds it: the boot instant, frozen.
// Build one per server boot (each test's first boot and each reboot).
func NewRateClock() clock.Clock {
	return clock.NewFrozen(time.Now())
}

// TestRSAKey returns the suite's RSA signing key: generated once per process, RSAKeyBits long,
// shared by every test.
func TestRSAKey() *rsa.PrivateKey {
	return testRSAKey()
}

// TestRSAKeyPEM returns TestRSAKey as AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY hold it:
// PKCS#8 `PRIVATE KEY` and PKIX `PUBLIC KEY` PEM.
func TestRSAKeyPEM() (privatePEM, publicPEM string) {
	return testRSAKeyPEM()
}

var testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, RSAKeyBits)
	if err != nil {
		panic("contracttest: generating the RSA test key: " + err.Error()) // crypto/rand does not fail
	}
	return key
})

var testRSAKeyPEM = sync.OnceValues(func() (string, string) {
	key := testRSAKey()
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err) // an RSA key always marshals
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
})
