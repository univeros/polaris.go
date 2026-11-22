package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func int64p(n int64) *int64 { return &n }

// PolarisTokenRoundTripTest

func TestRoundTripMintsAndVerifiesTheFullClaimSet(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	c := newCodec(t, testConfig(t, clk))
	jwt := mustIssue(t, c, mustClaims(t, AccessClaims{
		Subject: "user-123", ID: "jti-abc", SessionID: "family-xyz", OrganizationID: "org-789",
		Roles: []string{"admin", "member"}, EmailVerified: true, MFA: true,
		AMR: []string{"pwd", "otp"}, AuthTime: int64p(1_780_000_000),
	}))
	tok, err := c.Parse(jwt)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"sub": "user-123", "jti": "jti-abc", "sid": "family-xyz", "org": "org-789",
		"roles": []any{"admin", "member"}, "email_verified": true, "mfa": true,
		"amr": []any{"pwd", "otp"}, "auth_time": int64(1_780_000_000), "iss": testIssuer,
		"aud": []any{testAudience},
	}
	for name, v := range want {
		if got := tok.Claim(name); !reflect.DeepEqual(got, v) {
			t.Errorf("%s = %#v, want %#v", name, got, v)
		}
	}
	if tok.Subject() != "user-123" || tok.ID() != "jti-abc" || tok.Raw() != jwt {
		t.Fatal("accessors disagree with claims")
	}
	if !tok.IssuedAt().Equal(clk.Now()) || !tok.ExpiresAt().Equal(clk.Now().Add(900*time.Second)) {
		t.Fatalf("iat %v exp %v", tok.IssuedAt(), tok.ExpiresAt())
	}
	if len(tok.Claims()) != 14 {
		t.Fatalf("claims = %v", tok.Claims())
	}
}

func TestRoundTripHeaderCarriesTheKeyID(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	jwt := mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}))
	if got := segment(t, jwt, 0); got != `{"typ":"JWT","alg":"RS256","kid":"test-kid-1"}` {
		t.Fatalf("header = %s", got)
	}
	tok, _ := c.Parse(jwt)
	if tok.Header("kid") != testKID {
		t.Fatalf("kid = %v", tok.Header("kid"))
	}
}

func TestRoundTripNullableOrgIsCarriedExplicitly(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	jwt := mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}))
	want := `{"iss":"https://auth.polaris.test","iat":1780833600,"nbf":1780833600,"exp":1780834500,` +
		`"aud":"https://api.polaris.test","sub":"user-1","jti":"jti-1","org":null,"roles":[],` +
		`"email_verified":false,"mfa":false,"amr":[]}`
	if got := segment(t, jwt, 1); got != want {
		t.Fatalf("payload\n got %s\nwant %s", got, want)
	}
	tok, err := c.Parse(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := tok.Claims()["org"]; !present || tok.Claim("org") != nil {
		t.Fatal("org must be present and null")
	}
	if !reflect.DeepEqual(tok.Claim("roles"), []any{}) || tok.Claim("email_verified") != false {
		t.Fatalf("roles %#v email_verified %#v", tok.Claim("roles"), tok.Claim("email_verified"))
	}
}

func TestIssueEncodesDatesAsWholeSeconds(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	clk.Set(clk.Now().Add(123456789 * time.Nanosecond)) // the fraction is dropped: dates are whole seconds
	c := newCodec(t, testConfig(t, clk, func(c *Config) { c.Audience = "" }))
	jwt := mustIssue(t, c, Claims{}.With("sub", "u").With("iss", "ignored").With("", "dropped").With("ratio", 0.5))
	want := `{"iss":"https://auth.polaris.test","iat":1780833600,"nbf":1780833600,"exp":1780834500,"sub":"u","ratio":0.5}`
	if got := segment(t, jwt, 1); got != want {
		t.Fatalf("payload\n got %s\nwant %s", got, want)
	}
	tok, err := c.Parse(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if !tok.IssuedAt().Equal(clk.Now().Truncate(time.Second)) {
		t.Fatalf("iat = %v", tok.IssuedAt())
	}
}

func TestIssueRequiresAPrivateKeyAndStringSubject(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00"), func(c *Config) { c.PrivateKey = "" }))
	if _, err := c.Issue(Claims{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
	c = newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	for _, claims := range []Claims{
		Claims{}.With("sub", 5),
		Claims{}.With("jti", nil),
		Claims{}.With("bad", struct{}{}),
		Claims{}.With("bad", "\xff"),
	} {
		if _, err := c.Issue(claims); err == nil {
			t.Errorf("Issue(%v) succeeded", claims.Names())
		}
	}
}

func TestEdDSARoundTrip(t *testing.T) {
	k := loadKeys(t)
	clk := at(t, "2026-06-07 12:00:00")
	c := newCodec(t, testConfig(t, clk, func(c *Config) {
		c.Algorithm, c.PublicKey, c.PrivateKey = EdDSA, k.edPublic(), k.edSecret()
	}))
	jwt := mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}))
	if !strings.Contains(segment(t, jwt, 0), `"alg":"EdDSA"`) {
		t.Fatal("alg header")
	}
	if _, err := c.Parse(jwt); err != nil {
		t.Fatal(err)
	}
	// An RS256 codec over the same issuer refuses it (signer mismatch).
	if _, err := newCodec(t, testConfig(t, clk)).Parse(jwt); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
}

// PolarisTokenRejectionTest

func validJWT(t *testing.T, ttl time.Duration) string {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00"), func(c *Config) { c.TTL = ttl }))
	return mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}))
}

func assertRejected(t *testing.T, c *Codec, jwt string) {
	t.Helper()
	if tok, err := c.Parse(jwt); !errors.Is(err, ErrInvalidToken) || tok != nil {
		t.Fatalf("Parse = %v, %v; want ErrInvalidToken", tok, err)
	}
}

func TestRejectsATamperedSignature(t *testing.T) {
	foreign := testConfig(t, at(t, "2026-06-07 12:01:00"), func(c *Config) { c.PublicKey = loadKeys(t).RSAAlternate.Public })
	assertRejected(t, newCodec(t, foreign), validJWT(t, 900*time.Second))
}

func TestRejectsAWrongIssuer(t *testing.T) {
	cfg := testConfig(t, at(t, "2026-06-07 12:01:00"), func(c *Config) { c.Issuer = "https://evil.example" })
	assertRejected(t, newCodec(t, cfg), validJWT(t, 900*time.Second))
}

func TestRejectsAWrongAudience(t *testing.T) {
	cfg := testConfig(t, at(t, "2026-06-07 12:01:00"), func(c *Config) { c.Audience = "https://other-api.example" })
	assertRejected(t, newCodec(t, cfg), validJWT(t, 900*time.Second))
}

func TestRejectsAnExpiredToken(t *testing.T) {
	jwt := validJWT(t, 60*time.Second)
	assertRejected(t, newCodec(t, testConfig(t, at(t, "2026-06-07 12:10:00"))), jwt)
	// Expired once now >= exp, so the exact expiry instant is already too late.
	assertRejected(t, newCodec(t, testConfig(t, at(t, "2026-06-07 12:01:00"))), jwt)
	if _, err := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:59"))).Parse(jwt); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}
}

func TestRejectsATokenUsedBeforeItsNotBeforeTime(t *testing.T) {
	assertRejected(t, newCodec(t, testConfig(t, at(t, "2026-06-07 11:55:00"))), validJWT(t, 900*time.Second))
}

func TestRejectsAWellSignedTokenThatOmitsExpiry(t *testing.T) {
	jwt := craft(t, `{"typ":"JWT","alg":"RS256"}`, `{"iss":"https://auth.polaris.test","aud":"https://api.polaris.test","sub":"user-1"}`)
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	assertRejected(t, c, jwt)
	if _, err := c.Verify(jwt); err != nil {
		t.Fatalf("Verify (LooseValidAt) passes a token without time claims: %v", err)
	}
	withIat := craft(t, `{"alg":"RS256"}`, `{"iss":"https://auth.polaris.test","aud":"https://api.polaris.test","iat":1780833600}`)
	assertRejected(t, c, withIat) // still no exp
}

func TestRejectsAMalformedToken(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	good := validJWT(t, 900*time.Second)
	parts := strings.Split(good, ".")
	for _, bad := range []string{
		"", "not-a-jwt", "a.b", "a.b.c.d", good + ".", "." + parts[1] + "." + parts[2],
		parts[0] + "." + parts[1] + ".", parts[0] + "==." + parts[1] + "." + parts[2],
		parts[0] + "." + parts[1] + "\n." + parts[2], parts[0] + "." + parts[1] + "." + parts[2] + "A",
		b64("[]") + "." + parts[1] + "." + parts[2],
	} {
		assertRejected(t, c, bad)
	}
}

// PolarisTokenValidatorTest and the Polaris-specific parser rules.

func TestParseRejectsASinglePurposeTokenOnTheAccessPath(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	jwt := mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}).With("purpose", "login_mfa"))
	assertRejected(t, c, jwt)
	tok, err := c.Verify(jwt)
	if err != nil || tok.Claim("purpose") != "login_mfa" {
		t.Fatalf("Verify must accept tickets: %v", err)
	}
	// purpose: null is no purpose.
	nullPurpose := mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}).With("purpose", nil))
	if _, err := c.Parse(nullPurpose); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsOtherTokenTypes(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00"), func(c *Config) { c.Audience = "" }))
	payload := `{"iss":"https://auth.polaris.test","iat":1780833600,"exp":1780834500,"sub":"u"}`
	for typ, ok := range map[string]bool{`"at+jwt"`: false, `"dpop+jwt"`: false, `"jwt"`: true, `"JWT"`: true, `""`: true, `5`: true} {
		jwt := craft(t, `{"typ":`+typ+`,"alg":"RS256"}`, payload)
		if _, err := c.Parse(jwt); (err == nil) != ok {
			t.Errorf("typ %s: err = %v", typ, err)
		}
	}
	if _, err := c.Parse(craft(t, `{"alg":"RS256"}`, payload)); err != nil {
		t.Errorf("absent typ: %v", err)
	}
}

func TestParseRejectsAnAudienceWhenNoneIsConfigured(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00"), func(c *Config) { c.Audience = "" }))
	for _, aud := range []string{`"x"`, `["x"]`, `null`, `[]`} {
		jwt := craft(t, `{"alg":"RS256"}`, `{"iss":"https://auth.polaris.test","iat":1780833600,"exp":1780834500,"aud":`+aud+`}`)
		assertRejected(t, c, jwt)
	}
}

func TestVerifyChecksAlgorithmIssuerAndDates(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00"), func(c *Config) { c.Audience = "" }))
	const iss = `"iss":"https://auth.polaris.test"`
	for name, tc := range map[string]struct {
		header, payload string
		ok              bool
	}{
		"alg none":            {`{"alg":"none"}`, `{` + iss + `}`, false},
		"alg missing":         {`{"typ":"JWT"}`, `{` + iss + `}`, false},
		"enc header":          {`{"alg":"RS256","enc":"A128GCM"}`, `{` + iss + `}`, false},
		"empty header key":    {`{"alg":"RS256","":1}`, `{` + iss + `}`, false},
		"empty claim key":     {`{"alg":"RS256"}`, `{` + iss + `,"":1}`, false},
		"issuer not string":   {`{"alg":"RS256"}`, `{"iss":["https://auth.polaris.test"]}`, false},
		"no issuer":           {`{"alg":"RS256"}`, `{}`, false},
		"iat in future":       {`{"alg":"RS256"}`, `{` + iss + `,"iat":1780833601}`, false},
		"exp bool":            {`{"alg":"RS256"}`, `{` + iss + `,"exp":true}`, false},
		"exp null":            {`{"alg":"RS256"}`, `{` + iss + `,"exp":null}`, false},
		"exp not numeric":     {`{"alg":"RS256"}`, `{` + iss + `,"exp":"tomorrow"}`, false},
		"exp overflow":        {`{"alg":"RS256"}`, `{` + iss + `,"exp":1e400}`, false},
		"exp numeric string":  {`{"alg":"RS256"}`, `{` + iss + `,"exp":" 1780833601.5 "}`, false},
		"nbf numeric string":  {`{"alg":"RS256"}`, `{` + iss + `,"nbf":"1780833600"}`, false},
		"exp float":           {`{"alg":"RS256"}`, `{` + iss + `,"exp":1780833600.000001}`, true},
		"exp now":             {`{"alg":"RS256"}`, `{` + iss + `,"exp":1780833600}`, false},
		"iat now":             {`{"alg":"RS256"}`, `{` + iss + `,"iat":1780833600,"nbf":1780833600}`, true},
		"iat negative":        {`{"alg":"RS256"}`, `{` + iss + `,"iat":-1}`, false},
		"nbf negative float":  {`{"alg":"RS256"}`, `{` + iss + `,"nbf":-1.5}`, false},
		"aud string":          {`{"alg":"RS256"}`, `{` + iss + `,"aud":"x"}`, true},
		"aud strings":         {`{"alg":"RS256"}`, `{` + iss + `,"aud":["x","y"]}`, true},
		"aud null":            {`{"alg":"RS256"}`, `{` + iss + `,"aud":null}`, false},
		"aud number":          {`{"alg":"RS256"}`, `{` + iss + `,"aud":5}`, false},
		"aud object":          {`{"alg":"RS256"}`, `{` + iss + `,"aud":{"a":"x"}}`, false},
		"aud mixed list":      {`{"alg":"RS256"}`, `{` + iss + `,"aud":["x",1]}`, false},
		"trailing JSON":       {`{"alg":"RS256"}`, `{` + iss + `} {}`, false},
		"invalid UTF-8 claim": {`{"alg":"RS256"}`, `{` + iss + `,"x":"` + "\xff" + `"}`, false},
		"lone high surrogate": {`{"alg":"RS256"}`, `{` + iss + `,"x":"\ud800"}`, false},
		"lone low surrogate":  {`{"alg":"RS256"}`, `{` + iss + `,"x":"\udc00x"}`, false},
		"high then non-low":   {`{"alg":"RS256"}`, `{` + iss + `,"x":"\ud800\u0041"}`, false},
		"surrogate pair":      {`{"alg":"RS256"}`, `{` + iss + `,"x":"\ud83d\ude00"}`, true},
		"escaped backslash u": {`{"alg":"RS256"}`, `{` + iss + `,"x":"\\ud800"}`, true},
		"depth 511":           {`{"alg":"RS256"}`, `{` + iss + `,"x":` + strings.Repeat("[", 510) + strings.Repeat("]", 510) + `}`, true},
		"depth 512":           {`{"alg":"RS256"}`, `{` + iss + `,"x":` + strings.Repeat("[", 511) + strings.Repeat("]", 511) + `}`, false},
		"huge iat":            {`{"alg":"RS256"}`, `{` + iss + `,"iat":9223372036854775807}`, false},
		"huge nbf float":      {`{"alg":"RS256"}`, `{` + iss + `,"nbf":9.3e18}`, false},
	} {
		_, err := c.Verify(craft(t, tc.header, tc.payload))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", name, err)
		}
		if err != nil && !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: %v does not wrap ErrInvalidToken", name, err)
		}
	}
}

func TestVerifyRefusesSmallOrderEd25519Signatures(t *testing.T) {
	// Go's ed25519.Verify accepts the identity point as key and R with S = 0; libsodium's
	// crypto_sign_verify_detached, which verifyEd25519 follows, refuses small-order keys and R.
	identity := make([]byte, 32)
	identity[0] = 1
	sig := append(append([]byte{}, identity...), make([]byte, 32)...)
	if !ed25519.Verify(identity, []byte("m"), sig) {
		t.Skip("stdlib behaviour changed; the extra check is still in place")
	}
	if verifyEd25519(identity, []byte("m"), sig) {
		t.Fatal("small-order R accepted")
	}
	_, err := New(Config{Algorithm: EdDSA, PublicKey: string(identity), Issuer: testIssuer})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("small-order public key: err = %v", err)
	}
	for i, p := range ed25519Blocklist {
		if !ed25519SmallOrder(p[:]) {
			t.Errorf("blocklist %d not detected", i)
		}
		p[31] |= 0x80
		if !ed25519SmallOrder(p[:]) {
			t.Errorf("blocklist %d with sign bit not detected", i)
		}
	}
	nonCanonical := append([]byte{0xee}, append(make([]byte, 0, 31), []byte(strings.Repeat("\xff", 30)+"\x7f")...)...)
	if ed25519Canonical(nonCanonical) {
		t.Fatal("y >= p reported canonical")
	}
}

func TestNewValidatesConfiguration(t *testing.T) {
	k := loadKeys(t)
	for name, mutate := range map[string]func(*Config){
		"no public key":     func(c *Config) { c.PublicKey = "" },
		"no issuer":         func(c *Config) { c.Issuer = "" },
		"bad algorithm":     func(c *Config) { c.Algorithm = "HS256" },
		"negative ttl":      func(c *Config) { c.TTL = -time.Second },
		"fractional ttl":    func(c *Config) { c.TTL = 1500 * time.Millisecond },
		"bad public pem":    func(c *Config) { c.PublicKey = "-----BEGIN PUBLIC KEY-----not a key-----END PUBLIC KEY-----" },
		"ec public key":     func(c *Config) { c.PublicKey = k.ECPublic },
		"bad private pem":   func(c *Config) { c.PrivateKey = "nope" },
		"public as private": func(c *Config) { c.PrivateKey = k.RSA.Public },
		"short eddsa":       func(c *Config) { c.Algorithm, c.PublicKey = EdDSA, "short" },
		"short eddsa sk": func(c *Config) {
			c.Algorithm, c.PublicKey, c.PrivateKey = EdDSA, k.edPublic(), "short"
		},
	} {
		if _, err := New(testConfig(t, nil, mutate)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	c, err := New(testConfig(t, nil, func(c *Config) { c.Algorithm = "" }))
	if err != nil || c.alg != RS256 {
		t.Fatalf("empty algorithm defaults to RS256: %v", err)
	}
}

func TestRSAKeysBelow2048BitsAreRefused(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub1024 := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	if _, err := New(Config{PublicKey: pub1024, Issuer: testIssuer}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
	set, err := NewJWKSet(RS256, PublicKey{KeyID: "small", PEM: pub1024})
	if err != nil || len(set.Keys) != 1 {
		t.Fatalf("JWKS renders any RSA key: %v", err)
	}
}

func TestTokenAndCodecLogValuesHideSecrets(t *testing.T) {
	c := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00")))
	jwt := mustIssue(t, c, mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"}))
	tok, _ := c.Parse(jwt)
	for _, v := range []string{tok.LogValue().String(), c.LogValue().String()} {
		if strings.Contains(v, jwt) || strings.Contains(v, "PRIVATE") {
			t.Fatalf("log value leaks: %s", v)
		}
	}
	cfg := testConfig(t, nil)
	for _, v := range []any{tok, c, cfg, IssuedTokens{AccessToken: jwt, RefreshToken: "rt-secret"}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			if out := fmt.Sprintf(verb, v); strings.Contains(out, jwt) || strings.Contains(out, "PRIVATE") || strings.Contains(out, "rt-secret") {
				t.Fatalf("%s of %T leaks: %s", verb, v, out)
			}
		}
	}
	if !strings.Contains(tok.LogValue().String(), "user-1") {
		t.Fatal("token log value should name the subject")
	}
}
