package token

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Mint and VerifyJWT: the OAuth provider's non-session JWTs.

func withPrevious(t *testing.T) func(*Config) {
	k := loadKeys(t)
	return func(c *Config) { c.PreviousPublicKey, c.PreviousKeyID = k.RSAAlternate.Public, "kid-old" }
}

func TestMintAccessTokenLayout(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	c := newCodec(t, testConfig(t, clk))
	jwt, err := c.Mint("at+jwt", Claims{}.
		With("sub", "user-1").With("iss", "dropped").With("jti", "at-1").
		With("aud", "https://rs.example").With("client_id", "client-1").With("exp", 1),
		clk.Now().Add(300*time.Second+500*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if got := segment(t, jwt, 0); got != `{"typ":"at+jwt","alg":"RS256","kid":"test-kid-1"}` {
		t.Fatalf("header = %s", got)
	}
	want := `{"iss":"https://auth.polaris.test","iat":1780833600,"nbf":1780833600,"exp":1780833900.0005,` +
		`"sub":"user-1","jti":"at-1","aud":"https://rs.example","client_id":"client-1"}`
	if got := segment(t, jwt, 1); got != want {
		t.Fatalf("payload\n got %s\nwant %s", got, want)
	}
}

func TestMintAudienceAndTypeRules(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	c := newCodec(t, testConfig(t, clk))
	exp := clk.Now().Add(time.Minute)
	for aud, want := range map[string]any{
		"list":   []string{"a", "b", "a"}, // duplicates kept, as permittedFor over an empty set
		"single": []any{"only"},
		"empty":  []string{},
	} {
		jwt, err := c.Mint("", Claims{}.With("aud", want), exp)
		if err != nil {
			t.Fatalf("%s: %v", aud, err)
		}
		tok, err := c.VerifyJWT(jwt, 0)
		if err != nil {
			t.Fatalf("%s: %v", aud, err)
		}
		if tok.Header("typ") != "JWT" {
			t.Fatalf("typ = %v", tok.Header("typ"))
		}
		expect := map[string]any{"list": []any{"a", "b", "a"}, "single": []any{"only"}, "empty": []any{}}[aud]
		if !reflect.DeepEqual(tok.Claim("aud"), expect) {
			t.Errorf("%s: aud = %#v", aud, tok.Claim("aud"))
		}
	}
	if seg := segment(t, mustMint(t, c, Claims{}.With("aud", []string{"only"}), exp), 1); !strings.Contains(seg, `"aud":"only"`) {
		t.Fatalf("single audience must collapse to a string: %s", seg)
	}
	for name, claims := range map[string]Claims{
		"empty name":     Claims{}.With("", "x"),
		"sub not string": Claims{}.With("sub", 1),
		"jti not string": Claims{}.With("jti", nil),
		"aud number":     Claims{}.With("aud", 5),
		"aud mixed list": Claims{}.With("aud", []any{"a", 1}),
	} {
		if _, err := c.Mint("", claims, exp); err == nil {
			t.Errorf("%s: minted", name)
		}
	}
	verifyOnly := newCodec(t, testConfig(t, clk, func(c *Config) { c.PrivateKey = "" }))
	if _, err := verifyOnly.Mint("", Claims{}, exp); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestVerifyJWTWindowWithLeeway(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	c := newCodec(t, testConfig(t, clk))
	jwt := mustMint(t, c, Claims{}.With("sub", "u").With("purpose", "x"), clk.Now().Add(300*time.Second))
	for offset, ok := range map[time.Duration]bool{
		-61 * time.Second: false, // iat beyond the leeway
		-60 * time.Second: true,
		0:                 true,
		359 * time.Second: true, // exp + 59 s
		360 * time.Second: false,
	} {
		v := newCodec(t, testConfig(t, at(t, "2026-06-07 12:00:00"), func(cfg *Config) {
			cfg.Clock = fixedAt(clk.Now().Add(offset))
		}))
		if _, err := v.VerifyJWT(jwt, 60*time.Second); (err == nil) != ok {
			t.Errorf("offset %s: err = %v", offset, err)
		}
	}
	// No audience, typ or purpose rule: callers check those.
	if _, err := c.VerifyJWT(jwt, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyJWT(jwt, -time.Second); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative leeway: %v", err)
	}
	wrongIssuer := newCodec(t, testConfig(t, clk, func(c *Config) { c.Issuer = "https://evil.example" }))
	if _, err := wrongIssuer.VerifyJWT(jwt, time.Minute); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("issuer: %v", err)
	}
}

func TestVerifyJWTSelectsTheKeyByKid(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	k := loadKeys(t)
	exp := clk.Now().Add(time.Minute)
	verifier := newCodec(t, testConfig(t, clk, withPrevious(t)))
	oldSigner := newCodec(t, testConfig(t, clk, func(c *Config) {
		c.PublicKey, c.PrivateKey, c.KeyID = k.RSAAlternate.Public, k.RSAAlternate.Private, "kid-old"
	}))
	unknown := newCodec(t, testConfig(t, clk, func(c *Config) { c.KeyID = "kid-unknown" }))
	current := newCodec(t, testConfig(t, clk))
	signedOldAsCurrent := newCodec(t, testConfig(t, clk, func(c *Config) {
		c.PublicKey, c.PrivateKey = k.RSAAlternate.Public, k.RSAAlternate.Private
	}))
	currentAsOld := newCodec(t, testConfig(t, clk, func(c *Config) { c.KeyID = "kid-old" }))

	for name, tc := range map[string]struct {
		jwt string
		ok  bool
	}{
		"previous kid, previous key":  {mustMint(t, oldSigner, Claims{}, exp), true},
		"current kid, current key":    {mustMint(t, current, Claims{}, exp), true},
		"unknown kid, current key":    {mustMint(t, unknown, Claims{}, exp), false},
		"current kid, previous key":   {mustMint(t, signedOldAsCurrent, Claims{}, exp), false},
		"previous kid, current key":   {mustMint(t, currentAsOld, Claims{}, exp), false},
		"no kid, current key":         {craft(t, `{"alg":"RS256"}`, `{"iss":"https://auth.polaris.test"}`), true},
		"null kid, current key":       {craft(t, `{"alg":"RS256","kid":null}`, `{"iss":"https://auth.polaris.test"}`), true},
		"numeric kid, current key":    {craft(t, `{"alg":"RS256","kid":1}`, `{"iss":"https://auth.polaris.test"}`), false},
		"malformed":                   {"not.a.jwt", false},
		"empty":                       {"", false},
		"current kid with purpose ok": {mustMint(t, current, Claims{}.With("purpose", "login_mfa"), exp), true},
	} {
		if _, err := verifier.VerifyJWT(tc.jwt, 0); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := current.VerifyJWT(mustMint(t, oldSigner, Claims{}, exp), 0); err == nil {
		t.Fatal("previous kid accepted without a rotation configured")
	}
	// Session tokens keep verifying with the active key only.
	if _, err := verifier.Parse(mustIssue(t, oldSigner, mustClaims(t, AccessClaims{Subject: "u", ID: "j"}))); err == nil {
		t.Fatal("Parse accepted a previous-key session token")
	}
}

func TestPreviousKeyConfiguration(t *testing.T) {
	k := loadKeys(t)
	for name, mutate := range map[string]func(*Config){
		"key without kid": func(c *Config) { c.PreviousPublicKey = k.RSAAlternate.Public },
		"kid without key": func(c *Config) { c.PreviousKeyID = "kid-old" },
		"bad key":         func(c *Config) { c.PreviousPublicKey, c.PreviousKeyID = "nope", "kid-old" },
		"ec key":          func(c *Config) { c.PreviousPublicKey, c.PreviousKeyID = k.ECPublic, "kid-old" },
	} {
		if _, err := New(testConfig(t, nil, mutate)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func mustMint(t *testing.T, c *Codec, claims Claims, exp time.Time) string {
	t.Helper()
	jwt, err := c.Mint("", claims, exp)
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

type fixedClock time.Time

func (f fixedClock) Now() time.Time { return time.Time(f) }

func fixedAt(t time.Time) fixedClock { return fixedClock(t) }

// Sign is the agents receipt signature.
func TestSignReceiptLayout(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	c := newCodec(t, testConfig(t, clk))
	created := clk.Now().Add(-90*time.Second + 250*time.Microsecond)
	jwt, err := c.Sign("receipt+jwt", Claims{}.
		With("iss", "dropped").
		With("iat", created).
		With("receipt_hash", "ab12").With("receipt_id", "r-1").With("agent_id", "agent-7").With("seq", 3))
	if err != nil {
		t.Fatal(err)
	}
	if got := segment(t, jwt, 0); got != `{"typ":"receipt+jwt","alg":"RS256","kid":"test-kid-1"}` {
		t.Fatalf("header = %s", got)
	}
	want := `{"iss":"https://auth.polaris.test","iat":1780833510.00025,"receipt_hash":"ab12","receipt_id":"r-1","agent_id":"agent-7","seq":3}`
	if got := segment(t, jwt, 1); got != want {
		t.Fatalf("payload\n got %s\nwant %s", got, want)
	}
	// No exp: VerifyJWT accepts it long after; a future iat beyond the leeway is refused.
	later := newCodec(t, testConfig(t, clk, func(cfg *Config) { cfg.Clock = fixedAt(clk.Now().Add(1000 * time.Hour)) }))
	tok, err := later.VerifyJWT(jwt, time.Minute)
	if err != nil || tok.Header("typ") != "receipt+jwt" || tok.Claim("seq") != int64(3) {
		t.Fatalf("VerifyJWT = %v, %v", tok, err)
	}
	early := newCodec(t, testConfig(t, clk, func(cfg *Config) { cfg.Clock = fixedAt(created.Add(-2 * time.Minute)) }))
	if _, err := early.VerifyJWT(jwt, time.Minute); err == nil {
		t.Fatal("future iat accepted")
	}
	plain, err := c.Sign("", Claims{}.With("iat", int64(5)))
	if err != nil || segment(t, plain, 1) != `{"iss":"https://auth.polaris.test","iat":5}` || !strings.HasPrefix(segment(t, plain, 0), `{"typ":"JWT"`) {
		t.Fatalf("Sign without typ: %v", err)
	}
	for name, claims := range map[string]Claims{
		"empty name": Claims{}.With("", 1),
		"sub number": Claims{}.With("sub", 1),
		"bad aud":    Claims{}.With("aud", 1),
	} {
		if _, err := c.Sign("x", claims); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
	if _, err := newCodec(t, testConfig(t, clk, func(c *Config) { c.PrivateKey = "" })).Sign("", Claims{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no private key: %v", err)
	}
}
