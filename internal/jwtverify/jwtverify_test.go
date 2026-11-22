package jwtverify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/contracttest"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, contracttest.TestRSAKey(), crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

var now = time.Unix(1_800_000_000, 0)

func claims(extra map[string]any) map[string]any {
	c := map[string]any{"iss": "https://iss.test", "sub": "ada", "exp": now.Unix() + 60}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

func TestVerifierWithLocalKeys(t *testing.T) {
	v := &Verifier{Issuer: "https://iss.test", Algorithms: []string{"RS256"}, Clock: clock.NewFrozen(now),
		Keys: map[string]any{"k": &contracttest.TestRSAKey().PublicKey}}
	rs := map[string]any{"alg": "RS256", "kid": "k"}
	if c, err := v.Verify(context.Background(), sign(t, rs, claims(nil))); err != nil || c["sub"] != "ada" {
		t.Fatalf("no typ, no aud: %v %v", c, err)
	}
	withAud := *v
	withAud.Audiences = []string{"https://a.test", "https://b.test"}
	for _, aud := range []any{"https://b.test", []any{1, "https://a.test"}} {
		if _, err := withAud.Verify(context.Background(), sign(t, rs, claims(map[string]any{"aud": aud}))); err != nil {
			t.Errorf("aud %v: %v", aud, err)
		}
	}
	strict := *v
	strict.RequireTyp = true
	for name, c := range map[string]struct {
		v   *Verifier
		raw string
	}{
		"typ required":   {&strict, sign(t, rs, claims(nil))},
		"aud, none set":  {v, sign(t, rs, claims(map[string]any{"aud": "https://a.test"}))},
		"aud elsewhere":  {&withAud, sign(t, rs, claims(map[string]any{"aud": []any{"https://c.test"}}))},
		"aud a number":   {&withAud, sign(t, rs, claims(map[string]any{"aud": 7}))},
		"unknown kid":    {v, sign(t, map[string]any{"alg": "RS256", "kid": "x"}, claims(nil))},
		"wrong issuer":   {v, sign(t, rs, claims(map[string]any{"iss": "https://evil.test"}))},
		"a purpose":      {v, sign(t, rs, claims(map[string]any{"purpose": "step_up"}))},
		"no exp":         {v, sign(t, rs, map[string]any{"iss": "https://iss.test"})},
		"wrong alg list": {&Verifier{Issuer: "https://iss.test", Algorithms: []string{"EdDSA"}, Clock: v.Clock, Keys: v.Keys}, sign(t, rs, claims(nil))},
	} {
		var inv Invalid
		if _, err := c.v.Verify(context.Background(), c.raw); !errors.As(err, &inv) {
			t.Errorf("%s: %v, want Invalid", name, err)
		}
	}
}

func TestJWKSFetchFailures(t *testing.T) {
	var answer func(w http.ResponseWriter)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { answer(w) }))
	defer srv.Close()
	var logged []string
	j := &JWKS{URL: srv.URL, Client: srv.Client(), TTL: time.Hour, Clock: clock.NewFrozen(now),
		Log: func(msg string, _ ...any) { logged = append(logged, msg) }}
	for name, a := range map[string]func(w http.ResponseWriter){
		"a 500":    func(w http.ResponseWriter) { http.Error(w, "x", 500) },
		"not JSON": func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) },
		"no keys":  func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"other":[]}`)) },
		"too large": func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"keys":["` + strings.Repeat("a", maxJWKSBytes) + `"]}`))
		},
		"unreachable":   nil,
		"a bad request": nil,
	} {
		answer = a
		jj := j
		switch name {
		case "unreachable":
			jj = &JWKS{URL: "https://127.0.0.1:1/jwks", Client: srv.Client(), TTL: time.Hour, Clock: j.Clock, Log: j.Log}
		case "a bad request":
			jj = &JWKS{URL: "https://\x7f", Client: srv.Client(), TTL: time.Hour, Clock: j.Clock, Log: j.Log}
		}
		if _, err := jj.keys(context.Background(), false); !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: %v, want ErrUnavailable", name, err)
		}
	}
	if len(logged) != 6 {
		t.Fatalf("every failure is logged: %v", logged)
	}
	answer = func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"keys":[1,{"kid":"k","kty":"RSA","alg":"RS256","n":"AQ","e":"AQ"}]}`))
	}
	set, err := j.keys(context.Background(), false)
	if err != nil || len(set) != 1 {
		t.Fatalf("non-object members are skipped: %v %v", set, err)
	}
	v := &Verifier{Issuer: "https://iss.test", Algorithms: []string{"RS256"}, Clock: j.Clock, JWKS: j}
	var inv Invalid
	if _, err := v.Verify(context.Background(), sign(t, map[string]any{"alg": "RS256", "kid": "k"}, claims(nil))); !errors.As(err, &inv) {
		t.Fatalf("an unusable published key: %v", err)
	}
}

func TestHelpers(t *testing.T) {
	for _, raw := range []string{"", "a.b", "a.b.c.d", "!!.b.c", b64([]byte("[]")) + ".b.c"} {
		if Header(raw) != nil {
			t.Errorf("Header(%q) is not nil", raw)
		}
	}
	if !slices.Equal(Scopes("a  b"), []string{"a", "b"}) || !slices.Equal(Scopes([]any{"a", 1, "b"}), []string{"a", "b"}) || Scopes(3) != nil {
		t.Error("Scopes")
	}
	if _, ok := Number("1"); ok {
		t.Error("Number of a string")
	}
	for name, jwk := range map[string]map[string]any{
		"alg mismatch":  {"kty": "RSA", "alg": "EdDSA"},
		"not a key":     {"kty": "nope"},
		"a private key": {"kty": "oct", "k": "c2VjcmV0"},
		"unmarshalable": {"kty": "RSA", "n": func() {}},
	} {
		if _, err := ParseJWK(jwk, "RS256"); err == nil {
			t.Errorf("ParseJWK %s accepted", name)
		}
	}
	if _, err := VerifyJWS("a.b.c", "HS256", nil, now, 0); err == nil {
		t.Error("VerifyJWS with HS256")
	}
	if _, err := VerifyJWS("a.b.c", "RS256", nil, now, 0); err == nil {
		t.Error("VerifyJWS of garbage")
	}
	if Invalid("x").Error() != "x" {
		t.Error("Invalid.Error")
	}
}
