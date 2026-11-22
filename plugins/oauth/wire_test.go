package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/netguard"
	"github.com/univeros/polaris.go/polaristest"
)

func TestTimestampsAreRFC3339InUTC(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 500, time.FixedZone("CET", 3600))
	if got := timestamp(at); got != "2026-11-22T09:00:00Z" {
		t.Errorf("timestamp %q", got)
	}
	if timestampPtr(nil) != nil || timestampPtr(&at) != "2026-11-22T09:00:00Z" {
		t.Error("timestampPtr")
	}
}

func TestAFetchedDocumentMustBeAJSONObject(t *testing.T) {
	log := polaristest.New(t).Graph().Logger()
	client := netguard.NoRedirects(&http.Client{Transport: &docs{status: 200, body: `[]`}})
	_, err := fetchJSON(context.Background(), client, log, "https://x.example.com/doc", CodeInvalidClientMetadata)
	wantCode(t, err, CodeInvalidClientMetadata, "a JSON list is not a document")
}

// A JWK Set's keys member is an array (RFC 7517 §5): a set a client registers or a jwks_uri
// answers is refused otherwise; a client row stored by an earlier release with keys as an object
// still reads.
func TestAKeySetIsAnArrayButAStoredObjectStillReads(t *testing.T) {
	ctx := context.Background()
	objectForm := map[string]any{"keys": map[string]any{"b": map[string]any{"kid": "b"}, "a": map[string]any{"kid": "a"}}}
	if jwksKeys(objectForm) != nil {
		t.Error("keys as an object is not a JWK Set")
	}
	p, _ := boot(t, Config{HTTPClient: &http.Client{Transport: &docs{status: http.StatusOK, body: `{"keys":{"0":{"kty":"EC"}}}`}}})
	_, err := p.clients.create(ctx, ClientFields{"name": "x", "grant_types": []any{"client_credentials"},
		"token_endpoint_auth_method": "private_key_jwt", "jwks": objectForm}, "", "", false)
	wantCode(t, err, CodeInvalidClientMetadata, "a registered key set with keys as an object")
	_, err = p.clients.keySet(ctx, Client{JWKSURI: "https://keys.example.com/jwks.json"})
	wantCode(t, err, CodeInvalidClient, "a jwks_uri answering keys as an object")

	keys, err := p.clients.keySet(ctx, Client{JWKS: objectForm})
	must(t, err)
	if len(keys) != 2 || keys[0].(map[string]any)["kid"] != "a" {
		t.Errorf("a stored object of keys reads in key order: %v", keys)
	}
}

func TestAKeyIsChosenByItsKidOnly(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	jwk := func(kid string) map[string]any {
		m := map[string]any{"kty": "RSA", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
		if kid != "" {
			m["kid"] = kid
		}
		return m
	}
	now := time.Now()
	sign := func(header map[string]any, claims map[string]any) string {
		h, _ := json.Marshal(header)
		c, _ := json.Marshal(claims)
		input := b64(h) + "." + b64(c)
		sum := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		must(t, err)
		return input + "." + b64(sig)
	}
	valid := map[string]any{"exp": now.Unix() + 60}
	verify := func(header map[string]any, set []any) error {
		_, err := verifyWithKeySet(sign(header, valid), header, "RS256", set, now)
		return err
	}
	noKid := map[string]any{"alg": "RS256"}
	if err := verify(noKid, []any{jwk("")}); err != nil {
		t.Errorf("a token without kid verifies with the only key: %v", err)
	}
	if err := verify(noKid, []any{jwk("a"), jwk("b")}); err == nil || err.Error() != "the token names no key (kid) and the key set holds more than one" {
		t.Errorf("a token without kid and two keys: %v", err)
	}
	if err := verify(map[string]any{"alg": "RS256", "kid": "0"}, []any{jwk("")}); err == nil || err.Error() != "no key in the key set has the token's kid" {
		t.Errorf("a key without kid is not named by its index: %v", err)
	}
	if err := verify(map[string]any{"alg": "RS256", "kid": "b"}, []any{jwk("a"), jwk("b")}); err != nil {
		t.Errorf("the kid picks the key: %v", err)
	}
	if err := verify(map[string]any{"alg": "RS256", "kid": 7}, []any{jwk("")}); err == nil {
		t.Error("a kid that is not a string")
	}
	if err := verify(noKid, nil); err == nil || err.Error() != "the key set holds no keys" {
		t.Errorf("an empty set: %v", err)
	}
	ec := jwk("a")
	ec["alg"] = "ES256"
	if err := verify(map[string]any{"alg": "RS256", "kid": "a"}, []any{ec}); err == nil || err.Error() != "the key's alg is not the token's alg" {
		t.Errorf("a key for another algorithm: %v", err)
	}

	key, err := parseJWK(jwk(""))
	must(t, err)
	header := map[string]any{"alg": "RS256"}
	for want, claims := range map[string]map[string]any{
		"the token has expired": {"exp": now.Unix() - 120},
		"the token is not valid before " + time.Unix(now.Unix()+600, 0).UTC().Format(time.RFC3339):             {"nbf": now.Unix() + 600},
		"the token was issued in the future (" + time.Unix(now.Unix()+600, 0).UTC().Format(time.RFC3339) + ")": {"iat": now.Unix() + 600},
	} {
		if _, err := verifySigned(sign(header, claims), "RS256", key, now, time.Minute); err == nil || err.Error() != want {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	h, _ := json.Marshal(header)
	input := b64(h) + "." + b64([]byte(`[1]`))
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if _, err := verifySigned(input+"."+b64(sig), "RS256", key, now, 0); err == nil || err.Error() != "the claims are not a JSON object" {
		t.Errorf("claims not an object: %v", err)
	}
	if _, err := verifySigned(input+"."+b64([]byte("forged")), "RS256", key, now, 0); err == nil || err.Error() != "the signature does not verify" {
		t.Errorf("a forged signature: %v", err)
	}
	if _, err := verifySigned("a.b", "RS256", key, now, 0); err == nil || err.Error() != "the token is not a compact JWS" {
		t.Errorf("not a compact JWS: %v", err)
	}
}

// A redirect's query is form-encoded with RFC 3986's unreserved characters left as they are.
func TestRedirectQueriesKeepTheUnreservedCharacters(t *testing.T) {
	got := redirectWith("https://app.example/cb?x=1", "state", "a~b c/d", "empty", "", "code", "k")
	if want := "https://app.example/cb?x=1&state=a~b+c%2Fd&code=k"; got != want {
		t.Errorf("redirect %q, want %q", got, want)
	}
}

func TestProblemTitlesAreSentences(t *testing.T) {
	for code, want := range map[string]string{
		CodeInvalidClient:    "Invalid client",
		CodeInvalidDPoPProof: "Invalid DPoP proof",
		CodeUnknownUserID:    "Unknown user ID",
		CodeNotFound:         "Not found",
	} {
		body, _ := refuse(refusal(code, "x")).Body.(map[string]any)
		if body["title"] != want {
			t.Errorf("%s: title %q, want %q", code, body["title"], want)
		}
	}
	if strings.Contains(problemTitle("slow_down"), "_") {
		t.Error("underscores")
	}
}
