package token

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
)

// Known-answer vectors: testdata/vectors/{jwt,oauth-jwt,receipt}.json hold tokens recorded once
// (their generator field names the implementation that recorded them). Polaris must keep minting
// them byte for byte and accepting or refusing them at the recorded instants, so issued tokens stay valid
// across releases.

type jwtCheck struct {
	Access bool `json:"access"`
	Verify bool `json:"verify"`
}

type jwtCase struct {
	Name       string              `json:"name"`
	Alg        Algorithm           `json:"alg"`
	Keys       string              `json:"keys"`
	Kid        string              `json:"kid"`
	Issuer     string              `json:"issuer"`
	Audience   string              `json:"audience"`
	TTL        int                 `json:"ttl"`
	Now        string              `json:"now"`
	Claims     json.RawMessage     `json:"claims"`
	Regenerate bool                `json:"regenerate"`
	Token      string              `json:"token"`
	Checks     map[string]jwtCheck `json:"checks"`
}

type jwksVector struct {
	Alg  Algorithm `json:"alg"`
	Keys []struct {
		Kid  string `json:"kid"`
		Keys string `json:"keys"`
	} `json:"keys"`
	Document string `json:"document"`
}

type jwtVectors struct {
	Generator string     `json:"generator"`
	Cases     []jwtCase  `json:"cases"`
	JWKS      jwksVector `json:"jwks"`
}

// checkOffsets are the instants, relative to a case, its recorded checks were made at.
func checkOffset(label string, ttl int) int {
	return map[string]int{"before": -1, "at": 0, "last": ttl - 1, "expiry": ttl}[label]
}

func TestJWTVectors(t *testing.T) {
	var v jwtVectors
	readVector(t, "jwt.json", &v)
	if v.Generator != "php" || len(v.Cases) == 0 {
		t.Fatalf("unexpected vector file: %+v", v)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Regenerate {
				got := mustIssue(t, newCodec(t, c.config(t, c.Now)), orderedClaims(t, c.Claims))
				if got != c.Token {
					t.Fatalf("Go minted a different token\n go %s\nwant %s", got, c.Token)
				}
			}
			goChecks := map[string]jwtCheck{}
			for label, want := range c.Checks {
				instant := plusSeconds(t, c.Now, checkOffset(label, c.TTL))
				codec := newCodec(t, c.config(t, instant))
				tok, err := codec.Parse(c.Token)
				_, verr := codec.Verify(c.Token)
				goChecks[label] = jwtCheck{Access: err == nil, Verify: verr == nil}
				if goChecks[label] != want {
					t.Errorf("%s: Go access/verify = %+v (%v, %v), recorded = %+v", label, goChecks[label], err, verr, want)
				}
				if tok != nil {
					sub, _ := orderedClaims(t, c.Claims).Get("sub")
					if tok.Subject() != sub {
						t.Errorf("%s: sub = %q, want %v", label, tok.Subject(), sub)
					}
				}
			}
		})
	}

	keys := make([]PublicKey, 0, len(v.JWKS.Keys))
	for _, k := range v.JWKS.Keys {
		keys = append(keys, PublicKey{KeyID: k.Kid, PEM: keyPair(t, k.Keys).public})
	}
	set, err := NewJWKSet(v.JWKS.Alg, keys...)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(set)
	if string(doc) != v.JWKS.Document {
		t.Fatalf("JWKS differs\n go %s\nwant %s", doc, v.JWKS.Document)
	}
}

func (c jwtCase) config(t *testing.T, instant string) Config {
	pair := keyPair(t, c.Keys)
	return Config{
		Algorithm: c.Alg, PublicKey: pair.public, PrivateKey: pair.private, KeyID: c.Kid,
		Issuer: c.Issuer, Audience: c.Audience, TTL: time.Duration(c.TTL) * time.Second,
		Clock: clock.NewFrozen(parseInstant(t, instant)),
	}
}

type pemPair struct{ public, private string }

func keyPair(t *testing.T, name string) pemPair {
	k := loadKeys(t)
	switch name {
	case "rsa":
		return pemPair{k.RSA.Public, k.RSA.Private}
	case "rsa_alternate":
		return pemPair{k.RSAAlternate.Public, k.RSAAlternate.Private}
	case "eddsa":
		return pemPair{k.edPublic(), k.edSecret()}
	}
	t.Fatalf("unknown key pair %q", name)
	return pemPair{}
}

// parseInstant reads seconds.microseconds ("1780833600.123456").
func parseInstant(t *testing.T, s string) time.Time {
	sec, usec, _ := strings.Cut(s, ".")
	n, err1 := strconv.ParseInt(sec, 10, 64)
	u, err2 := strconv.ParseInt(usec, 10, 64)
	if err1 != nil || err2 != nil {
		t.Fatalf("bad instant %q", s)
	}
	return time.Unix(n, u*1000).UTC()
}

func plusSeconds(t *testing.T, s string, seconds int) string {
	ts := parseInstant(t, s).Add(time.Duration(seconds) * time.Second)
	return fmt.Sprintf("%d.%06d", ts.Unix(), ts.Nanosecond()/1000)
}

// orderedClaims decodes a JSON object (or [] for an empty one) into Claims, keeping key order
// and the decoder's number types (int64 when integral, float64 otherwise).
func orderedClaims(t *testing.T, raw json.RawMessage) Claims {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeOrdered(dec)
	if err != nil {
		t.Fatal(err)
	}
	switch v := v.(type) {
	case Claims:
		return v
	case []any:
		if len(v) == 0 {
			return Claims{}
		}
	}
	t.Fatalf("claims are not an object: %s", raw)
	return Claims{}
}

func decodeOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok := tok.(type) {
	case json.Delim:
		if tok == '[' {
			list := []any{}
			for dec.More() {
				e, err := decodeOrdered(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, e)
			}
			_, err := dec.Token()
			return list, err
		}
		obj := Claims{}
		for dec.More() {
			key, err := dec.Token()
			if err != nil {
				return nil, err
			}
			val, err := decodeOrdered(dec)
			if err != nil {
				return nil, err
			}
			obj = obj.With(key.(string), val)
		}
		_, err := dec.Token()
		return obj, err
	case json.Number:
		return parseNumber(string(tok)), nil
	default:
		return tok, nil
	}
}

func readVector(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}

type oauthSide struct {
	Keys         string `json:"keys"`
	Kid          string `json:"kid"`
	PreviousKeys string `json:"previous_keys"`
	PreviousKid  string `json:"previous_kid"`
}

type oauthCase struct {
	Name       string          `json:"name"`
	Alg        Algorithm       `json:"alg"`
	Typ        string          `json:"typ"`
	Issuer     string          `json:"issuer"`
	Now        string          `json:"now"`
	ExpiresAt  string          `json:"expires_at"`
	Minter     oauthSide       `json:"minter"`
	Verifier   oauthSide       `json:"verifier"`
	Claims     json.RawMessage `json:"claims"`
	CheckAt    []string        `json:"check_at"`
	Regenerate bool            `json:"regenerate"`
	Token      string          `json:"token"`
	Checks     map[string]bool `json:"checks"`
}

type oauthVectors struct {
	Generator string      `json:"generator"`
	Cases     []oauthCase `json:"cases"`
}

// oauthLeeway is the leeway the OAuth provider verifies its JWTs with.
const oauthLeeway = 60 * time.Second

func (c oauthCase) codec(t *testing.T, side oauthSide, instant string) *Codec {
	pair := keyPair(t, side.Keys)
	cfg := Config{
		Algorithm: c.Alg, PublicKey: pair.public, PrivateKey: pair.private, KeyID: side.Kid,
		Issuer: c.Issuer, TTL: 900 * time.Second, Clock: clock.NewFrozen(parseInstant(t, instant)),
	}
	if side.PreviousKeys != "" {
		cfg.PreviousPublicKey, cfg.PreviousKeyID = keyPair(t, side.PreviousKeys).public, side.PreviousKid
	}
	return newCodec(t, cfg)
}

func TestOAuthJWTVectors(t *testing.T) {
	var v oauthVectors
	readVector(t, "oauth-jwt.json", &v)
	if v.Generator != "php" || len(v.Cases) == 0 {
		t.Fatalf("unexpected vector file: %+v", v)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, err := c.codec(t, c.Minter, c.Now).Mint(c.Typ, orderedClaims(t, c.Claims), parseInstant(t, c.ExpiresAt))
			if err != nil {
				t.Fatal(err)
			}
			if c.Regenerate && got != c.Token {
				t.Fatalf("Go minted a different token\n go %s\nwant %s", got, c.Token)
			}
			goChecks := map[string]bool{}
			for _, instant := range c.CheckAt {
				tok, err := c.codec(t, c.Verifier, instant).VerifyJWT(c.Token, oauthLeeway)
				goChecks[instant] = err == nil
				if goChecks[instant] != c.Checks[instant] {
					t.Errorf("at %s: Go err = %v, recorded accepts = %v", instant, err, c.Checks[instant])
				}
				if tok != nil && c.Typ != "" && tok.Header("typ") != c.Typ {
					t.Errorf("typ = %v", tok.Header("typ"))
				}
			}
		})
	}
}

type receiptCase struct {
	Name     string    `json:"name"`
	Alg      Algorithm `json:"alg"`
	Issuer   string    `json:"issuer"`
	Keys     string    `json:"keys"`
	Kid      string    `json:"kid"`
	Verifier oauthSide `json:"verifier"`
	Receipt  struct {
		ID        string `json:"id"`
		AgentID   string `json:"agent_id"`
		Seq       int64  `json:"seq"`
		Hash      string `json:"hash"`
		CreatedAt string `json:"created_at"`
	} `json:"receipt"`
	CheckAt []string        `json:"check_at"`
	Token   string          `json:"token"`
	Checks  map[string]bool `json:"checks"`
}

func TestReceiptVectors(t *testing.T) {
	var v struct {
		Generator string        `json:"generator"`
		Cases     []receiptCase `json:"cases"`
	}
	readVector(t, "receipt.json", &v)
	if v.Generator != "php" || len(v.Cases) == 0 {
		t.Fatalf("unexpected vector file: %+v", v)
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			oc := oauthCase{Alg: c.Alg, Issuer: c.Issuer}
			signer := oc.codec(t, oauthSide{Keys: c.Keys, Kid: c.Kid}, c.Receipt.CreatedAt)
			r := c.Receipt
			got, err := signer.Sign("receipt+jwt", Claims{}.
				With("iat", parseInstant(t, r.CreatedAt)).
				With("receipt_hash", r.Hash).With("receipt_id", r.ID).With("agent_id", r.AgentID).With("seq", r.Seq))
			if err != nil {
				t.Fatal(err)
			}
			if got != c.Token {
				t.Fatalf("Go signed a different receipt\n go %s\nwant %s", got, c.Token)
			}
			goChecks := map[string]bool{}
			for _, instant := range c.CheckAt {
				tok, err := oc.codec(t, c.Verifier, instant).VerifyJWT(c.Token, oauthLeeway)
				goChecks[instant] = err == nil && tok.Header("typ") == "receipt+jwt"
				if goChecks[instant] != c.Checks[instant] {
					t.Errorf("at %s: Go err = %v, recorded accepts = %v", instant, err, c.Checks[instant])
				}
			}
		})
	}
}
