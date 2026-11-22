package agents

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/store"
)

func TestTimestampsAreRFC3339InUTC(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 30, 0, 0, time.FixedZone("CET", 3600))
	g := Grant{CreatedAt: at, UpdatedAt: at, ExpiresAt: &at}.view()
	for _, k := range []string{"created_at", "updated_at", "expires_at"} {
		if g[k] != "2026-11-22T09:30:00Z" {
			t.Errorf("%s = %v", k, g[k])
		}
	}
	if (Grant{}).view()["expires_at"] != nil {
		t.Error("no expiry is null")
	}
}

func TestRequestJWTErrorsReadAsGo(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwk := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	j := &requestJWTs{clock: clock.NewFrozen(now)}
	sign := func(payload string) string {
		in := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"agent+jwt"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
		return in + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(in)))
	}
	later := now.Add(time.Hour).Unix()
	for payload, want := range map[string]string{
		`[1]`:                         "the claims are not a JSON object",
		`{"nbf":` + itoa(later) + `}`: "the token is not valid before 2026-11-22T13:00:00Z",
		`{"iat":` + itoa(later) + `}`: "the token was issued in the future (2026-11-22T13:00:00Z)",
		`{"exp":` + itoa(now.Add(-time.Hour).Unix()) + `}`: "the token has expired",
	} {
		if _, err := j.decode(sign(payload), jwk); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", payload, err, want)
		}
	}
	tampered := sign(`{}`)
	tampered = tampered[:len(tampered)-4] + "AAAA"
	if _, err := j.decode(tampered, jwk); err == nil || err.Error() != "the signature does not verify" {
		t.Errorf("signature: %v", err)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestArgumentsAreAnObject(t *testing.T) {
	for _, v := range []any{nil, map[string]any{}} {
		if _, ok := arguments(v); !ok {
			t.Errorf("%v refused", v)
		}
	}
	for _, v := range []any{[]any{}, []any{"x"}, "x", json.Number("1")} {
		if _, ok := arguments(v); ok {
			t.Errorf("%v accepted as arguments", v)
		}
	}
}

func TestPagingFieldsAreIntegers(t *testing.T) {
	in := func(q string) *endpoint.Input {
		return endpoint.NewInput(httptest.NewRequest("GET", "/agents/x/receipts?"+q, nil), nil)
	}
	for q, want := range map[string]int{"": 7, "limit=5": 5, "limit=0": 0, "limit=-3": -3} {
		if n, ok := intField(in(q), "limit", 7); !ok || n != want {
			t.Errorf("%q: %d %v, want %d", q, n, ok, want)
		}
	}
	for _, q := range []string{"limit=1e2", "limit=2.5", "limit=%205", "limit=x", "limit=0x10"} {
		if _, ok := intField(in(q), "limit", 7); ok {
			t.Errorf("%q accepted", q)
		}
	}
	body := endpoint.FromData(nil, map[string]any{"limit": json.Number("5"), "after": json.Number("2.5")})
	if n, ok := intField(body, "limit", 7); !ok || n != 5 {
		t.Errorf("json number: %d %v", n, ok)
	}
	if _, ok := intField(body, "after", 0); ok {
		t.Error("a fraction accepted")
	}
}

func TestCapabilityListsAreLists(t *testing.T) {
	in := endpoint.FromData(nil, map[string]any{"capabilities": map[string]any{"0": "a"}, "none": nil, "list": []any{"a"}})
	if _, ok := listOf(in, "capabilities"); ok {
		t.Error("an object read as a list")
	}
	if l, ok := listOf(in, "list"); !ok || len(l) != 1 {
		t.Error("a list")
	}
	if l, ok := listOf(in, "none"); !ok || l != nil {
		t.Error("null is empty")
	}
}

// Rows written by earlier releases may hold [] for an empty object; they keep reading.
func TestStoredConstraintsReadTheirOldForms(t *testing.T) {
	for stored, want := range map[string]int{`[]`: 0, `{"amount":[]}`: 1, `{"amount":{"max":1.0}}`: 1} {
		g := grantFromRow(store.Row{"constraints": stored})
		if len(g.Constraints) != want {
			t.Errorf("%s: %v", stored, g.Constraints)
		}
		if v := violations(g.Constraints, map[string]any{"amount": json.Number("1")}); len(v) != 0 {
			t.Errorf("%s: violations %v", stored, v)
		}
	}
}

// A receipt's hash covers its created_at text: receipts already issued (and the agent SDK, which
// hashes the text as sent) verify only while that text keeps the form they were hashed in.
func TestAReceiptHashesItsCreationTimeInTheIssuedForm(t *testing.T) {
	r := Receipt{ID: "r1", AgentID: "a1", Seq: 1, InputHash: "ih", Outcome: OutcomeSuccess,
		CreatedAt: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	want := `{"agent_id":"a1","budget_after":null,"budget_before":null,"capability":null,"created_at":"2026-11-22T10:00:00+00:00","grant_id":null,"id":"r1","input_hash":"ih","outcome":"success","prev_hash":null,"seq":1}`
	if got := canonicalJSON(r.hashed()); got != want {
		t.Errorf("hashed form\n got %s\nwant %s", got, want)
	}
	if r.view()["created_at"] != "2026-11-22T10:00:00+00:00" {
		t.Errorf("the receipt shows the text its hash covers: %v", r.view()["created_at"])
	}
}

func TestProblemTitlesAreSentences(t *testing.T) {
	for typ, want := range map[string]string{
		"invalid_jwt": "Invalid JWT", "capability_not_granted": "Capability not granted",
		"not_found": "Not found", "unauthorized": "Unauthorized",
	} {
		if got := (&Error{Type: typ}).problem()["title"]; got != want {
			t.Errorf("title of %q = %q, want %q", typ, got, want)
		}
	}
}
