package agents

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/endpoint"
)

// Protect and Guard read the body for its hash and arguments: never more than MaxBodyBytes.
func TestProtectedRoutesBoundTheBody(t *testing.T) {
	located := unitCapability("invite", RiskLow, "deploy.staging")
	located.Location, located.Handler = "https://app.polaris.test/invitations", nil
	p, _ := bootUnit(t, Config{Capabilities: []Capability{located}, MaxBodyBytes: 64})
	reached := false
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	for name, guarded := range map[string]http.Handler{"Protect": p.Protect("invite", h), "Guard": p.Guard(h)} {
		for _, chunked := range []bool{false, true} {
			r := httptest.NewRequest("POST", located.Location, strings.NewReader(`{"x":"`+strings.Repeat("a", 100)+`"}`))
			if chunked {
				r.ContentLength = -1
				r.Body = io.NopCloser(r.Body)
			}
			w := httptest.NewRecorder()
			guarded.ServeHTTP(w, r)
			var doc map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &doc)
			if w.Code != http.StatusRequestEntityTooLarge || doc["type"] != endpoint.ProblemTypes+"agents/payload_too_large" || reached {
				t.Fatalf("%s, chunked %v: %d %s", name, chunked, w.Code, w.Body)
			}
		}
	}
	if _, _, err := (Config{MaxBodyBytes: -1}).resolve(); err == nil || !strings.Contains(err.Error(), "MaxBodyBytes") {
		t.Errorf("a negative limit is a configuration error: %v", err)
	}
}

// The arguments a grant's constraints are checked on are the whole body: a body holding more than
// one JSON value has none, so a constrained argument is missing and refused, rather than checked on
// the first value while the handler reads another.
func TestBodyArgumentsAreTheWholeBody(t *testing.T) {
	for body, want := range map[string]int{`{"amount":1}`: 1, " {\"amount\":1}\n": 1, `{"amount":1}{"amount":1000}`: 0, `{"amount":1}0`: 0, `null`: 0, `[]`: 0, ``: 0} {
		if got, err := bodyArguments([]byte(body)); got == nil || len(got) != want || err != nil {
			t.Errorf("%q: %v %v", body, got, err)
		}
	}
}

// Nor may two members of one object name the same thing: a Go handler decoding the body into a struct
// matches names whatever their case and keeps the last, where the checks read each on its own.
func TestABodyWhoseMembersAreAmbiguousIsRefused(t *testing.T) {
	for body, ok := range map[string]bool{
		`{"email":"a","Email":"b"}`:               false,
		`{"email":"a","email":"b"}`:               false,
		`{"email":"a","\u0045mail":"b"}`:          false,
		`{"task":"a","ta\u017fk":"b"}`:            false, // the long s folds to s
		`{"x":{"a":{"y":1}},"z":[{"k":1,"K":2}]}`: false,
		`{"x":{"a":1},"y":{"a":1}}`:               true,
		`{"email":["email","Email"],"e":"email"}`: true,
		`[{"a":1},{"A":1}]`:                       true,
	} {
		if _, err := bodyArguments([]byte(body)); (err == nil) != ok {
			t.Errorf("%s: %v", body, err)
		}
	}
	located := unitCapability("invite", RiskLow, "deploy.staging")
	located.Location, located.Handler = "https://app.polaris.test/invitations", nil
	other := unitCapability("remove", RiskLow, "deploy.staging")
	other.Location, other.Handler = "https://admin.polaris.test/invitations", nil
	p, _ := bootUnit(t, Config{Capabilities: []Capability{located, other}})
	reached := false
	guarded := p.Guard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	// Two hosts share the path: a Host that is neither is refused, not matched to either.
	r := httptest.NewRequest("POST", "https://elsewhere.polaris.test/invitations", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	guarded.ServeHTTP(w, r)
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	if reached || w.Code != http.StatusNotFound || doc["type"] != endpoint.ProblemTypes+"agents/capability_not_found" {
		t.Fatalf("an unknown host: %d %s", w.Code, w.Body)
	}
}
