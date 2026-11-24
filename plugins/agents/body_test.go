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
	for body, want := range map[string]int{`{"amount":1}`: 1, " {\"amount\":1}\n": 1, ``: 0, " \r\n\t": 0} {
		if got, err := bodyArguments([]byte(body)); got == nil || len(got) != want || err != nil {
			t.Errorf("%q: %v %v", body, got, err)
		}
	}
	for _, body := range []string{`null`, `[]`, `"x"`, `amount=1`, "\xef\xbb\xbf{}"} {
		if _, err := bodyArguments([]byte(body)); err == nil {
			t.Errorf("%q is taken as no arguments, and a handler may read it", body)
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
		`[{"a":1},{"A":1}]`:                       false, // no object
		`{"email":"a"} x`:                         false, // a handler reads the first value
		` {"email":"a"}{"email":"b"}`:             false,
		`{"email":`:                               false,
		`email=a`:                                 false,
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

// A router decodes the path before it matches: whatever it would take for a location's path is guarded.
func TestGuardDecodesThePathAsARouterDoes(t *testing.T) {
	located := unitCapability("invite", RiskLow, "deploy.staging")
	located.Location, located.Handler = "https://app.polaris.test/v1/users:invite", nil
	p, _ := bootUnit(t, Config{Capabilities: []Capability{located}})
	reached := ""
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/users:invite", func(_ http.ResponseWriter, r *http.Request) { reached = r.RequestURI })
	lenient := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { // matches the decoded path
		if r.URL.Path == "/v1/users:invite" {
			reached = r.RequestURI
		}
	})
	for name, router := range map[string]http.Handler{"ServeMux": mux, "decoded path": lenient} {
		srv := httptest.NewServer(p.Guard(router))
		defer srv.Close()
		for _, path := range []string{"/v1/users:invite", "/v1/users%3Ainvite", "/v1/users%3ainvite", "/v1/%75sers%3Ainvite", "/v1%2Fusers:invite", "/v1%2fusers%3Ainvite",
			"/v1/./users%3Ainvite", "/v1/x/../users%3Ainvite", "/v1/x/%2e%2e/users%3Ainvite", "//v1//users%3Ainvite", "/v1/users%3Ainvite/"} {
			resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if reached != "" {
				t.Errorf("%s: %s reached the handler (%d)", name, path, resp.StatusCode)
				reached = ""
			}
		}
		if resp, err := http.Post(srv.URL+"/v1/users%253Ainvite", "application/json", nil); err != nil || resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("%s: another path is not guarded: %v %v", name, resp, err)
		}
	}
}

// A declared argument spelled in another case is refused, at any depth: the schema and the constraints
// read past it, a Go handler does not.
func TestAMisspelledArgumentIsFound(t *testing.T) {
	schema := map[string]any{"properties": map[string]any{
		"amount": map[string]any{"type": "number"},
		"to":     map[string]any{"properties": map[string]any{"email": map[string]any{}}},
		"items":  map[string]any{"items": map[string]any{"properties": map[string]any{"sku": map[string]any{}}}},
	}}
	for body, want := range map[string]string{
		`{"amount":1,"to":{"email":"a"},"items":[{"sku":"x"}],"note":"Amount"}`: "",
		`{"Amount":1000}`:                          "Amount",
		`{"to":{"Email":"a"}}`:                     "Email",
		`{"items":[{"sku":"x"},{"SKU":"y"}]}`:      "SKU",
		`{"free":{"Email":"a"},"other":[{"x":1}]}`: "",
	} {
		args, err := bodyArguments([]byte(body))
		if got := misspelled(schema, args); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", body, got, err, want)
		}
	}
	located := unitCapability("refund", RiskLow, "deploy.staging")
	located.Location, located.Handler = "https://app.polaris.test/refunds", nil
	located.Input = map[string]any{"type": "object", "properties": map[string]any{"amount": map[string]any{"type": "number", "maximum": 100}}}
	_ = located.check()
	args, _ := bodyArguments([]byte(`{"Amount":1000}`))
	if err := checkSpelling(&located, args); err == nil {
		t.Error("the capability's own schema")
	}
}

// The arguments the checks read are the ones the handler reads: an object, as it was sent, or nothing.
func TestTheArgumentsOfAnExecution(t *testing.T) {
	c := &Capability{Name: "invite"}
	for body, want := range map[string]string{
		`{"capability":"invite"}`: "{}", `{"capability":"invite","arguments":null}`: "{}", ` {"arguments": {"a" : 1.0} , "capability":"invite"} `: `{"a" : 1.0}`,
		`{"capability":"invite","arguments":[]}`: "", `{"capability":"invite","arguments":"{}"}`: "", `{"capability":"invite","arguments":1}`: "",
		`{"capability":null}`: "", `{"capability":"Invite"}`: "", `{}`: "",
	} {
		got, err := executionArguments([]byte(body), c)
		if string(got) != want || (err == nil) != (want != "") {
			t.Errorf("%s: %s %v", body, got, err)
		}
	}
}
