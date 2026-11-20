package agents

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/endpoint"
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
