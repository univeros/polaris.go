package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/netguard"
)

// Every endpoint a discovery document names is an absolute http(s) URL: the browser is sent to two of
// them.
func TestADiscoveryDocumentsEndpointsAreWebURLs(t *testing.T) {
	for _, name := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri", "end_session_endpoint"} {
		for _, bad := range []string{"javascript:alert(1)//", "data:text/html,x", "//evil.example/x", "/relative", "https:evil.example"} {
			var issuer string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				doc := map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
					"jwks_uri": issuer + "/jwks", "end_session_endpoint": issuer + "/end"}
				doc[name] = bad
				_ = json.NewEncoder(w).Encode(doc)
			}))
			issuer = srv.URL
			o := &HTTPOIDC{HTTP: netguard.NoRedirects(&http.Client{}), Cache: cache.NewMemory(clock.System{}), Clock: clock.System{}}
			prov := testProvider(TypeOIDC, map[string]any{"client_id": "c1"}, issuer, nil)
			for range 2 { // the second reads what was cached
				u, err := o.AuthorizationURL(context.Background(), prov, testBase+"/sso/callback/p1", "s", "n", "c")
				refusedAs(t, err, ReasonAssertionInvalid, name, name+" "+bad)
				if end := o.EndSessionURL(context.Background(), prov, ""); u != "" || end != "" {
					t.Errorf("%s %q: %q %q", name, bad, u, end)
				}
			}
			srv.Close()
		}
	}
}
