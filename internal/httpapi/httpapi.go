// Package httpapi holds core's endpoints: one endpoint.Endpoint per route in internal/apispec/api/core,
// registered by route name. Each area lives in its own files (auth, mfa, orgs).
package httpapi

import (
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/wiring"
)

// Endpoints returns every core endpoint keyed by route name. Every core route has one
// (TestNoPendingRoutes); a route without one would make pipeline.New fail at startup, naming it.
func Endpoints(g *wiring.Graph) map[string]endpoint.Endpoint {
	out := map[string]endpoint.Endpoint{}
	for _, area := range []func(*wiring.Graph) map[string]endpoint.Endpoint{authEndpoints, mfaEndpoints, orgEndpoints} {
		for name, e := range area(g) {
			out[name] = e
		}
	}
	return out
}
