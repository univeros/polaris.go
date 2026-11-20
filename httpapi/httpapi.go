// Package httpapi holds core's endpoints: one endpoint.Endpoint per route in upstream/api/core,
// registered by route name. Each area lives in its own files (auth, mfa, orgs).
package httpapi

import (
	"context"
	"net/http"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/wiring"
)

// Endpoints returns every core endpoint keyed by route name. A core route without an
// implementation yet answers 501 (TestNoPendingRoutes lists them; it must be empty to release).
func Endpoints(g *wiring.Graph) map[string]endpoint.Endpoint {
	out := map[string]endpoint.Endpoint{}
	for _, area := range []func(*wiring.Graph) map[string]endpoint.Endpoint{authEndpoints, mfaEndpoints, orgEndpoints} {
		for name, e := range area(g) {
			out[name] = e
		}
	}
	for _, r := range g.Manifest.Routes() {
		if r.Plugin != "" {
			continue
		}
		if _, ok := out[r.Name]; !ok {
			out[r.Name] = pending
		}
	}
	return out
}

var pending endpoint.Func = func(_ context.Context, _ *endpoint.Input) endpoint.Result {
	return endpoint.Error(http.StatusNotImplemented, "not_implemented", "This endpoint is not ported yet.")
}
