// Package httpapi holds core's endpoints: one endpoint.Endpoint per route in internal/apispec/api/core,
// registered by route name. Each area lives in its own files (auth, mfa, orgs).
package httpapi

import (
	"context"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/wiring"
)

// Endpoints returns every core endpoint keyed by route name. Every core route has one
// (TestNoPendingRoutes); a route without one would make pipeline.New fail at startup, naming it.
// Each endpoint first checks its input's JSON types against its spec (typed).
func Endpoints(g *wiring.Graph) map[string]endpoint.Endpoint {
	out := map[string]endpoint.Endpoint{}
	for _, area := range []func(*wiring.Graph) map[string]endpoint.Endpoint{authEndpoints, mfaEndpoints, orgEndpoints} {
		for name, e := range area(g) {
			if r, ok := g.Manifest().Named(name); ok {
				e = typed(r.Input.Fields, e)
			}
			out[name] = e
		}
	}
	return out
}

// typed answers 422 before e runs when a field holds another JSON type than its spec declares:
// a string field takes a string, a boolean field true or false, a list<string> field a list of
// strings. Nothing is coerced. An absent or null field is left to the endpoint's own rules.
func typed(fields []manifest.Field, e endpoint.Endpoint) endpoint.Endpoint {
	return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
		var problems []string
		for _, f := range fields {
			if v := in.Value(f.Name); v != nil && !hasType(v, strings.TrimPrefix(f.Type, "?")) {
				problems = append(problems, f.Name+" must be "+typeNames[strings.TrimPrefix(f.Type, "?")]+".")
			}
		}
		if problems != nil {
			return endpoint.Unprocessable(problems)
		}
		return e.Serve(ctx, in)
	})
}

// typeNames are the declared field types core checks, as a 422 names them.
var typeNames = map[string]string{"string": "a string", "boolean": "true or false", "list<string>": "a list of strings"}

func hasType(v any, declared string) bool {
	switch declared {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "list<string>":
		list, ok := v.([]any)
		for _, item := range list {
			if _, isString := item.(string); !isString {
				return false
			}
		}
		return ok
	}
	return true // a type core does not declare is not checked
}
