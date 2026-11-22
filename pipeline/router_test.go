package pipeline

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/contracttest"
)

func TestRouterMatchesParametersAndReportsAllowedMethods(t *testing.T) {
	core, _ := manifests(t)
	rt := newRouter(core, "/api")

	route, params, _ := rt.match("delete", "/api/auth/sessions/0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b")
	if route == nil || route.Pattern() != "DELETE /auth/sessions/{id}" {
		t.Fatalf("route = %v", route)
	}
	if params["id"] != "0192a1b2-c3d4-7e5f-8a6b-7c8d9e0f1a2b" || len(params) != 1 {
		t.Fatalf("params = %v", params)
	}

	route, _, allowed := rt.match("PUT", "/api/auth/login")
	if route != nil || !slices.Equal(allowed, []string{"POST"}) {
		t.Fatalf("PUT /auth/login: route %v allowed %v", route, allowed)
	}
	route, _, allowed = rt.match("GET", "/api/nope")
	if route != nil || len(allowed) != 0 {
		t.Fatalf("GET /nope: route %v allowed %v", route, allowed)
	}
	if route, _, _ := newRouter(core, "").match("GET", "/auth/me"); route == nil {
		t.Fatal("no prefix: GET /auth/me unmatched")
	}
}

func TestRouteAnswers404And405InTheEnvelope(t *testing.T) {
	core, _ := manifests(t)
	h := newPipeline(t, options(t, core)).Handler()

	w := serve(h, httptest.NewRequest("GET", "/auth/does-not-exist", nil))
	if w.Code != 404 || w.Body.String() != `{"error":"not_found","message":"No such endpoint."}` {
		t.Fatalf("404: %d %s", w.Code, w.Body)
	}
	w = serve(h, httptest.NewRequest("PUT", "/auth/login", nil))
	if w.Code != 405 || w.Header().Get("Allow") != "POST" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("405: %d %v", w.Code, w.Header())
	}
	if w.Body.String() != `{"error":"method_not_allowed","message":"The method is not allowed for this endpoint."}` {
		t.Fatalf("405 body: %s", w.Body)
	}
}

func TestEndpointsRoutesWithoutTheRouteMiddleware(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	o.Endpoints["polaris.auth.session-revoke"] = endpoint.Func(func(_ context.Context, in *endpoint.Input) endpoint.Result {
		return endpoint.Data(200, map[string]any{"id": in.String("id"), "route": endpoint.Route(in.Request.Context()).Name})
	})
	h := newPipeline(t, o).Endpoints()

	w := serve(h, httptest.NewRequest("DELETE", "/auth/sessions/abc", nil))
	if w.Code != 200 || w.Body.String() != `{"data":{"id":"abc","route":"polaris.auth.session-revoke"}}` {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if w := serve(h, httptest.NewRequest("GET", "/nope", nil)); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
}

// An empty result body stays empty, through the dispatcher.
func TestEmptyResultBodyStaysEmpty(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	o.Endpoints["polaris.auth.me"] = endpoint.Func(func(context.Context, *endpoint.Input) endpoint.Result {
		return endpoint.NoContent()
	})
	o.Endpoints["polaris.auth.sessions-list"] = endpoint.Func(func(context.Context, *endpoint.Input) endpoint.Result {
		return endpoint.Data(201, map[string]any{"id": 1}).WithHeader("Location", "/x")
	})
	p := newPipeline(t, o)
	tok := issue(t, "user-1", nil)

	empty := serve(p.Endpoints(), withToken(routed(t, core, "GET", "/auth/me"), tok))
	full := serve(p.Endpoints(), withToken(routed(t, core, "GET", "/auth/sessions"), tok))
	if empty.Code != 204 || empty.Body.Len() != 0 || empty.Header().Get("Content-Type") != "" {
		t.Fatalf("204: %d %q %v", empty.Code, empty.Body, empty.Header())
	}
	if full.Body.String() != `{"data":{"id":1}}` || full.Header().Get("Location") != "/x" || full.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("201: %s %v", full.Body, full.Header())
	}
}

// The recorded fixtures reach every core route, so their replay freezes the whole contract.
func TestEveryManifestRouteIsCoveredByARecordedFixture(t *testing.T) {
	core, _ := manifests(t)
	requests, err := contracttest.Requests(contracttest.Fixtures(t, "core"))
	if err != nil {
		t.Fatal(err)
	}
	rt := newRouter(core, "/")
	covered := map[string]bool{}
	for _, req := range requests {
		route, _, _ := rt.match(req.Method, req.Path)
		if route == nil {
			// JwksEndpointTest::testUnknownRouteIsNotFound is the only recorded request off the manifest.
			if req.Method+" "+req.Path != "GET /auth/does-not-exist" {
				t.Errorf("recorded %s %s matches no manifest route", req.Method, req.Path)
			}
			continue
		}
		covered[route.Name] = true
	}
	var missing []string
	for _, route := range core.Routes() {
		if !covered[route.Name] {
			missing = append(missing, route.Pattern())
		}
	}
	if len(missing) > 0 {
		t.Errorf("every manifest route needs a recorded fixture; missing %v", missing)
	}
	if len(requests) <= 1000 {
		t.Errorf("only %d recorded steps", len(requests))
	}
	if len(covered) != len(core.Routes()) {
		t.Errorf("covered %d of %d routes", len(covered), len(core.Routes()))
	}
}

func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	return m
}
