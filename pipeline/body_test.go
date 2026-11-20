package pipeline

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
)

func TestRequestBodiesAreBounded(t *testing.T) {
	_, all := manifests(t)
	var corePost, pluginPost *manifest.Route
	for _, rt := range all.Routes() {
		if rt.Method != http.MethodPost || strings.Contains(rt.Path, "{") || rt.Auth != manifest.AuthPublic {
			continue
		}
		if rt.Plugin == "" && corePost == nil {
			corePost = rt
		}
		if rt.Plugin != "" && pluginPost == nil {
			pluginPost = rt
		}
	}
	if corePost == nil || pluginPost == nil {
		t.Fatal("no anonymous POST routes in the manifests")
	}
	got := map[string]int{}
	o := options(t, all)
	for _, rt := range []*manifest.Route{corePost, pluginPost} {
		name := rt.Name
		o.Endpoints[name] = endpoint.Func(func(_ context.Context, in *endpoint.Input) endpoint.Result {
			got[name] = len(in.String("name"))
			return endpoint.Data(200, nil)
		})
	}
	o.MaxBodyBytes = 64
	p := newPipeline(t, o)
	body := func(n int) string { return `{"name":"` + strings.Repeat("x", n) + `"}` }
	post := func(h http.Handler, rt *manifest.Route, b string, chunked bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", rt.Path, strings.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		if chunked {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(b))
		}
		return serve(h, r)
	}

	if w := post(p.Handler(), corePost, body(40), false); w.Code != 200 || got[corePost.Name] != 40 {
		t.Fatalf("a body within the limit reaches the endpoint: %d %d", w.Code, got[corePost.Name])
	}
	for _, chunked := range []bool{false, true} {
		w := post(p.Handler(), corePost, body(80), chunked)
		var doc map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &doc)
		if w.Code != 413 || doc["error"] != "payload_too_large" || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("core route, chunked %v: %d %s", chunked, w.Code, w.Body)
		}
		w = post(p.Handler(), pluginPost, body(80), chunked)
		_ = json.Unmarshal(w.Body.Bytes(), &doc)
		if w.Code != 413 || doc["error"] != "payload_too_large" || w.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("plugin route, chunked %v: %d %s", chunked, w.Code, w.Body)
		}
		if w := post(p.Endpoints(), corePost, body(80), chunked); w.Code != 413 {
			t.Fatalf("Endpoints alone, chunked %v: %d", chunked, w.Code)
		}
	}

	o.MaxBodyBytes = -1
	if w := post(newPipeline(t, o).Handler(), corePost, body(2000), true); w.Code != 200 || got[corePost.Name] != 2000 {
		t.Fatalf("no limit: %d", w.Code)
	}
	o.MaxBodyBytes = 0
	if w := post(newPipeline(t, o).Handler(), corePost, body(DefaultMaxBodyBytes), false); w.Code != 413 {
		t.Fatalf("the default limit is 1 MiB: %d", w.Code)
	}
}
