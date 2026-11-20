package endpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/token"
)

func TestInputMergeOrder(t *testing.T) {
	r := httptest.NewRequest("POST", "/orgs/p?q=query&id=query", strings.NewReader(`{"id":"body","q":"body","b":"body","n":5,"l":["a",1,"b"],"m":{"k":true},"t":true}`))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "c", Value: "cookie"})
	r.AddCookie(&http.Cookie{Name: "b", Value: "cookie"})
	in := NewInput(r, map[string]string{"id": "path"})
	if in.Has("c") {
		t.Error("a cookie is not input: a cookie tossed from a sibling subdomain could override a body field")
	}
	cases := map[string]string{"id": "path", "q": "query", "b": "body"}
	for k, want := range cases {
		if got := in.String(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if n, ok := in.Value("n").(json.Number); !ok || n.String() != "5" {
		t.Errorf("n = %#v", in.Value("n"))
	}
	if got := in.Strings("l"); len(got) != 2 || got[1] != "b" {
		t.Errorf("l = %v", got)
	}
	if !in.Map("m")["k"].(bool) || !in.Bool("t") || !in.Has("q") || in.Has("zz") {
		t.Error("accessors")
	}
	all := in.All()
	all["id"] = "x"
	if in.String("id") != "path" {
		t.Error("All must copy")
	}
}

func TestInputFormAndBadJSON(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("a=1&a=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := NewInput(r, nil).String("a"); got != "2" {
		t.Errorf("form a = %q", got)
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader("{bad"))
	if len(NewInput(r, nil).All()) != 0 {
		t.Error("bad JSON must contribute nothing")
	}
	if FromData(r, map[string]any{"x": "y"}).String("x") != "y" {
		t.Error("FromData")
	}
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return m
}

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, Data(200, map[string]any{"url": "a/b<c>"}).WithHeader("X-A", "1"))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("X-A") != "1" {
		t.Fatalf("headers %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), `"a/b<c>"`) {
		t.Errorf("html escaped: %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	Write(rec, NoContent())
	if rec.Code != 204 || rec.Header().Get("Content-Type") != "" || rec.Body.Len() != 0 {
		t.Error("204 must have no content type or body")
	}

	rec = httptest.NewRecorder()
	Write(rec, Problem(409, "api-keys/revoked", "Revoked", "The key is revoked.", map[string]any{"key_id": "k"}))
	m := decode(t, rec)
	if rec.Header().Get("Content-Type") != "application/problem+json" || m["error"] != "api_keys_revoked" || m["type"] != ProblemTypes+"api-keys/revoked" || m["status"].(float64) != 409 || m["key_id"] != "k" || m["message"] != m["detail"] {
		t.Errorf("problem %v", m)
	}

	rec = httptest.NewRecorder()
	Write(rec, Result{Status: 200, Raw: []byte("raw")})
	if rec.Body.String() != "raw" {
		t.Error("raw")
	}

	for _, r := range []Result{Unauthorized(), Forbidden("no"), NotFound("gone"), Error(400, "bad", "Bad.")} {
		rec = httptest.NewRecorder()
		Write(rec, r)
		if m := decode(t, rec); m["error"] == nil || m["message"] == nil {
			t.Errorf("envelope %v", m)
		}
	}
	rec = httptest.NewRecorder()
	Write(rec, Invalid(&manifest.ValidationError{}))
	if rec.Code != 422 || rec.Body.String() != `{"errors":[]}` {
		t.Errorf("422 %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	Write(rec, JSON(200, map[string]any{"bad": func() {}}))
	if decode(t, rec)["error"] != "server_error" {
		t.Error("unencodable body")
	}
}

func TestContext(t *testing.T) {
	ctx := context.Background()
	if Token(ctx) != nil || Authority(ctx) != nil || Route(ctx) != nil || Client(ctx) != (token.ClientContext{}) {
		t.Fatal("empty context")
	}
	if _, ok := MFATicket(ctx); ok {
		t.Fatal("ticket")
	}
	tok := &token.Token{}
	route := &manifest.Route{Name: "polaris.auth.me"}
	ctx = WithToken(ctx, tok)
	ctx = WithMFATicket(ctx, "u1")
	ctx = WithAuthority(ctx, "auth")
	ctx = WithClient(ctx, token.ClientContext{IP: "1.2.3.4"})
	ctx = WithRoute(ctx, route)
	uid, ok := MFATicket(ctx)
	if Token(ctx) != tok || !ok || uid != "u1" || Authority(ctx) != "auth" || Client(ctx).IP != "1.2.3.4" || Route(ctx) != route {
		t.Fatal("round trip")
	}
	var f Endpoint = Func(func(ctx context.Context, in *Input) Result { return NoContent() })
	if f.Serve(ctx, FromData(nil, nil)).Status != 204 {
		t.Fatal("Func")
	}
}
