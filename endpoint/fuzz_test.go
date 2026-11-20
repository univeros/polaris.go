package endpoint

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/internal/upstream"
	"github.com/univeros/polaris-go/manifest"
)

// fuzzRoutes is every upstream route, core and plugins.
func fuzzRoutes(f *testing.F) []*manifest.Route {
	f.Helper()
	dirs, err := fs.ReadDir(upstream.API, "api")
	if err != nil {
		f.Fatal(err)
	}
	var routes []*manifest.Route
	for _, d := range dirs {
		sub, err := fs.Sub(upstream.API, "api/"+d.Name())
		if err != nil {
			f.Fatal(err)
		}
		m, err := manifest.Load(sub)
		if err != nil {
			f.Fatal(err)
		}
		routes = append(routes, m.Routes()...)
	}
	return routes
}

// FuzzInput builds a request's Input from a hostile body, content type, query and cookie
// header, then validates it against every route's rules and reads it the way endpoints do.
// Nothing may panic, and route parameters always win.
func FuzzInput(f *testing.F) {
	f.Add([]byte(`{"email":"a@b.test","password":"x","id":"body","phone":"+15551234567","name":{"a":[1,2]}}`), "application/json", "id=q&email=", "id=c; email=x")
	f.Add([]byte(`email=a%40b&password=%ZZ&id=form`), "application/x-www-form-urlencoded", "a=%", "")
	f.Add([]byte("--b\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\nx\r\n--b--\r\n"), "multipart/form-data; boundary=b", "", "")
	f.Add([]byte(`[1,2,3]`), "", ";;", "=;=")
	f.Add([]byte(strings.Repeat("[", 20000)), "application/json", "", "")
	routes := fuzzRoutes(f)
	f.Fuzz(func(t *testing.T, body []byte, contentType, query, cookie string) {
		r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(string(body)))
		r.URL.RawQuery = query
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("Cookie", cookie)
		in := NewInput(r, map[string]string{"id": "path"})
		if in.String("id") != "path" {
			t.Fatalf("a route parameter was overridden: %v", in.Value("id"))
		}
		data := in.All()
		for _, rt := range routes {
			_ = rt.Validate(data)
		}
		for k := range data {
			_, _, _, _ = in.String(k), in.Strings(k), in.Bool(k), in.Map(k)
		}
	})
}
