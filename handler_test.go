package polaris_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/wiring"
)

type pagesPlugin struct{ id, prefix string }

func (p pagesPlugin) ID() string { return p.id }

func (p pagesPlugin) Handler(*wiring.Graph) (string, http.Handler) {
	return p.prefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("page " + r.URL.Path))
	})
}

func TestPluginHandlersServeTheirPrefixOnly(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPathPrefix("/api"), polaristest.WithPlugins(pagesPlugin{id: "pages", prefix: "/pages"}))
	for path, want := range map[string]string{
		"/api/pages":          "page /api/pages",
		"/api/pages/sign-in":  "page /api/pages/sign-in",
		"/api/pagesx":         `"not_found"`,
		"/api/auth/me":        `"unauthorized"`,
		"/pages/not-prefixed": `"not_found"`,
	} {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("GET %s = %d %s, want %s", path, rec.Code, rec.Body, want)
		}
	}
}

func TestPluginHandlerPrefixMustBeItsOwn(t *testing.T) {
	base := polaristest.New(t).Graph().Config()
	cases := map[string][]polaris.Plugin{
		"overlaps /auth/*":    {pagesPlugin{id: "pages", prefix: "/auth"}},
		"is a route":          {pagesPlugin{id: "pages", prefix: "/auth/login"}},
		"relative":            {pagesPlugin{id: "pages", prefix: "pages"}},
		"trailing slash":      {pagesPlugin{id: "pages", prefix: "/pages/"}},
		"root":                {pagesPlugin{id: "pages", prefix: "/"}},
		"taken by a plugin":   {pagesPlugin{id: "a", prefix: "/a"}, pagesPlugin{id: "b", prefix: "/a"}},
		"under another's one": {pagesPlugin{id: "a", prefix: "/a"}, pagesPlugin{id: "b", prefix: "/a/b"}},
	}
	for name, plugins := range cases {
		cfg := base
		cfg.Plugins = plugins
		if _, err := polaris.New(cfg); err == nil {
			t.Errorf("%s: New accepted it", name)
		}
	}
}
