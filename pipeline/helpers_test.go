package pipeline

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/internal/upstream"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/token"
)

var now = time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

var (
	manifestsOnce           sync.Once
	coreManifest, allRoutes *manifest.Manifest
	manifestErr             error
)

// manifests loads core's manifest and core plus every plugin's (as upstream's cookie test does).
func manifests(t testing.TB) (core, all *manifest.Manifest) {
	t.Helper()
	manifestsOnce.Do(func() {
		sub := func(name string) fs.FS { f, _ := fs.Sub(upstream.API, "api/"+name); return f }
		if coreManifest, manifestErr = manifest.Load(sub("core")); manifestErr != nil {
			return
		}
		entries, _ := fs.ReadDir(upstream.API, "api")
		dirs := []fs.FS{sub("core")}
		for _, e := range entries {
			if e.IsDir() && e.Name() != "core" {
				dirs = append(dirs, sub(e.Name()))
			}
		}
		allRoutes, manifestErr = manifest.Load(dirs...)
	})
	if manifestErr != nil {
		t.Fatal(manifestErr)
	}
	return coreManifest, allRoutes
}

// okEndpoints answers 200 {"data": {"route": name}} on every route of m.
func okEndpoints(m *manifest.Manifest) map[string]endpoint.Endpoint {
	eps := map[string]endpoint.Endpoint{}
	for _, rt := range m.Routes() {
		name := rt.Name
		eps[name] = endpoint.Func(func(context.Context, *endpoint.Input) endpoint.Result {
			return endpoint.Data(200, map[string]any{"route": name})
		})
	}
	return eps
}

func authConfig() config.Auth {
	a := config.Defaults()
	a.Issuer = contracttest.Issuer
	return a
}

var (
	codecOnce sync.Once
	codec     *token.Codec
	codecClk  = clock.NewFrozen(now)
)

// issue mints and parses an access token with the given extra claims.
func issue(t testing.TB, sub string, extra map[string]any) *token.Token {
	t.Helper()
	codecOnce.Do(func() {
		priv, pub := contracttest.TestRSAKeyPEM()
		var err error
		codec, err = token.New(token.Config{PublicKey: pub, PrivateKey: priv, Issuer: contracttest.Issuer, TTL: time.Hour, Clock: codecClk})
		if err != nil {
			panic(err)
		}
	})
	claims := token.Claims{}.With("sub", sub).With("jti", "jti-"+sub)
	for _, k := range slices.Sorted(maps.Keys(extra)) {
		claims = claims.With(k, extra[k])
	}
	raw, err := codec.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := codec.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type stubTickets struct{}

func (stubTickets) Authenticate(_ context.Context, ticket string) (string, error) {
	if ticket == "good-ticket" {
		return "user-1", nil
	}
	return "", errors.New("bad ticket")
}

type stubStepUp struct {
	has bool
	err error
}

func (s stubStepUp) HasConfirmedFactor(context.Context, string) (bool, error) { return s.has, s.err }

type stubDenylist struct {
	revoked bool
	err     error
}

func (s stubDenylist) Revoked(context.Context, string, time.Time) (bool, error) {
	return s.revoked, s.err
}

type grants []string

func (g grants) Allows(permissions ...string) bool {
	for _, p := range permissions {
		if !slices.Contains(g, p) {
			return false
		}
	}
	return true
}

type stubGate struct {
	grants grants
	err    error
}

func (s stubGate) Authority(context.Context, *token.Token) (Authority, error) {
	return s.grants, s.err
}

type resolverFunc func(r *http.Request) (*token.Token, error)

func (f resolverFunc) Resolve(r *http.Request) (*token.Token, error) { return f(r) }

// options returns working Options over m with every service stubbed.
func options(t testing.TB, m *manifest.Manifest) Options {
	t.Helper()
	issue(t, "warm-up", nil)
	return Options{
		Manifest:   m,
		Endpoints:  okEndpoints(m),
		Auth:       authConfig(),
		Tokens:     codec,
		MFATickets: stubTickets{},
		StepUp:     stubStepUp{},
		Denylist:   stubDenylist{},
		Gate:       stubGate{},
		Clock:      clock.NewFrozen(now),
		Logger:     slog.New(slog.DiscardHandler),
	}
}

func newPipeline(t testing.TB, o Options) *Pipeline {
	t.Helper()
	p, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// counting records the requests that reach the end of a middleware.
type counting struct {
	calls int
	last  *http.Request
}

func (c *counting) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.calls++
	c.last = r
	w.WriteHeader(http.StatusOK)
}

// routed is a request with the manifest route of method and path in its context.
func routed(t testing.TB, m *manifest.Manifest, method, path string) *http.Request {
	t.Helper()
	rt, ok := m.Find(method, path)
	if !ok {
		t.Fatalf("%s %s is not in the manifest", method, path)
	}
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = "203.0.113.7:1234"
	return r.WithContext(endpoint.WithRoute(r.Context(), rt))
}

func withToken(r *http.Request, tok *token.Token) *http.Request {
	return r.WithContext(endpoint.WithToken(r.Context(), tok))
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
