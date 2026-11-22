package polaris_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

func whoami(w http.ResponseWriter, r *http.Request) {
	who, ok := polaris.PrincipalFrom(r.Context())
	if !ok {
		_, _ = io.WriteString(w, "anonymous")
		return
	}
	_, _ = io.WriteString(w, string(who.Kind))
}

func serveWith(h http.Handler, bearer string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthenticateAndRequire(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t)
	ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	ok(t, err)
	tokens, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID})
	ok(t, err)
	access := tokens.AccessToken
	h := http.HandlerFunc(whoami)

	for name, c := range map[string]struct {
		h      http.Handler
		bearer string
		code   int
		body   string
	}{
		"Authenticate, anonymous":        {srv.Authenticate(h), "", 200, "anonymous"},
		"Authenticate, signed in":        {srv.Authenticate(h), access, 200, "user"},
		"Authenticate, invalid token":    {srv.Authenticate(h), "forged", 401, ""},
		"Require(), anonymous":           {srv.Require()(h), "", 401, ""},
		"Require(), signed in":           {srv.Require()(h), access, 200, "user"},
		"Require(perm), not held":        {srv.Require("members.update")(h), access, 403, ""},
		"Authenticate then Require":      {srv.Authenticate(srv.Require()(h)), access, 200, "user"},
		"Authenticate then Require anon": {srv.Authenticate(srv.Require()(h)), "", 401, ""},
	} {
		if w := serveWith(c.h, c.bearer); w.Code != c.code || c.body != "" && w.Body.String() != c.body {
			t.Errorf("%s: %d %q", name, w.Code, w.Body)
		}
	}
}

func TestRequireKindAndOrganization(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	as := func(mw func(http.Handler) http.Handler, tok *token.Token) int {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		if tok != nil {
			r = r.WithContext(endpoint.WithToken(r.Context(), tok))
		}
		w := httptest.NewRecorder()
		mw(h).ServeHTTP(w, r)
		return w.Code
	}
	user := token.NewPrincipal(map[string]any{"sub": "ada"})
	member := token.NewPrincipal(map[string]any{"sub": "ada", "org": "org-1"})
	key := token.NewPrincipal(map[string]any{"sub": "ada", "org": "org-1", "api_key": "k1"}).Delegate(nil)
	for name, c := range map[string]struct {
		mw   func(http.Handler) http.Handler
		tok  *token.Token
		code int
	}{
		"kind, no principal":    {polaris.RequireKind(polaris.KindUser), nil, 401},
		"kind, a user":          {polaris.RequireKind(polaris.KindUser), user, 200},
		"kind, an API key":      {polaris.RequireKind(polaris.KindUser, polaris.KindAgent), key, 403},
		"kind, API key allowed": {polaris.RequireKind(polaris.KindAPIKey), key, 200},
		"kind, none allowed":    {polaris.RequireKind(), user, 403},
		"org, no principal":     {polaris.RequireOrganization, nil, 401},
		"org, none active":      {polaris.RequireOrganization, user, 403},
		"org, active":           {polaris.RequireOrganization, member, 200},
		"org, an org's API key": {polaris.RequireOrganization, key, 200},
	} {
		if got := as(c.mw, c.tok); got != c.code {
			t.Errorf("%s: %d, want %d", name, got, c.code)
		}
	}
}
