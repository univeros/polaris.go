package apikeys_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/apikeys"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
)

var now = time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)

type env struct {
	p    *polaris.Polaris
	keys *apikeys.Keys
	clk  *clock.Frozen
	db   *memstore.Store
	user model.User
}

func boot(t *testing.T, cfg apikeys.Config, withAudit bool) env {
	t.Helper()
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	clk := clock.NewFrozen(now)
	models := append(schema.Core(), apikeys.Models()...)
	plugins := []polaris.Plugin{apikeys.New(cfg)}
	if withAudit {
		models = append(models, audit.Models()...)
		plugins = append([]polaris.Plugin{audit.New(audit.Config{})}, plugins...)
	}
	db := memstore.New(models...)
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Clock: clk, Plugins: plugins,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified := now
	user := model.User{ID: repository.NewID(), Email: "ada@example.com", EmailVerifiedAt: &verified, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := p.Graph().Repos.Users.Insert(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return env{p: p, keys: apikeys.Of(p.Graph()).Keys(), clk: clk, db: db, user: user}
}

func (e env) create(t *testing.T, cp apikeys.CreateParams) apikeys.Issued {
	t.Helper()
	if cp.OwnerType == "" {
		cp.OwnerType, cp.OwnerID = apikeys.OwnerUser, e.user.ID
	}
	cp.CreatedBy = e.user.ID
	issued, err := e.keys.Create(context.Background(), cp)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func refused(t *testing.T, err error, want error, msg string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", msg, err, want)
	}
}

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	e := boot(t, apikeys.Config{}, true)
	g := e.p.Graph()
	if !slices.ContainsFunc(g.Schema, func(m schema.Model) bool { return m.Table == apikeys.TableKeys }) {
		t.Fatal("no table")
	}
	var routes []string
	for _, r := range g.Manifest.Routes() {
		if r.Plugin == apikeys.ID {
			routes = append(routes, r.Method+" "+r.Path)
		}
	}
	slices.Sort(routes)
	want := []string{"DELETE /api-keys/{id}", "GET /api-keys", "GET /api-keys/{id}", "PATCH /api-keys/{id}", "POST /api-keys", "POST /api-keys/verify", "POST /api-keys/{id}/rotate"}
	if !slices.Equal(routes, want) {
		t.Fatalf("routes %v", routes)
	}
	if !audit.Of(g).Catalog().Has(apikeys.AuditCreated) {
		t.Fatal("the names did not join the audit catalog")
	}
}

func TestTheSettingsAreValidated(t *testing.T) {
	for _, cfg := range []apikeys.Config{{Environment: "staging"}, {MaxPerOwner: -1}} {
		private, public := contracttest.TestRSAKeyPEM()
		auth := config.Defaults()
		auth.Issuer = "https://issuer.test"
		_, err := polaris.New(polaris.Config{
			Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
			Auth:    auth, DB: memstore.New(), Plugins: []polaris.Plugin{apikeys.New(cfg)},
		})
		if err == nil || !strings.Contains(err.Error(), "Config.") {
			t.Errorf("%+v: %v", cfg, err)
		}
	}
}

func TestTheAuditPluginIsOptional(t *testing.T) {
	e := boot(t, apikeys.Config{}, false)
	if audit.Of(e.p.Graph()) != nil || e.create(t, apikeys.CreateParams{Name: "x"}).Secret == "" {
		t.Fatal("keys work without the audit plugin")
	}
}

func TestAKeyIsMintedOnceAuthenticatedWhileLiveAndBoundedByTheOwner(t *testing.T) {
	ctx := context.Background()
	e := boot(t, apikeys.Config{}, true)
	issued := e.create(t, apikeys.CreateParams{Name: "  CI  ", Permissions: []string{"org.read", "org.read"}, Held: []string{"org.read", "members.read"},
		RateLimit: &apikeys.RateLimit{Window: 60, Max: 5}, Metadata: map[string]any{"team": "infra"}})
	k := issued.Key
	if !strings.HasPrefix(issued.Secret, "pk_live_") || k.Name != "CI" || k.Hint != issued.Secret[len(issued.Secret)-4:] || k.KeyHash == issued.Secret ||
		*k.RateLimit != (apikeys.RateLimit{Window: 60, Max: 5}) || k.Metadata["team"] != "infra" || !slices.Equal(k.Permissions, []string{"org.read"}) {
		t.Fatalf("issued %+v", k)
	}
	if strings.Contains(issued.String(), issued.Secret) || strings.Contains(issued.GoString(), issued.Secret) {
		t.Fatal("the secret leaks through fmt")
	}
	got, ok, err := e.keys.Authenticate(ctx, issued.Secret)
	if err != nil || !ok || got.ID != k.ID || !got.LastUsedAt.Equal(now) {
		t.Fatalf("authenticated %+v %v", got, err)
	}
	for _, s := range []string{"pk_live_" + strings.Repeat("x", 43), "not a key", "pk_" + strings.Repeat("x", 80)} {
		if _, ok, _ := e.keys.Authenticate(ctx, s); ok {
			t.Errorf("%q authenticated", s)
		}
	}
	base := apikeys.CreateParams{OwnerType: apikeys.OwnerUser, OwnerID: e.user.ID, CreatedBy: e.user.ID, Name: "x"}
	with := func(f func(*apikeys.CreateParams)) error {
		p := base
		f(&p)
		_, err := e.keys.Create(ctx, p)
		return err
	}
	past := now
	refused(t, with(func(p *apikeys.CreateParams) {
		p.Permissions, p.Held = []string{"members.invite"}, []string{"org.read"}
	}), apikeys.ErrPermissionNotHeld, "not held")
	refused(t, with(func(p *apikeys.CreateParams) {
		p.Permissions, p.Held = []string{"not.a.permission"}, []string{"not.a.permission"}
	}), apikeys.ErrInvalidInput, "unknown")
	refused(t, with(func(p *apikeys.CreateParams) { p.Name = strings.Repeat("n", 81) }), apikeys.ErrInvalidInput, "long name")
	refused(t, with(func(p *apikeys.CreateParams) { p.Environment = "staging" }), apikeys.ErrInvalidInput, "environment")
	refused(t, with(func(p *apikeys.CreateParams) { p.RateLimit = &apikeys.RateLimit{Window: 60} }), apikeys.ErrInvalidInput, "rate limit")
	refused(t, with(func(p *apikeys.CreateParams) { p.ExpiresAt = &past }), apikeys.ErrInvalidInput, "expiry in the past")
	refused(t, with(func(p *apikeys.CreateParams) { p.Metadata = map[string]any{"big": strings.Repeat("x", 5000)} }), apikeys.ErrInvalidInput, "metadata size")
	var ke *apikeys.Error
	if err := with(func(p *apikeys.CreateParams) { p.Name = "" }); !errors.As(err, &ke) || ke.Detail != "name is required and at most 80 characters." || !strings.Contains(ke.Error(), "invalid_input") {
		t.Fatalf("detail %v", err)
	}
}

func TestExpiryRotationGraceAndRevocationEndAKey(t *testing.T) {
	ctx := context.Background()
	e := boot(t, apikeys.Config{RotationGrace: 10 * time.Minute}, true)
	hour := now.Add(time.Hour)
	expiring := e.create(t, apikeys.CreateParams{Name: "expiring", ExpiresAt: &hour})
	rotating := e.create(t, apikeys.CreateParams{Name: "rotating"})
	before, successor, err := e.keys.Rotate(ctx, rotating.Key)
	if err != nil || successor.Key.RotatedFromID != rotating.Key.ID || before.Status(now) != apikeys.StatusRotated {
		t.Fatalf("rotate %+v %v", successor.Key, err)
	}
	if _, _, err := e.keys.Rotate(ctx, rotating.Key); !errors.Is(err, apikeys.ErrForbidden) {
		t.Fatalf("a concurrent second rotation: %v", err)
	}
	live := func(secret string) bool {
		_, ok, err := e.keys.Authenticate(ctx, secret)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !live(rotating.Secret) || !live(successor.Secret) {
		t.Fatal("the predecessor answers during the grace")
	}
	e.clk.Advance(10 * time.Minute)
	if live(rotating.Secret) || !live(successor.Secret) || !live(expiring.Secret) {
		t.Fatal("the grace ended")
	}
	e.clk.Advance(time.Hour)
	if live(expiring.Secret) {
		t.Fatal("expired")
	}
	if k, _, _ := e.keys.Find(ctx, expiring.Key.ID); k.Status(e.clk.Now()) != apikeys.StatusExpired {
		t.Fatal("status expired")
	}
	revoked, err := e.keys.Revoke(ctx, successor.Key)
	if err != nil || live(successor.Secret) || revoked.Status(e.clk.Now()) != apikeys.StatusRevoked {
		t.Fatal("revoked")
	}
	keys, _ := e.keys.ForOwner(ctx, apikeys.OwnerUser, e.user.ID)
	for _, k := range keys {
		if k.RevokedAt != nil {
			t.Fatal("revoked keys leave the list")
		}
	}
	name := "renamed"
	k, changes, err := e.keys.Update(ctx, expiring.Key, apikeys.UpdateParams{Held: []string{"org.read"}, Name: &name, Permissions: []string{"org.read"}, ClearRateLimit: true, ClearExpiry: true, Metadata: map[string]any{"k": "v"}})
	if err != nil || !slices.Equal(changes, []string{"name", "permissions", "rate_limit", "expires_at", "metadata"}) || k.Name != "renamed" {
		t.Fatalf("update %v %v", changes, err)
	}
	if _, changes, _ := e.keys.Update(ctx, k, apikeys.UpdateParams{}); len(changes) != 0 {
		t.Fatal("nothing changed")
	}
	if !live(expiring.Secret) {
		t.Fatal("the expiry was cleared")
	}
	limit := apikeys.RateLimit{Window: 30, Max: 3}
	later := e.clk.Now().Add(time.Hour)
	if k, _, err = e.keys.Update(ctx, k, apikeys.UpdateParams{RateLimit: &limit, ExpiresAt: &later}); err != nil || k.RateLimit.Max != 3 {
		t.Fatal(err)
	}
	if found, _, _ := e.keys.Find(ctx, k.ID); found.RateLimit == nil || *found.RateLimit != limit || found.ExpiresAt == nil {
		t.Fatalf("stored %+v", found)
	}
	for _, bad := range []apikeys.UpdateParams{{Name: new(string)}, {Permissions: []string{"x"}}, {RateLimit: &apikeys.RateLimit{}}, {ExpiresAt: &now}, {Metadata: map[string]any{"x": strings.Repeat("y", 5000)}}} {
		if _, _, err := e.keys.Update(ctx, k, bad); !errors.Is(err, apikeys.ErrInvalidInput) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestAnOwnerIsBoundedInKeysAndAnErasedUserLeavesNone(t *testing.T) {
	ctx := context.Background()
	e := boot(t, apikeys.Config{MaxPerOwner: 2}, true)
	e.create(t, apikeys.CreateParams{Name: "one"})
	e.create(t, apikeys.CreateParams{Name: "two"})
	_, err := e.keys.Create(ctx, apikeys.CreateParams{OwnerType: apikeys.OwnerUser, OwnerID: e.user.ID, CreatedBy: e.user.ID, Name: "three"})
	refused(t, err, apikeys.ErrTooMany, "too many")
	e.create(t, apikeys.CreateParams{OwnerType: apikeys.OwnerOrganization, OwnerID: "org-1", OrganizationID: "org-1", Name: "org key"})
	events := e.p.Graph().Events
	events.Dispatch(ctx, event.MemberRemoved{OrganizationID: "org-1", UserID: e.user.ID, ActorUserID: "admin-1"})
	if k, _ := e.keys.ForOwner(ctx, apikeys.OwnerOrganization, "org-1"); len(k) != 0 {
		t.Fatal("a member who leaves takes the organization keys they act for")
	}
	if k, _ := e.keys.ForOwner(ctx, apikeys.OwnerUser, e.user.ID); len(k) != 2 {
		t.Fatal("their own keys stay")
	}
	e.create(t, apikeys.CreateParams{OwnerType: apikeys.OwnerOrganization, OwnerID: "org-1", OrganizationID: "org-1", Name: "again"})
	events.Dispatch(ctx, event.UserDeleted{UserID: e.user.ID, ActorUserID: "admin-1"})
	user, _ := e.keys.ForOwner(ctx, apikeys.OwnerUser, e.user.ID)
	org, _ := e.keys.ForOwner(ctx, apikeys.OwnerOrganization, "org-1")
	if len(user)+len(org) != 0 {
		t.Fatal("an erased user leaves no key")
	}
	e.create(t, apikeys.CreateParams{OwnerType: apikeys.OwnerOrganization, OwnerID: "org-2", OrganizationID: "org-2", Name: "org two"})
	events.Dispatch(ctx, event.OrganizationDeleted{OrganizationID: "org-2"})
	if k, _ := e.keys.ForOwner(ctx, apikeys.OwnerOrganization, "org-2"); len(k) != 0 {
		t.Fatal("an erased organization leaves no key")
	}
}

func TestTheResolverAnswersTheOwnersPrincipalWithTheDelegatedPermissionsAndRefusesTheRest(t *testing.T) {
	ctx := context.Background()
	e := boot(t, apikeys.Config{}, true)
	issued := e.create(t, apikeys.CreateParams{OrganizationID: "org-1", Name: "CI", Permissions: []string{"org.read"}, Held: []string{"org.read"}, RateLimit: &apikeys.RateLimit{Window: 60, Max: 5}})
	var seen []string
	h := e.p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := polaris.Principal(r.Context())
		perms, delegated := tok.Delegation()
		amr, _ := tok.Claim("amr").([]any)
		if !delegated || !slices.Equal(perms, []string{"org.read"}) || tok.Organization() != "org-1" || len(amr) != 1 || amr[0] != apikeys.AMR || tok.IssuedAt().IsZero() {
			t.Errorf("principal %v %v", tok.Claims(), perms)
		}
		seen = append(seen, tok.Subject())
		w.WriteHeader(http.StatusNoContent)
	}))
	serve := func(header, value string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		if header != "" {
			r.Header.Set(header, value)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := serve("Authorization", "Bearer "+issued.Secret); w.Code != 204 || w.Header().Get("X-RateLimit-Limit") != "5" {
		t.Fatalf("bearer %d %v", w.Code, w.Header())
	}
	if w := serve(apikeys.Header, issued.Secret); w.Code != 204 || !slices.Equal(seen, []string{e.user.ID, e.user.ID}) {
		t.Fatalf("x-api-key %d %v", w.Code, seen)
	}
	if apikeys.Presented(httptest.NewRequest(http.MethodGet, "/", nil)) != "" {
		t.Fatal("nothing presented")
	}
	for _, c := range [][2]string{{"Authorization", "Bearer eyJ.a.jwt"}, {apikeys.Header, "pk_live_unknown"}, {"", ""}} {
		if w := serve(c[0], c[1]); w.Code != 401 {
			t.Errorf("%v: %d", c, w.Code)
		}
	}
	if _, err := e.db.Update(ctx, "auth_users", store.Criteria{"id": e.user.ID}, store.Data{"status": model.UserStatusDisabled}); err != nil {
		t.Fatal(err)
	}
	if w := serve(apikeys.Header, issued.Secret); w.Code != 401 {
		t.Fatalf("a disabled subject: %d", w.Code)
	}
}

// A host route behind polaris.Protect accepts an API key: the handler sees the owner as the
// principal, delegated the key's permissions, and the gate intersects them with the owner's.
func TestProtectAcceptsAnAPIKey(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), apikeys.New(apikeys.Config{})))
	c := contracttest.NewClient(t, srv.Handler(), nil)
	f := &flow{t: t, srv: srv, c: c}
	userID, session := f.login("ada@example.com")
	orgID, session := f.organization(session, "Acme")
	secret, _ := data(t, c.Post("/api-keys", map[string]any{"name": "host", "permissions": []string{"org.read"}, "rate_limit": map[string]any{"window": 60, "max": 10}}, contracttest.Bearer(session)))["key"].(string)

	host := func(perms ...string) *contracttest.Client {
		return contracttest.NewClient(t, srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := polaris.Principal(r.Context())
			delegated, ok := tok.Delegation()
			if tok.Subject() != userID || tok.Organization() != orgID || !ok || !slices.Equal(delegated, []string{"org.read"}) {
				t.Errorf("principal %s %s %v", tok.Subject(), tok.Organization(), delegated)
			}
			if a, ok := polaris.Authority(r.Context()); len(perms) > 0 && (!ok || !a.Allows(perms...)) {
				t.Error("no authority")
			}
			w.WriteHeader(http.StatusOK)
		}), perms...), nil)
	}
	if resp := host().Get("/invoices", contracttest.Bearer(secret)); resp.StatusCode != 200 || resp.Header.Get("X-RateLimit-Limit") != "10" {
		t.Fatalf("no permission: %d %v", resp.StatusCode, resp.Header)
	}
	status(t, host("org.read").Get("/invoices", contracttest.Header("x-api-key", secret)), 200)
	status(t, host("members.read").Get("/invoices", contracttest.Bearer(secret)), 403, "held by the owner, not delegated")
	status(t, host().Get("/invoices", contracttest.Bearer("pk_live_unknown")), 401)
}
