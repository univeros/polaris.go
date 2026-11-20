package session

import (
	"context"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
	"github.com/univeros/polaris-go/token"
)

var ctx = context.Background()

func at(s string) time.Time {
	t, err := time.Parse(time.DateTime, s)
	if err != nil {
		panic(err)
	}
	return t
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// backends runs fn on memstore and on SQLite, both holding core's schema.
func backends(t *testing.T, fn func(t *testing.T, db store.Adapter)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { fn(t, memstore.New(schema.Core()...)) })
	t.Run("sqlite", func(t *testing.T) { fn(t, openSQLite(t)) })
}

func openSQLite(t *testing.T) *sqlstore.Store {
	t.Helper()
	s, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "p.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)")
	must(t, err)
	t.Cleanup(func() { _ = s.DB().Close() })
	must(t, s.CreateSchema(ctx, schema.Core()))
	return s
}

// recordingIssuer records every claim set minted (RecordingTokenGenerator).
type recordingIssuer struct {
	mu     sync.Mutex
	claims []token.Claims
}

func (r *recordingIssuer) Issue(c token.Claims) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claims = append(r.claims, c)
	return "jwt-" + repository.NewID(), nil
}

func (r *recordingIssuer) claim(i int, name string) any {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, _ := r.claims[i].Get(name)
	return v
}

// stubPrincipals returns fixed roles, email verified (StubSessionPrincipalResolver).
type stubPrincipals struct{ roles []string }

func (s stubPrincipals) Resolve(_ context.Context, userID, organizationID string) (token.SessionPrincipal, error) {
	return token.SessionPrincipal{UserID: userID, OrganizationID: organizationID, Roles: s.roles, EmailVerified: true}, nil
}

// recorder records dispatched events (RecordingEventDispatcher).
type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Dispatch(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func ofType[T event.Event](r *recorder) []T {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []T
	for _, e := range r.events {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// harness is one service world: a database, a clock, a recording issuer and events.
type harness struct {
	db     store.Adapter
	repos  *repository.Repos
	clock  *clock.Frozen
	issuer *recordingIssuer
	events *recorder
	cache  *cache.Memory
	auth   config.Auth
}

func newHarness(db store.Adapter, start string) *harness {
	auth := config.Defaults()
	auth.Issuer = "https://auth.polaris.test"
	clk := clock.NewFrozen(at(start))
	return &harness{db: db, repos: repository.New(db), clock: clk, issuer: &recordingIssuer{}, events: &recorder{}, cache: cache.NewMemory(clk), auth: auth}
}

func (h *harness) service(t *testing.T) *Service {
	t.Helper()
	pepper, err := security.NewPepper("test-application-key-0123456789ab")
	must(t, err)
	s, err := New(Config{
		DB: h.db, Pepper: pepper, Access: h.issuer, Principals: stubPrincipals{roles: []string{"member"}},
		Denylist: NewDenylist(h.cache, h.clock, h.auth.AccessToken.TTL), Auth: h.auth, Clock: h.clock, Events: h.events,
	})
	must(t, err)
	return s
}

func (h *harness) family(t *testing.T, id string) []model.RefreshToken {
	t.Helper()
	rows, err := h.repos.RefreshTokens.ListByFamily(ctx, id)
	must(t, err)
	return rows
}

func split(rows []model.RefreshToken) (active, revoked []model.RefreshToken) {
	for _, r := range rows {
		if r.RevokedAt == nil {
			active = append(active, r)
		} else {
			revoked = append(revoked, r)
		}
	}
	return active, revoked
}

func principal() token.SessionPrincipal {
	return token.SessionPrincipal{UserID: "user-1", OrganizationID: "org-1", EmailVerified: true}
}

func strs(v any) []string {
	s, _ := v.([]string)
	return slices.Clone(s)
}
