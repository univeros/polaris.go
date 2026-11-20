package identity

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
	"github.com/univeros/polaris.go/token"
)

var ctx = context.Background()

const (
	email       = "ada@example.com"
	password    = "correct horse battery staple"
	newPassword = "an entirely different passphrase"
	appKey      = "test-application-key-0123456789ab"
)

var start = time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)

var client = token.ClientContext{IP: "203.0.113.7", UserAgent: "Browser/1.0 (Functional)"}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func isErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

// backends runs fn on every storetest backend (memstore, SQLite, PostgreSQL / MySQL when configured),
// each a fresh database holding core's schema.
func backends(t *testing.T, fn func(t *testing.T, h *harness)) {
	t.Helper()
	storetest.Each(t, func(t *testing.T, db store.Adapter) { fn(t, newHarness(t, db)) })
}

// countingHasher is a cheap Argon2id that counts its calls.
type countingHasher struct {
	security.Argon2id
	hashes, verifies atomic.Int32
}

func (c *countingHasher) Hash(plain string) (string, error) {
	c.hashes.Add(1)
	return c.Argon2id.Hash(plain)
}

func (c *countingHasher) Verify(plain, hash string) bool {
	c.verifies.Add(1)
	return c.Argon2id.Verify(plain, hash)
}

// recorder records dispatched events.
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

type fakeIssuer struct{}

func (fakeIssuer) Issue(token.Claims) (string, error) { return "jwt-" + repository.NewID(), nil }

// gate reads confirmed factors straight from the database.
type gate struct{ repos *repository.Repos }

func (g gate) ConfirmedFactors(ctx context.Context, userID string) ([]model.MFAFactor, error) {
	all, err := g.repos.MFAFactors.ListByUser(ctx, userID)
	var out []model.MFAFactor
	for _, f := range all {
		if f.ConfirmedAt != nil {
			out = append(out, f)
		}
	}
	return out, err
}

type tickets struct{}

func (tickets) Issue(userID string) (string, error) { return "mfa-ticket-" + userID, nil }

// authorities grants fixed authority per actor; everyone else holds nothing.
type authorities map[string]authz.Authority

func (a authorities) Resolve(_ context.Context, userID, _ string) (authz.Authority, error) {
	return a[userID], nil
}

// harness is one service world over a database.
type harness struct {
	db       store.Adapter
	repos    *repository.Repos
	clock    *clock.Frozen
	events   *recorder
	hasher   *countingHasher
	pepper   *security.Pepper
	sessions *session.Service
	admins   authorities
	auth     config.Auth
	svc      *Service
}

func newHarness(t *testing.T, db store.Adapter) *harness {
	t.Helper()
	auth := config.Defaults()
	auth.Issuer = "https://auth.polaris.test"
	pepper, err := security.NewPepper(appKey)
	must(t, err)
	clk := clock.NewFrozen(start)
	h := &harness{
		db: db, repos: repository.New(db), clock: clk, events: &recorder{}, pepper: pepper, auth: auth,
		hasher: &countingHasher{Argon2id: security.Argon2id{Memory: 8, Time: 1, Threads: 1}}, admins: authorities{},
	}
	h.sessions, err = session.New(session.Config{
		DB: db, Pepper: pepper, Access: fakeIssuer{}, Principals: session.UserPrincipals{Users: h.repos.Users},
		Denylist: session.NewDenylist(cache.NewMemory(clk), clk, auth.AccessToken.TTL), Auth: auth, Clock: clk, Events: h.events,
	})
	must(t, err)
	h.svc = h.service(t, auth)
	return h
}

func (h *harness) service(t *testing.T, auth config.Auth) *Service {
	t.Helper()
	s, err := New(Config{
		DB: h.db, Hasher: h.hasher, Pepper: h.pepper, Sessions: h.sessions, MFA: gate{h.repos}, Tickets: tickets{},
		Authority: h.admins, Auth: auth, Clock: h.clock, Events: h.events,
	})
	must(t, err)
	return s
}

func (h *harness) user(t *testing.T, address string) model.User {
	t.Helper()
	u, err := h.repos.Users.ByEmail(ctx, address)
	must(t, err)
	return u
}

func (h *harness) set(t *testing.T, address string, change func(*model.User)) {
	t.Helper()
	before := h.user(t, address)
	after := before
	change(&after)
	must(t, h.repos.Users.Update(ctx, before, after))
}

// register creates address and returns its verification token.
func (h *harness) register(t *testing.T, address string) string {
	t.Helper()
	must(t, h.svc.Register(ctx, address, password, "", client))
	regs := ofType[event.UserRegistered](h.events)
	return regs[len(regs)-1].VerificationToken
}

// registerAndVerify creates a verified account and returns its id.
func (h *harness) registerAndVerify(t *testing.T, address string) string {
	t.Helper()
	must(t, h.svc.VerifyEmail(ctx, h.register(t, address)))
	return h.user(t, address).ID
}

func (h *harness) login(t *testing.T, address string) token.IssuedTokens {
	t.Helper()
	r, err := h.svc.Login(ctx, address, password, client)
	must(t, err)
	return r.Tokens
}

// refreshes reports whether a refresh token still exchanges.
func (h *harness) refreshes(t *testing.T, refresh string) bool {
	t.Helper()
	_, err := h.sessions.Refresh(ctx, refresh, client)
	if err != nil && !errors.Is(err, session.ErrInvalidGrant) {
		t.Fatal(err)
	}
	return err == nil
}

func (h *harness) requestReset(t *testing.T, address string) string {
	t.Helper()
	must(t, h.svc.ForgotPassword(ctx, address, client))
	resets := ofType[event.PasswordResetRequested](h.events)
	return resets[len(resets)-1].ResetToken
}
