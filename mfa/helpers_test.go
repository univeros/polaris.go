package mfa

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
	"github.com/univeros/polaris-go/token"
)

const testAppKey = "app-key-for-tests-0123456789abcdef"

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

// recorder is an event.Dispatcher that keeps every event (RecordingEventDispatcher).
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

// stubTOTP matches every non-empty code at a fixed step, or nothing when ok is false.
type stubTOTP struct {
	step int64
	ok   bool
}

func (stubTOTP) GenerateSecret() string { return "JBSWY3DPEHPK3PXP" }
func (stubTOTP) ProvisioningURI(secret, account string) (string, error) {
	return "otpauth://totp/x?secret=" + secret, nil
}
func (s stubTOTP) Match(_, code string) (int64, bool, error) { return s.step, s.ok && code != "", nil }

// failingEncrypter cannot open anything (corruption, key rotation).
type failingEncrypter struct{ security.Encrypter }

func (failingEncrypter) Decrypt(string) (string, error) { return "", security.ErrDecrypt }

// fakeSessions records what the gate asks the session service for.
type fakeSessions struct {
	mu        sync.Mutex
	issued    []token.SessionPrincipal
	steppedUp [][3]string
	failStep  error
}

func (f *fakeSessions) Issue(_ context.Context, p token.SessionPrincipal, _ token.ClientContext) (token.IssuedTokens, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issued = append(f.issued, p)
	return token.IssuedTokens{AccessToken: "access-" + p.UserID, RefreshToken: "refresh", SessionID: "session-1"}, nil
}

func (f *fakeSessions) StepUp(_ context.Context, userID, organizationID, sessionID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStep != nil {
		return "", f.failStep
	}
	f.steppedUp = append(f.steppedUp, [3]string{userID, organizationID, sessionID})
	return "stepped-up-" + sessionID, nil
}

type fakeTickets struct{}

func (fakeTickets) Issue(userID string) (string, error) { return "ticket-" + userID, nil }

// fakePrincipals resolves an email-verified member with fixed roles (StubSessionPrincipalResolver).
type fakePrincipals struct{}

func (fakePrincipals) Resolve(_ context.Context, userID, organizationID string) (token.SessionPrincipal, error) {
	return token.SessionPrincipal{UserID: userID, OrganizationID: organizationID, Roles: []string{"member"}, EmailVerified: true}, nil
}

// harness is one Service over db with recording ports, frozen at a wall time.
type harness struct {
	db       store.Adapter
	repos    *repository.Repos
	clock    *clock.Frozen
	pepper   *security.Pepper
	events   *recorder
	sms      *notifytest.SMSSender
	mail     *notifytest.Mailer
	cache    cache.Cache
	sessions *fakeSessions
	cfg      Config
}

func newHarness(t *testing.T, db store.Adapter, wall string) *harness {
	t.Helper()
	pepper, err := security.NewPepper(testAppKey)
	must(t, err)
	enc, err := security.NewXChaCha20Poly1305(testAppKey)
	must(t, err)
	clk := clock.NewFrozen(at(wall))
	h := &harness{
		db: db, repos: repository.New(db), clock: clk, pepper: pepper, events: &recorder{},
		sms: &notifytest.SMSSender{}, mail: &notifytest.Mailer{}, cache: cache.NewMemory(clk), sessions: &fakeSessions{},
	}
	h.cfg = Config{
		DB: db, Pepper: pepper, Encrypter: enc, TOTP: stubTOTP{step: 5000, ok: true}, SMS: h.sms, Mailer: h.mail,
		Cache: h.cache, Sessions: h.sessions, Tickets: fakeTickets{}, Principals: fakePrincipals{},
		Auth: config.Defaults(), Clock: clk, Events: h.events,
	}
	return h
}

func (h *harness) service(t *testing.T, mutate ...func(*Config)) *Service {
	t.Helper()
	cfg := h.cfg
	for _, m := range mutate {
		m(&cfg)
	}
	s, err := New(cfg)
	must(t, err)
	return s
}

func (h *harness) insertFactor(t *testing.T, f model.MFAFactor) model.MFAFactor {
	t.Helper()
	if f.ID == "" {
		f.ID = repository.NewID()
	}
	if f.UserID == "" {
		f.UserID = "user-1"
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = h.clock.Now()
		f.UpdatedAt = h.clock.Now()
	}
	must(t, h.repos.MFAFactors.Insert(ctx, f))
	return f
}

func (h *harness) factor(t *testing.T, id string) model.MFAFactor {
	t.Helper()
	f, err := h.repos.MFAFactors.Get(ctx, id)
	must(t, err)
	return f
}

func smsFactor() model.MFAFactor {
	return model.MFAFactor{ID: "factor-1", UserID: "user-1", Type: model.FactorSMS, PhoneE164: ptr("+14155550101")}
}

func emailFactor() model.MFAFactor {
	return model.MFAFactor{ID: "factor-2", UserID: "user-1", Type: model.FactorEmail, Email: ptr("ada@example.com")}
}

func memDB() store.Adapter { return memstore.New(schema.Core()...) }

// staleAfterRead runs mutate once, right after the service's first multi-row read: another
// request changes the rows this one has just loaded.
func staleAfterRead(db store.Adapter, mutate func()) func(*Config) {
	return func(c *Config) { c.DB = &staleDB{Adapter: db, mutate: mutate} }
}

type staleDB struct {
	store.Adapter
	once   sync.Once
	mutate func()
}

func (s *staleDB) FindMany(ctx context.Context, table string, c store.Criteria, q store.Query) ([]store.Row, error) {
	rows, err := s.Adapter.FindMany(ctx, table, c, q)
	s.once.Do(s.mutate)
	return rows, err
}
