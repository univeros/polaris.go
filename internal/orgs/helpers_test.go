package orgs

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/internal/session"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
)

// *session.Service is the production Sessions.
var _ Sessions = (*session.Service)(nil)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
)

const appKey = "0123456789abcdef0123456789abcdef"

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// backends runs fn on every storetest backend (memstore, SQLite, PostgreSQL / MySQL when configured),
// each a fresh database holding core's schema and the seeded catalog.
func backends(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	storetest.Each(t, func(t *testing.T, db store.Adapter) { fn(t, newFixture(t, db)) })
}

type fixture struct {
	db       store.Adapter
	r        *repository.Repos
	svc      *Service
	clock    *clock.Frozen
	pepper   *security.Pepper
	sessions *sessionsRecorder
	events   *eventRecorder
}

func newFixture(t *testing.T, db store.Adapter) *fixture {
	t.Helper()
	must(t, authz.Seed(ctx, db, authz.NewCatalog(), clock.NewFrozen(t0)))
	pepper, err := security.NewPepper(appKey)
	must(t, err)
	f := &fixture{
		db: db, r: repository.New(db), clock: clock.NewFrozen(t0), pepper: pepper,
		sessions: &sessionsRecorder{}, events: &eventRecorder{},
	}
	bus := &event.Bus{}
	bus.Subscribe(f.events.record)
	f.svc, err = New(Config{DB: db, Sessions: f.sessions, Pepper: pepper, Clock: f.clock, Events: bus})
	must(t, err)
	return f
}

// user inserts a verified user and returns its id.
func (f *fixture) user(t *testing.T, email string) string {
	t.Helper()
	u := model.User{ID: repository.NewID(), Email: email, DisplayName: &email, CreatedAt: t0, UpdatedAt: t0}
	must(t, f.r.Users.Insert(ctx, u))
	return u.ID
}

// orgOwnedBy creates an organization owned by a new user; it returns the org and owner ids.
func (f *fixture) orgOwnedBy(t *testing.T, email string) (string, string) {
	t.Helper()
	owner := f.user(t, email)
	org, err := f.svc.CreateOrganization(ctx, "Acme "+email, "", owner)
	must(t, err)
	return org.ID, owner
}

// member makes a new user a member of org with status and role slugs; it returns the user id.
func (f *fixture) member(t *testing.T, org, email, status string, slugs ...string) string {
	t.Helper()
	id := f.user(t, email)
	f.join(t, org, id, status, slugs...)
	return id
}

func (f *fixture) join(t *testing.T, org, userID, status string, slugs ...string) {
	t.Helper()
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: org, Status: status, CreatedAt: t0, UpdatedAt: t0}
	must(t, f.r.Memberships.Insert(ctx, m))
	for _, slug := range slugs {
		must(t, f.r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: f.roleID(t, org, slug)}))
	}
}

// superadmin makes userID a platform superadmin through a membership of org.
func (f *fixture) superadmin(t *testing.T, org, userID string) {
	t.Helper()
	role, err := f.r.Roles.ByOrganizationAndSlug(ctx, nil, authz.RoleSuperadmin)
	must(t, err)
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: org, Status: model.MembershipStatusActive, CreatedAt: t0, UpdatedAt: t0}
	must(t, f.r.Memberships.Insert(ctx, m))
	must(t, f.r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}))
}

func (f *fixture) roleID(t *testing.T, org, slug string) string {
	t.Helper()
	role, err := f.r.Roles.ByOrganizationAndSlug(ctx, &org, slug)
	must(t, err)
	return role.ID
}

func (f *fixture) rolesOf(t *testing.T, org, userID string) []string {
	t.Helper()
	m, err := f.r.Memberships.ByUserAndOrganization(ctx, userID, org)
	must(t, err)
	slugs, err := f.svc.roleSlugsOf(ctx, m.ID)
	must(t, err)
	slices.Sort(slugs)
	return slugs
}

func (f *fixture) count(t *testing.T, table string, c store.Criteria) int64 {
	t.Helper()
	n, err := f.db.Count(ctx, table, c)
	must(t, err)
	return n
}

type revocation struct{ userID, organizationID, reason string }

type sessionsRecorder struct {
	mu    sync.Mutex
	calls []revocation
	err   error
}

func (s *sessionsRecorder) RevokeAllForOrganization(_ context.Context, userID, organizationID, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, revocation{userID, organizationID, reason})
	return s.err
}

func (s *sessionsRecorder) revoked() []revocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.calls)
}

type eventRecorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *eventRecorder) record(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func ofType[T event.Event](r *eventRecorder) []T {
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

// wantRefusal fails unless err is a *Error of kind with message ("" for any).
func wantRefusal(t *testing.T, err, kind error, message string) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || !errors.Is(err, kind) {
		t.Fatalf("err = %v; want %v", err, kind)
	}
	if message != "" && e.Message != message {
		t.Fatalf("message = %q; want %q", e.Message, message)
	}
}

// wantForbidden fails unless err is an *authz.ForbiddenError with message.
func wantForbidden(t *testing.T, err error, message string) {
	t.Helper()
	var e *authz.ForbiddenError
	if !errors.As(err, &e) || !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("err = %v; want forbidden", err)
	}
	if e.Message != message {
		t.Fatalf("message = %q; want %q", e.Message, message)
	}
}

func ptr[T any](v T) *T { return &v }
