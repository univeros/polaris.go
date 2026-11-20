package observe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
)

var (
	ctx = context.Background()
	now = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
)

func ptr[T any](v T) *T { return &v }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// auditBackends runs fn with an audit listener writing to memstore and to SQLite; rows returns
// what was written, oldest first.
func auditBackends(t *testing.T, fn func(t *testing.T, listen event.Listener, rows func() []model.AuditLogEntry)) {
	t.Helper()
	run := func(t *testing.T, db store.Adapter) {
		r := repository.New(db)
		rows := func() []model.AuditLogEntry {
			got, err := r.AuditLog.Find(ctx, nil, store.Query{OrderBy: []store.Order{{Column: "id"}}})
			must(t, err)
			return got
		}
		fn(t, AuditLog(r.AuditLog, clock.NewFrozen(now), nil), rows)
	}
	storetest.Each(t, run)
}

func metadata(t *testing.T, e model.AuditLogEntry) map[string]any {
	t.Helper()
	var m map[string]any
	if string(e.Metadata) == "[]" {
		return map[string]any{}
	}
	must(t, json.Unmarshal(e.Metadata, &m))
	return m
}

// wantMeta checks e's metadata is exactly want (PHP's JSON escaping) or, on PostgreSQL and MySQL
// (which store JSON parsed and hand back their own form), an equal JSON value.
func wantMeta(t *testing.T, e model.AuditLogEntry, want string) {
	t.Helper()
	if !sameMeta(t, e.Metadata, want) {
		t.Errorf("%s metadata = %s; want %s", e.Event, e.Metadata, want)
	}
}

func sameMeta(t *testing.T, got json.RawMessage, want string) bool {
	t.Helper()
	if string(got) == want || !storetest.JSONNormalized(store.Dialect(path.Base(t.Name()))) {
		return string(got) == want
	}
	var g, w any
	return json.Unmarshal(got, &g) == nil && json.Unmarshal([]byte(want), &w) == nil && reflect.DeepEqual(g, w)
}

func str(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

// Port of AuditLogListenerTest::testRecordsEventNameActorAndMetadata.
func TestRecordsEventNameActorAndMetadata(t *testing.T) {
	auditBackends(t, func(t *testing.T, listen event.Listener, rows func() []model.AuditLogEntry) {
		listen(ctx, event.UserLoggedIn{UserID: "user-1", SessionID: "session-9", IP: ptr("203.0.113.7"), UserAgent: ptr("Browser/1.0"), AMR: []string{"pwd", "otp"}})
		got := rows()
		if len(got) != 1 {
			t.Fatalf("rows = %d", len(got))
		}
		r := got[0]
		if r.Event != "user.logged_in" || str(r.ActorUserID) != "user-1" || r.OrganizationID != nil ||
			str(r.IP) != "203.0.113.7" || str(r.UserAgent) != "Browser/1.0" || !r.CreatedAt.Equal(now) || r.ID == "" {
			t.Errorf("row = %+v", r)
		}
		wantMeta(t, r, `{"session_id":"session-9","amr":["pwd","otp"]}`)
	})
}

// Port of testRecordsLoginFailureReasonAndLockExpiry, testRecordsSessionRevocationScaleAndReason
// and testRecordsMfaFactorContext.
func TestRecordsIdentityAndMFAContext(t *testing.T) {
	auditBackends(t, func(t *testing.T, listen event.Listener, rows func() []model.AuditLogEntry) {
		until := time.Date(2026, 6, 10, 12, 15, 0, 0, time.UTC)
		listen(ctx, event.UserLoginFailed{UserID: "user-1", IP: ptr("203.0.113.7"), UserAgent: ptr("Browser/1.0"), Reason: event.LoginFailedInvalidCredentials})
		listen(ctx, event.UserLocked{UserID: "user-1", IP: ptr("203.0.113.7"), Until: &until})
		listen(ctx, event.SessionsRevoked{UserID: "user-1", IP: ptr("203.0.113.7"), Count: 3, Reason: "logout"})
		listen(ctx, event.MFAEnrolled{UserID: "user-1", FactorID: "factor-1", Type: ptr("totp")})
		listen(ctx, event.MFAVerifyFailed{UserID: "user-1", FactorID: ptr("factor-1"), Type: ptr("sms")})
		listen(ctx, event.OTPVerifyFailed{UserID: "user-1", FactorID: "factor-1", AttemptsLeft: ptr(4)})
		listen(ctx, event.MFAVerified{UserID: "user-1"})
		listen(ctx, event.UserLocked{UserID: "user-1"})
		listen(ctx, event.OTPVerifyFailed{UserID: "user-1", FactorID: "factor-1"})

		got := rows()
		if len(got) != 9 {
			t.Fatalf("rows = %d", len(got))
		}
		if str(got[0].UserAgent) != "Browser/1.0" || got[1].UserAgent != nil || str(got[1].IP) != "203.0.113.7" {
			t.Errorf("rows = %+v", got[:2])
		}
		for i, want := range []string{
			`{"reason":"invalid_credentials"}`,
			`{"until":"2026-06-10T12:15:00+00:00"}`,
			`{"count":3,"reason":"logout"}`,
			`{"factor_id":"factor-1","type":"totp"}`,
			`{"factor_id":"factor-1","type":"sms"}`,
			`{"factor_id":"factor-1","attempts_left":4}`,
			`{"factor_id":null}`,
			`{"until":null}`,
			`{"factor_id":"factor-1","attempts_left":null}`,
		} {
			wantMeta(t, got[i], want)
		}
	})
}

// Port of testRecordsOrgAndRoleLifecycleEvents, testRecordsOrgContextAndAdminActor and
// testRecordsMembershipManagementEvents.
func TestRecordsOrganizationContextAndActors(t *testing.T) {
	auditBackends(t, func(t *testing.T, listen event.Listener, rows func() []model.AuditLogEntry) {
		listen(ctx, event.OrganizationSwitched{UserID: "user-1", FromOrganizationID: ptr("org-1"), ToOrganizationID: "org-2"})
		listen(ctx, event.OrganizationUpdated{OrganizationID: "org-2", ActorUserID: "admin-1"})
		listen(ctx, event.RoleCreated{OrganizationID: "org-2", RoleID: "role-1", ActorUserID: "admin-1"})
		listen(ctx, event.RoleUpdated{OrganizationID: "org-2", RoleID: "role-1", ActorUserID: "admin-1"})
		listen(ctx, event.RoleDeleted{OrganizationID: "org-2", RoleID: "role-1", ActorUserID: "admin-1"})
		listen(ctx, event.OrganizationDeleted{OrganizationID: "org-1", ActorUserID: "admin-1"})
		listen(ctx, event.UserDisabled{UserID: "target-1", ActorUserID: "admin-1"})
		listen(ctx, event.RefreshReuseDetected{UserID: "user-1", FamilyID: "family-3", IP: ptr("198.51.100.2"), UserAgent: ptr("Stolen/1.0")})
		listen(ctx, event.MemberRolesChanged{OrganizationID: "org-1", UserID: "member-1", RoleSlugs: []string{"admin", "support"}, ActorUserID: "owner-1"})
		listen(ctx, event.MemberStatusChanged{OrganizationID: "org-1", UserID: "member-1", Status: "suspended", ActorUserID: "owner-1"})
		listen(ctx, event.MemberRolesChanged{OrganizationID: "org-1", UserID: "member-1", ActorUserID: "owner-1"})

		got := rows()
		type row struct{ event, actor, org, meta string }
		want := []row{
			{"auth.org_switched", "user-1", "org-2", `{"from_organization_id":"org-1"}`},
			{"org.updated", "admin-1", "org-2", `[]`},
			{"role.created", "admin-1", "org-2", `{"role_id":"role-1"}`},
			{"role.updated", "admin-1", "org-2", `{"role_id":"role-1"}`},
			{"role.deleted", "admin-1", "org-2", `{"role_id":"role-1"}`},
			{"org.deleted", "admin-1", "org-1", `[]`},
			{"user.disabled", "admin-1", "<nil>", `{"user_id":"target-1"}`},
			{"auth.refresh_reuse_detected", "user-1", "<nil>", `{"family_id":"family-3"}`},
			{"member.roles_changed", "owner-1", "org-1", `{"user_id":"member-1","role_slugs":["admin","support"]}`},
			{"member.status_changed", "owner-1", "org-1", `{"user_id":"member-1","status":"suspended"}`},
			{"member.roles_changed", "owner-1", "org-1", `{"user_id":"member-1","role_slugs":[]}`},
		}
		if len(got) != len(want) {
			t.Fatalf("rows = %d", len(got))
		}
		for i, w := range want {
			g := row{got[i].Event, str(got[i].ActorUserID), str(got[i].OrganizationID), string(got[i].Metadata)}
			if g.event != w.event || g.actor != w.actor || g.org != w.org || !sameMeta(t, got[i].Metadata, w.meta) {
				t.Errorf("row %d = %+v; want %+v", i, g, w)
			}
		}
		if str(got[7].IP) != "198.51.100.2" || str(got[7].UserAgent) != "Stolen/1.0" {
			t.Errorf("reuse row = %+v", got[7])
		}
	})
}

// Port of testSecretCarryingEventsNeverLeakTheirTokens.
func TestSecretCarryingEventsNeverLeakTheirTokens(t *testing.T) {
	auditBackends(t, func(t *testing.T, listen event.Listener, rows func() []model.AuditLogEntry) {
		listen(ctx, event.UserRegistered{UserID: "user-1", Email: "new@example.com", VerificationToken: "verification-secret-token"})
		listen(ctx, event.PasswordResetRequested{UserID: "user-1", Email: "new@example.com", ResetToken: "reset-secret-token"})
		listen(ctx, event.MemberInvited{OrganizationID: "org-1", Email: "invitee@example.com", InvitedBy: "inviter-1", InviteToken: "invite-secret-token"})
		got := rows()
		if len(got) != 3 {
			t.Fatalf("rows = %d", len(got))
		}
		for _, r := range got {
			if strings.Contains(string(r.Metadata), "secret-token") {
				t.Errorf("secret leaked into %s metadata", r.Event)
			}
		}
		if m := metadata(t, got[0]); m["email"] != "new@example.com" || len(m) != 1 {
			t.Errorf("metadata = %v", m)
		}
		if str(got[2].ActorUserID) != "inviter-1" || str(got[2].OrganizationID) != "org-1" {
			t.Errorf("row = %+v", got[2])
		}
	})
}

// Every core event the listener maps writes a row; the rest are ignored (testIgnoresUnknownEvents).
func TestEveryCoreEventIsRecordedAndOthersIgnored(t *testing.T) {
	auditBackends(t, func(t *testing.T, listen event.Listener, rows func() []model.AuditLogEntry) {
		events := []event.Event{
			event.UserEmailVerified{UserID: "u", Email: "a/b@example.com"}, event.PasswordChanged{UserID: "u", Method: "reset"},
			event.UserEnabled{UserID: "t", ActorUserID: "a"}, event.UserDeleted{UserID: "t", ActorUserID: "a"},
			event.TokenRefreshed{UserID: "u", FamilyID: "f"}, event.MFAFactorRemoved{UserID: "u", FactorID: "f"},
			event.MFAStepUpCompleted{UserID: "u", SessionID: "s"}, event.MFARecoveryRegenerated{UserID: "u"},
			event.MFARecoveryUsed{UserID: "u", Remaining: 7}, event.OTPChallengeSent{UserID: "u", FactorID: "f", Channel: "sms"},
			event.OrganizationCreated{OrganizationID: "o", Slug: "acme", OwnerUserID: "u"},
			event.MemberJoined{OrganizationID: "o", UserID: "u", Email: "ü@example.com"},
			event.MemberRemoved{OrganizationID: "o", UserID: "t", ActorUserID: "a"},
		}
		for _, e := range events {
			listen(ctx, e)
		}
		listen(ctx, unknownEvent{})
		got := rows()
		if len(got) != len(events) {
			t.Fatalf("rows = %d; want %d", len(got), len(events))
		}
		for i, e := range events {
			if got[i].Event != e.EventName() {
				t.Errorf("row %d = %s; want %s", i, got[i].Event, e.EventName())
			}
		}
		wantMeta(t, got[0], `{"email":"a\/b@example.com"}`)
		wantMeta(t, got[7], `[]`)
		wantMeta(t, got[8], `{"remaining":7}`)
		wantMeta(t, got[11], `{"email":"\u00fc@example.com"}`)
		if str(got[10].OrganizationID) != "o" || str(got[10].ActorUserID) != "u" {
			t.Errorf("org.created row = %+v", got[10])
		}
	})
}

type unknownEvent struct{}

func (unknownEvent) EventName() string { return "not.a.polaris.event" }

type brokenWriter struct{}

func (brokenWriter) Insert(context.Context, model.AuditLogEntry) error {
	return errors.New("database is down")
}

// Port of testAFailedAuditWriteIsSwallowedNotPropagated.
func TestAFailedAuditWriteIsLoggedAndSwallowed(t *testing.T) {
	var buf bytes.Buffer
	listen := AuditLog(brokenWriter{}, nil, slog.New(slog.NewTextHandler(&buf, nil)))
	listen(ctx, event.UserLoggedIn{UserID: "user-1", SessionID: "session-1"})
	if !strings.Contains(buf.String(), "database is down") || !strings.Contains(buf.String(), "user.logged_in") {
		t.Errorf("log = %q", buf.String())
	}
}

func TestDefaultsAreUsable(t *testing.T) {
	var got model.AuditLogEntry
	listen := AuditLog(writerFunc(func(e model.AuditLogEntry) { got = e }), nil, nil)
	listen(ctx, event.MFARecoveryRegenerated{UserID: "u"})
	if got.CreatedAt.IsZero() || reflect.DeepEqual(got, model.AuditLogEntry{}) {
		t.Errorf("entry = %+v", got)
	}
	_ = AuditLog(brokenWriter{}, nil, nil) // a nil logger falls back to slog.Default()
}

type writerFunc func(model.AuditLogEntry)

func (f writerFunc) Insert(_ context.Context, e model.AuditLogEntry) error { f(e); return nil }
