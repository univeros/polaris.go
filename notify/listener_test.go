package notify_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/notify"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/storetest"
)

var bg = context.Background()

func ptr[T any](v T) *T { return &v }

// usersOn runs fn with a users repository on every storetest backend.
func usersOn(t *testing.T, fn func(t *testing.T, users repository.Users)) {
	t.Helper()
	storetest.Each(t, func(t *testing.T, db store.Adapter) { fn(t, repository.New(db).Users) })
}

func seedUser(t *testing.T, users repository.Users, email string) string {
	t.Helper()
	now := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	u := model.User{ID: repository.NewID(), Email: email, CreatedAt: now, UpdatedAt: now}
	if err := users.Insert(bg, u); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// Port of NotificationListenerTest::testTokenCarryingEventsMailTheTokenDirectly.
func TestTokenCarryingEventsMailTheTokenDirectly(t *testing.T) {
	usersOn(t, func(t *testing.T, users repository.Users) {
		m := &notifytest.Mailer{}
		listen := notify.Listener(m, users, nil)
		listen(bg, event.UserRegistered{UserID: "user-1", Email: "new@example.com", VerificationToken: "verify-token"})
		listen(bg, event.PasswordResetRequested{UserID: "user-1", Email: "new@example.com", ResetToken: "reset-token"})
		listen(bg, event.MemberInvited{OrganizationID: "org-1", Email: "invitee@example.com", InvitedBy: "inviter-1", InviteToken: "invite-token"})

		want := []notifytest.Mail{
			{To: "new@example.com", Template: "verify_email", Data: map[string]any{"token": "verify-token"}},
			{To: "new@example.com", Template: "password_reset", Data: map[string]any{"token": "reset-token"}},
			{To: "invitee@example.com", Template: "org_invite", Data: map[string]any{"token": "invite-token", "organization_id": "org-1"}},
		}
		if got := m.Sent(); !reflect.DeepEqual(got, want) {
			t.Errorf("sent = %+v", got)
		}
	})
}

// Port of testIdOnlyEventsResolveTheRecipient.
func TestIDOnlyEventsResolveTheRecipient(t *testing.T) {
	usersOn(t, func(t *testing.T, users repository.Users) {
		id := seedUser(t, users, "locked@example.com")
		m := &notifytest.Mailer{}
		listen := notify.Listener(m, users, nil)
		listen(bg, event.UserLocked{UserID: id, IP: ptr("203.0.113.7")})
		listen(bg, event.PasswordChanged{UserID: id, Method: "reset"})
		listen(bg, event.MFAEnrolled{UserID: id, FactorID: "factor-1"})
		listen(bg, event.MFAFactorRemoved{UserID: id, FactorID: "factor-1"})
		listen(bg, event.MFARecoveryRegenerated{UserID: id})
		listen(bg, event.MFARecoveryUsed{UserID: id, Remaining: 7})
		listen(bg, event.UserLocked{UserID: id})

		want := []notifytest.Mail{
			{To: "locked@example.com", Template: "account_locked", Data: map[string]any{"ip": "203.0.113.7"}},
			{To: "locked@example.com", Template: "password_changed", Data: map[string]any{"method": "reset"}},
			{To: "locked@example.com", Template: "mfa_enrolled", Data: map[string]any{"factor_id": "factor-1"}},
			{To: "locked@example.com", Template: "mfa_factor_removed", Data: map[string]any{"factor_id": "factor-1"}},
			{To: "locked@example.com", Template: "recovery_codes_regenerated", Data: map[string]any{}},
			{To: "locked@example.com", Template: "recovery_code_used", Data: map[string]any{"remaining": 7}},
			{To: "locked@example.com", Template: "account_locked", Data: map[string]any{"ip": nil}},
		}
		if got := m.Sent(); !reflect.DeepEqual(got, want) {
			t.Errorf("sent = %+v", got)
		}
	})
}

// Port of testUnknownUsersAndTombstonesAreSkipped and testIgnoresUnrelatedEvents.
func TestUnknownUsersTombstonesAndUnrelatedEventsAreSkipped(t *testing.T) {
	usersOn(t, func(t *testing.T, users repository.Users) {
		tombstone := seedUser(t, users, strings.Repeat("a", 64)+"@deleted.invalid")
		m := &notifytest.Mailer{}
		listen := notify.Listener(m, users, nil)
		listen(bg, event.UserLocked{UserID: repository.NewID()})
		listen(bg, event.UserLocked{UserID: tombstone})
		listen(bg, event.PasswordChanged{UserID: tombstone, Method: "change"})
		listen(bg, event.MFARecoveryUsed{UserID: tombstone, Remaining: 3})
		listen(bg, event.UserLoggedIn{UserID: tombstone})
		if got := m.Sent(); len(got) != 0 {
			t.Errorf("sent = %+v", got)
		}
	})
}

type brokenMailer struct{}

func (brokenMailer) Send(context.Context, string, string, map[string]any) error {
	return errors.New("smtp is down")
}

type brokenUsers struct{}

func (brokenUsers) Get(context.Context, string) (model.User, error) {
	return model.User{}, errors.New("db is down")
}

// Port of testAFailingMailerIsSwallowedNotPropagated; a failed lookup is logged the same way.
func TestFailuresAreLoggedAndSwallowed(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	notify.Listener(brokenMailer{}, brokenUsers{}, logger)(bg, event.UserRegistered{UserID: "u", Email: "new@example.com", VerificationToken: "secret"})
	notify.Listener(brokenMailer{}, brokenUsers{}, logger)(bg, event.PasswordChanged{UserID: "u", Method: "change"})
	out := buf.String()
	if !strings.Contains(out, "smtp is down") || !strings.Contains(out, "db is down") || strings.Contains(out, "secret") {
		t.Errorf("log = %q", out)
	}
}

func ExampleListener() {
	repos := repository.New(memstore.New(schema.Core()...))
	mailer := &notifytest.Mailer{} // your SES/SMTP adapter in production

	bus := &event.Bus{}
	bus.Subscribe(notify.Listener(mailer, repos.Users, nil))
	bus.Dispatch(context.Background(), event.MemberInvited{OrganizationID: "org-1", Email: "bob@example.com", InviteToken: "t0k3n"})

	sent := mailer.Sent()[0]
	fmt.Println(sent.To, sent.Template, sent.Data["token"])
	// Output: bob@example.com org_invite t0k3n
}
