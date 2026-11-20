package identity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
)

func TestNewNamesEveryMissingDependency(t *testing.T) {
	_, err := New(Config{Auth: config.Defaults()})
	isErr(t, err, ErrInvalidConfig)
	want := "Config.DB, Config.Hasher, Config.Pepper, Config.Sessions, Config.MFA, Config.Tickets, Config.Authority required"
	if !strings.Contains(err.Error(), want) {
		t.Fatal(err)
	}
}

func TestNewRejectsAnInvalidAuthConfig(t *testing.T) {
	h := newHarness(t, memstore.New())
	_, err := New(Config{
		DB: h.db, Hasher: h.hasher, Pepper: h.pepper, Sessions: h.sessions, MFA: gate{h.repos}, Tickets: tickets{},
		Authority: h.admins, Auth: config.Auth{},
	})
	isErr(t, err, ErrInvalidConfig)
	isErr(t, err, config.ErrInvalid)
}

// broken fails every read and write.
type broken struct{ store.Adapter }

var errDown = errors.New("database down")

func (broken) FindOne(context.Context, string, store.Criteria) (store.Row, error) {
	return nil, errDown
}

// An unreachable database is an error, never a refusal or a silent success: a generic answer
// (forgot, resend, register) must not hide an outage, and a login must not count as a failure.
func TestADatabaseErrorIsNeverARefusal(t *testing.T) {
	h := newHarness(t, memstore.New(schema.Core()...))
	h.db = broken{h.db}
	h.repos = repository.New(h.db)
	s := h.service(t, h.auth)
	refusals := []error{ErrInvalidCredentials, ErrInvalidVerificationToken, ErrInvalidResetToken, ErrUserNotFound}
	for name, err := range map[string]error{
		"register": s.Register(ctx, email, password, "", client),
		"verify":   s.VerifyEmail(ctx, "x"),
		"resend":   s.ResendVerification(ctx, email, client),
		"forgot":   s.ForgotPassword(ctx, email, client),
		"reset":    s.ResetPassword(ctx, "x", newPassword, client),
		"change":   s.ChangePassword(ctx, "id", password, newPassword, ""),
		"disable":  s.DisableUser(ctx, "a", "b"),
		"enable":   s.EnableUser(ctx, "a", "b"),
		"erase":    s.AnonymizeUser(ctx, "a", "b"),
		"login":    func() error { _, err := s.Login(ctx, email, password, client); return err }(),
		"read":     func() error { _, err := s.ReadUser(ctx, "a", "", "a"); return err }(),
		"update":   func() error { _, err := s.UpdateProfile(ctx, "a", "", "a", nil); return err }(),
	} {
		if !errors.Is(err, errDown) {
			t.Errorf("%s: %v", name, err)
		}
		for _, r := range refusals {
			if errors.Is(err, r) {
				t.Errorf("%s: an outage reads as %v", name, r)
			}
		}
	}
}
