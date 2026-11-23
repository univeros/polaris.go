package identity

// The user administration service (the users endpoints, service side). Route-level
// authorization (users.manage on disable/enable, authentication) belongs to the pipeline.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

func ptr[T any](v T) *T { return &v }

// superadmin registers operator@example.com holding every users permission.
func (h *harness) superadmin(t *testing.T) string {
	t.Helper()
	id := h.registerAndVerify(t, "operator@example.com")
	h.admins[id] = authz.Authority{Roles: []string{authz.RoleSuperadmin}, Scope: []string{authz.UsersRead, authz.UsersManage}}
	return id
}

func isForbidden(t *testing.T, err error) {
	t.Helper()
	var fe *authz.ForbiddenError
	if !errors.As(err, &fe) || fe.Message != "You may only manage your own account." {
		t.Fatalf("error = %v, want forbidden", err)
	}
}

func TestUserReadsAndUpdatesTheirOwnProfile(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		h.login(t, email)

		v, err := h.svc.ReadUser(ctx, id, "", id)
		must(t, err)
		last := start.Format("2006-01-02T15:04:05") + "Z"
		if v.Email != email || v.Status != "active" || !v.EmailVerified || v.MFAEnforced || v.DisplayName != nil ||
			v.CreatedAt != "2026-06-07T10:00:00Z" || v.LastLoginAt == nil || *v.LastLoginAt != last {
			t.Fatalf("view %+v", v)
		}

		h.clock.Advance(time.Minute)
		v, err = h.svc.UpdateProfile(ctx, id, "", id, ptr("  Tony \n"))
		must(t, err)
		if *v.DisplayName != "Tony" || *h.user(t, email).DisplayName != "Tony" || !h.user(t, email).UpdatedAt.Equal(start.Add(time.Minute)) {
			t.Fatalf("view %+v", v)
		}
		// nil leaves the name; blank clears it.
		v, _ = h.svc.UpdateProfile(ctx, id, "", id, nil)
		if *v.DisplayName != "Tony" {
			t.Fatalf("view %+v", v)
		}
		v, _ = h.svc.UpdateProfile(ctx, id, "", id, ptr("   "))
		if v.DisplayName != nil || h.user(t, email).DisplayName != nil {
			t.Fatalf("view %+v", v)
		}
	})
}

func TestPlainUserCannotReadOrUpdateAnotherUser(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		alice := h.registerAndVerify(t, "alice@example.com")
		bob := h.registerAndVerify(t, "bob@example.com")

		_, err := h.svc.ReadUser(ctx, alice, "", bob)
		isForbidden(t, err)
		_, err = h.svc.UpdateProfile(ctx, alice, "", bob, ptr("Hacked"))
		isForbidden(t, err)
		isForbidden(t, h.svc.EraseUser(ctx, alice, "", bob))

		// testNonAdminProbingAnUnknownIdGetsForbiddenNotNotFound
		_, err = h.svc.ReadUser(ctx, alice, "", repository.NewID())
		isForbidden(t, err)
		isForbidden(t, h.svc.EraseUser(ctx, alice, "", repository.NewID()))

		// users.read alone does not allow an update.
		h.admins[alice] = authz.Authority{Scope: []string{authz.UsersRead}}
		_, err = h.svc.ReadUser(ctx, alice, "", bob)
		must(t, err)
		_, err = h.svc.UpdateProfile(ctx, alice, "", bob, ptr("Hacked"))
		isForbidden(t, err)
	})
}

func TestSuperadminCanReadAndUpdateAnyUser(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		target := h.registerAndVerify(t, "target@example.com")

		v, err := h.svc.ReadUser(ctx, admin, "", target)
		must(t, err)
		if v.Email != "target@example.com" || v.LastLoginAt != nil {
			t.Fatalf("view %+v", v)
		}
		v, err = h.svc.UpdateProfile(ctx, admin, "", target, ptr("Renamed"))
		must(t, err)
		if *v.DisplayName != "Renamed" {
			t.Fatalf("view %+v", v)
		}
	})
}

func TestDisableRevokesSessionsAndBlocksLogin(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		target := h.registerAndVerify(t, "target@example.com")
		session := h.login(t, "target@example.com")

		must(t, h.svc.DisableUser(ctx, admin, target))
		if u := h.user(t, "target@example.com"); u.Status != model.UserStatusDisabled {
			t.Fatalf("user %+v", u)
		}
		if h.refreshes(t, session.RefreshToken) {
			t.Fatal("a session survived the disable")
		}
		rows, _ := h.repos.RefreshTokens.ListByFamily(ctx, session.SessionID)
		if *rows[0].RevokedReason != model.RevokedAdmin {
			t.Fatalf("revoked reason %v", *rows[0].RevokedReason)
		}
		_, err := h.svc.Login(ctx, "target@example.com", password, client)
		isErr(t, err, ErrAccountDisabled)

		// testDisablingTwiceEmitsASingleEvent
		must(t, h.svc.DisableUser(ctx, admin, target))
		disabled := ofType[event.UserDisabled](h.events)
		if len(disabled) != 1 || disabled[0].UserID != target || disabled[0].ActorUserID != admin {
			t.Fatalf("disabled %+v", disabled)
		}
	})
}

func TestEnableRestoresAccess(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		target := h.registerAndVerify(t, "target@example.com")
		for range 5 {
			_, _ = h.svc.Login(ctx, "target@example.com", "wrong", client)
		}
		must(t, h.svc.DisableUser(ctx, admin, target))
		must(t, h.svc.EnableUser(ctx, admin, target))

		u := h.user(t, "target@example.com")
		if u.Status != model.UserStatusActive || u.LockedUntil != nil || u.FailedLoginCount != 0 || u.FailedLoginAt != nil {
			t.Fatalf("user %+v", u)
		}
		if e := ofType[event.UserEnabled](h.events); len(e) != 1 || e[0].ActorUserID != admin {
			t.Fatalf("enabled %+v", e)
		}
		h.login(t, "target@example.com")
	})
}

// An erased account takes no password, and a disabled one no reset that was read before.
func TestAnErasedOrDisabledAccountTakesNoPassword(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		must(t, h.svc.AnonymizeUser(ctx, "operator", id))
		isErr(t, h.svc.SetPassword(ctx, id, newPassword), ErrConflict)
		name := "Ada"
		_, err := h.svc.UpdateProfile(ctx, id, "", id, &name)
		isErr(t, err, ErrConflict)

		id = h.registerAndVerify(t, "bob@example.com")
		secret := h.requestReset(t, "bob@example.com")
		svc, err := New(Config{DB: &raceDB{Adapter: h.db, before: func() { must(t, h.svc.DisableUser(ctx, "operator", id)) }}, Hasher: h.hasher, Pepper: h.pepper,
			Sessions: h.sessions, MFA: gate{h.repos}, Tickets: tickets{}, Authority: h.admins, Auth: h.auth, Clock: h.clock, Events: h.events})
		must(t, err)
		isErr(t, svc.ResetPassword(ctx, secret, newPassword, client), ErrInvalidResetToken)
		must(t, h.svc.EnableUser(ctx, "operator", id))
		if _, err := h.svc.Login(ctx, "bob@example.com", password, client); err != nil {
			t.Fatalf("the password was changed: %v", err)
		}
	})
}

// An account erased while an operator enables it, or enabled while it is erased, ends erased.
func TestAnErasureOutlivesAConcurrentEnable(t *testing.T) {
	racing := func(t *testing.T, h *harness, before func()) *Service {
		svc, err := New(Config{DB: &raceDB{Adapter: h.db, before: before}, Hasher: h.hasher, Pepper: h.pepper, Sessions: h.sessions, MFA: gate{h.repos},
			Tickets: tickets{}, Authority: h.admins, Auth: h.auth, Clock: h.clock, Events: h.events})
		must(t, err)
		return svc
	}
	for name, run := range map[string]func(t *testing.T, h *harness, id string){
		"erased first": func(t *testing.T, h *harness, id string) {
			svc := racing(t, h, func() { must(t, h.svc.AnonymizeUser(ctx, "operator", id)) })
			isErr(t, svc.EnableUser(ctx, "operator", id), ErrConflict)
		},
		"enabled first": func(t *testing.T, h *harness, id string) {
			svc := racing(t, h, func() { must(t, h.svc.EnableUser(ctx, "operator", id)) })
			must(t, svc.AnonymizeUser(ctx, "operator", id))
		},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, h *harness) {
				id := h.registerAndVerify(t, email)
				must(t, h.svc.DisableUser(ctx, "operator", id))
				run(t, h, id)
				if u, err := h.repos.Users.Get(ctx, id); err != nil || u.Status != model.UserStatusDisabled || u.PasswordHash != nil {
					t.Fatalf("user %+v %v", u, err)
				}
			})
		})
	}
}

func TestAdminCannotDisableThemselves(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		err := h.svc.DisableUser(ctx, admin, admin)
		isErr(t, err, ErrConflict)
		if err.Error() != "You cannot disable your own account." {
			t.Fatal(err)
		}
	})
}

func TestUnknownUserIsNotFoundForAdmins(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		unknown := repository.NewID()

		_, err := h.svc.ReadUser(ctx, admin, "", unknown)
		isErr(t, err, ErrUserNotFound)
		if err.Error() != "The user does not exist." {
			t.Fatal(err)
		}
		_, err = h.svc.UpdateProfile(ctx, admin, "", unknown, ptr("X"))
		isErr(t, err, ErrUserNotFound)
		isErr(t, h.svc.DisableUser(ctx, admin, unknown), ErrUserNotFound)
		isErr(t, h.svc.EnableUser(ctx, admin, unknown), ErrUserNotFound)
		isErr(t, h.svc.EraseUser(ctx, admin, "", unknown), ErrUserNotFound)
	})
}

func TestRejectsBadProfileInput(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		_, err := h.svc.UpdateProfile(ctx, id, "", id, ptr(strings.Repeat("x", 121)))
		isErr(t, err, ErrInvalidProfile)
		if err.Error() != "The display name must be 120 characters or fewer." {
			t.Fatal(err)
		}
		_, err = h.svc.UpdateProfile(ctx, id, "", id, ptr(strings.Repeat("é", 120)))
		must(t, err)
	})
}

func TestSelfDeleteAnonymizesAndKillsTheAccount(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		id := h.registerAndVerify(t, "leaving@example.com")
		session := h.login(t, "leaving@example.com")
		h.requestReset(t, "leaving@example.com")
		must(t, h.svc.ResendVerification(ctx, "leaving@example.com", client)) // verified: no-op
		confirmed := start
		factor := model.MFAFactor{ID: repository.NewID(), UserID: id, Type: model.FactorSMS, PhoneE164: ptr("+15551234567"),
			ConfirmedAt: &confirmed, CreatedAt: start, UpdatedAt: start}
		must(t, h.repos.MFAFactors.Insert(ctx, factor))
		must(t, h.repos.OTPChallenges.Insert(ctx, model.OTPChallenge{ID: repository.NewID(), UserID: id, FactorID: ptr(factor.ID),
			Purpose: "login_mfa", Channel: model.ChannelSMS, Destination: ptr("+15551234567"), CodeHash: ptr("h"), ExpiresAt: start,
			MaxAttempts: 5, CreatedAt: start}))
		h.set(t, "leaving@example.com", func(u *model.User) { u.DisplayName, u.MFAEnforced = ptr("Leaving"), true })

		must(t, h.svc.EraseUser(ctx, id, "", id))

		v, err := h.svc.ReadUser(ctx, admin, "", id)
		must(t, err)
		want := h.pepper.Hash("user_erasure", "leaving@example.com") + "@deleted.invalid"
		if v.Email != want || v.DisplayName != nil || v.Status != "disabled" || v.EmailVerified || v.MFAEnforced {
			t.Fatalf("view %+v", v)
		}
		u, err := h.repos.Users.Get(ctx, id)
		must(t, err)
		if u.PasswordHash != nil {
			t.Fatal("credentials survived")
		}
		for name, count := range map[string]func() (int64, error){
			"factors":       func() (int64, error) { return h.repos.MFAFactors.Count(ctx, nil) },
			"otp":           func() (int64, error) { return h.repos.OTPChallenges.Count(ctx, nil) },
			"verifications": func() (int64, error) { return h.repos.EmailVerifications.Count(ctx, map[string]any{"user_id": id}) },
			"resets":        func() (int64, error) { return h.repos.PasswordResets.Count(ctx, nil) },
		} {
			if n, err := count(); err != nil || n != 0 {
				t.Errorf("%s left: %d %v", name, n, err)
			}
		}
		if h.refreshes(t, session.RefreshToken) {
			t.Fatal("a session survived the erasure")
		}
		_, err = h.svc.Login(ctx, "leaving@example.com", password, client)
		isErr(t, err, ErrInvalidCredentials)
		if d := ofType[event.UserDeleted](h.events); len(d) != 1 || d[0].UserID != id || d[0].ActorUserID != id {
			t.Fatalf("deleted %+v", d)
		}

		// testATombstoneCannotBeReEnabled
		err = h.svc.EnableUser(ctx, admin, id)
		isErr(t, err, ErrConflict)
		if err.Error() != "The account has been anonymized and cannot be re-enabled." {
			t.Fatal(err)
		}
	})
}

func TestAdminCanDeleteAUser(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		admin := h.superadmin(t)
		target := h.registerAndVerify(t, "target@example.com")
		must(t, h.svc.EraseUser(ctx, admin, "", target))
		v, err := h.svc.ReadUser(ctx, admin, "", target)
		must(t, err)
		if !strings.HasSuffix(v.Email, "@deleted.invalid") {
			t.Fatalf("view %+v", v)
		}
		if d := ofType[event.UserDeleted](h.events); len(d) != 1 || d[0].ActorUserID != admin {
			t.Fatalf("deleted %+v", d)
		}
	})
}

// An address erased once can be registered and erased again: the tombstones of the same address do
// not collide.
func TestAnAddressCanBeErasedAgain(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		seen := map[string]bool{}
		for range 3 {
			h.registerAndVerify(t, email)
			u := h.user(t, email)
			must(t, h.svc.AnonymizeUser(ctx, "operator", u.ID))
			after, err := h.repos.Users.Get(ctx, u.ID)
			must(t, err)
			if !strings.HasSuffix(after.Email, "@deleted.invalid") || strings.Contains(after.Email, email) || seen[after.Email] {
				t.Fatalf("tombstone %q", after.Email)
			}
			seen[after.Email] = true
		}
		if !seen[h.pepper.Hash("user_erasure", email)+"@deleted.invalid"] {
			t.Fatal("the first erasure keeps the stored format")
		}
	})
}
