package identity

// Login, service side, plus the lockout, rehash and MFA
// hand-off rules.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
)

func TestValidLoginIssuesATokenPair(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		h.clock.Advance(time.Minute)

		r, err := h.svc.Login(ctx, "  ADA@example.com", password, client)
		must(t, err)
		if r.MFA != nil || r.UserID != id || r.Email != email || !r.EmailVerified ||
			r.Tokens.AccessToken == "" || r.Tokens.RefreshToken == "" || r.Tokens.SessionID == "" {
			t.Fatalf("result %+v", r)
		}
		// The session is real: its refresh token exchanges and records how the user signed in.
		row, err := h.repos.RefreshTokens.ActiveInFamily(ctx, r.Tokens.SessionID)
		must(t, err)
		if row.UserID != id || row.MFA || *row.AMR != "pwd" || *row.AuthTime != start.Add(time.Minute).Unix() {
			t.Fatalf("session %+v", row)
		}
		if !h.refreshes(t, r.Tokens.RefreshToken) {
			t.Fatal("refresh refused")
		}

		// testLoginCarriesTheSanitizedUserAgentIntoTheEvent
		logins := ofType[event.UserLoggedIn](h.events)
		if len(logins) != 1 || logins[0].SessionID != r.Tokens.SessionID || *logins[0].UserAgent != client.UserAgent ||
			*logins[0].IP != client.IP || !slices.Equal(logins[0].AMR, []string{"pwd"}) {
			t.Fatalf("logged in %+v", logins)
		}
	})
}

func TestUnknownUserAndWrongPasswordAreIndistinguishable(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		before := h.hasher.verifies.Load()

		_, wrong := h.svc.Login(ctx, email, "not-the-password", client)
		_, unknown := h.svc.Login(ctx, "nobody@example.com", password, client)

		isErr(t, wrong, ErrInvalidCredentials)
		isErr(t, unknown, ErrInvalidCredentials)
		if wrong.Error() != unknown.Error() || wrong.Error() != "Invalid email or password." {
			t.Fatalf("%q vs %q", wrong, unknown)
		}
		// One Argon2id verify each: the unknown user is checked against the dummy hash.
		if got := h.hasher.verifies.Load() - before; got != 2 {
			t.Fatalf("verifies %d", got)
		}
		failed := ofType[event.UserLoginFailed](h.events)
		if len(failed) != 1 || failed[0].Reason != event.LoginFailedInvalidCredentials || *failed[0].IP != client.IP {
			t.Fatalf("login failed %+v", failed)
		}
	})
}

func TestAPasswordlessAccountFailsAfterADummyVerify(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		h.set(t, email, func(u *model.User) { u.PasswordHash = nil })
		before := h.hasher.verifies.Load()

		_, err := h.svc.Login(ctx, email, password, client)
		isErr(t, err, ErrInvalidCredentials)
		if h.hasher.verifies.Load()-before != 1 || h.user(t, email).FailedLoginCount != 1 {
			t.Fatal("a passwordless account still costs one verify and counts the failure")
		}
	})
}

func TestUnverifiedEmail(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)

		_, err := h.svc.Login(ctx, email, password, client)
		isErr(t, err, ErrEmailNotVerified)

		// With auth.flows.require_verified_email off, the login succeeds, unverified.
		auth := h.auth
		auth.Flows.RequireVerifiedEmail = false
		r, err := h.service(t, auth).Login(ctx, email, password, client)
		must(t, err)
		if r.EmailVerified || r.Tokens.SessionID == "" {
			t.Fatalf("result %+v", r)
		}
	})
}

func TestDisabledAccountIsForbidden(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		h.set(t, email, func(u *model.User) { u.Status = model.UserStatusDisabled })

		_, err := h.svc.Login(ctx, email, password, client)
		isErr(t, err, ErrAccountDisabled)
		if err.Error() != "This account is disabled." {
			t.Fatal(err)
		}
	})
}

func TestSuccessfulLoginStampsLastLoginAndClearsFailures(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		for range 2 {
			_, err := h.svc.Login(ctx, email, "wrong", client)
			isErr(t, err, ErrInvalidCredentials)
		}
		if u := h.user(t, email); u.FailedLoginCount != 2 || !u.FailedLoginAt.Equal(start) {
			t.Fatalf("user %+v", u)
		}
		h.clock.Advance(time.Minute)
		h.login(t, email)

		u := h.user(t, email)
		if u.FailedLoginCount != 0 || u.FailedLoginAt != nil || u.LockedUntil != nil ||
			u.LastLoginAt == nil || !u.LastLoginAt.Equal(start.Add(time.Minute)) || !u.UpdatedAt.Equal(start.Add(time.Minute)) {
			t.Fatalf("user %+v", u)
		}
	})
}

func TestRepeatedFailuresLockTheAccount(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		for range 5 {
			_, err := h.svc.Login(ctx, email, "wrong", client)
			isErr(t, err, ErrInvalidCredentials)
		}
		locks := ofType[event.UserLocked](h.events)
		until := start.Add(15 * time.Minute)
		if len(locks) != 1 || locks[0].UserID != id || !locks[0].Until.Equal(until) || *locks[0].IP != client.IP {
			t.Fatalf("locked %+v", locks)
		}
		u := h.user(t, email)
		if u.Status != model.UserStatusLocked || !u.LockedUntil.Equal(until) || u.FailedLoginCount != 5 {
			t.Fatalf("user %+v", u)
		}

		// The right password is a generic failure while locked, and attempts against a live lock
		// neither count nor extend it.
		h.clock.Advance(time.Minute)
		_, err := h.svc.Login(ctx, email, password, client)
		isErr(t, err, ErrInvalidCredentials)
		_, err = h.svc.Login(ctx, email, "wrong", client)
		isErr(t, err, ErrInvalidCredentials)
		if u := h.user(t, email); u.FailedLoginCount != 5 || !u.LockedUntil.Equal(until) {
			t.Fatalf("user %+v", u)
		}
		if n := len(ofType[event.UserLoginFailed](h.events)); n != 5 {
			t.Fatalf("login failed events %d", n)
		}
	})
}

func TestLockAutoExpires(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		for range 5 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}
		h.clock.Advance(15 * time.Minute) // locked_until == now: the lock has lapsed
		h.login(t, email)

		u := h.user(t, email)
		if u.Status != model.UserStatusActive || u.LockedUntil != nil || u.FailedLoginCount != 0 || u.FailedLoginAt != nil {
			t.Fatalf("user %+v", u)
		}
	})
}

func TestAFailureAfterAnExpiredLockStartsAFreshWindow(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		for range 5 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}
		h.clock.Advance(16 * time.Minute)
		_, err := h.svc.Login(ctx, email, "wrong", client)
		isErr(t, err, ErrInvalidCredentials)

		u := h.user(t, email)
		if u.Status != model.UserStatusActive || u.LockedUntil != nil || u.FailedLoginCount != 1 {
			t.Fatalf("user %+v", u)
		}
	})
}

func TestFailuresOutsideTheWindowDoNotAccumulateToALock(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		for range 4 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}
		// One second inside the 900 s window still counts …
		h.clock.Advance(900 * time.Second)
		_, _ = h.svc.Login(ctx, email, "wrong", client)
		if u := h.user(t, email); u.FailedLoginCount != 5 || u.LockedUntil == nil {
			t.Fatalf("at the window edge: %+v", u)
		}
	})
}

func TestAFailurePastTheWindowStartsAFreshStreak(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		for range 4 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}
		// … one past it starts a fresh streak.
		h.clock.Advance(901 * time.Second)
		_, _ = h.svc.Login(ctx, email, "wrong", client)
		if u := h.user(t, email); u.FailedLoginCount != 1 || u.LockedUntil != nil {
			t.Fatalf("past the window: %+v", u)
		}
		h.login(t, email)
	})
}

func TestFailedLoginsAgainstADisabledAccountNeverReEnableIt(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		h.set(t, email, func(u *model.User) { u.Status = model.UserStatusDisabled })
		for range 5 {
			_, err := h.svc.Login(ctx, email, "wrong", client)
			isErr(t, err, ErrInvalidCredentials)
		}
		u := h.user(t, email)
		if u.Status != model.UserStatusDisabled || u.FailedLoginCount != 0 || u.LockedUntil != nil {
			t.Fatalf("user %+v", u)
		}
		_, err := h.svc.Login(ctx, email, password, client)
		isErr(t, err, ErrAccountDisabled)
	})
}

func TestLoginRehashesAnOutdatedHash(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		old, err := security.Argon2id{Memory: 16, Time: 1, Threads: 1}.Hash(password)
		must(t, err)
		h.set(t, email, func(u *model.User) { u.PasswordHash = &old })

		h.login(t, email)
		hash := *h.user(t, email).PasswordHash
		if hash == old || h.hasher.NeedsRehash(hash) || !h.hasher.Verify(password, hash) {
			t.Fatalf("hash %q not upgraded", hash)
		}
	})
}

func TestAConfirmedFactorTurnsTheLoginIntoAnMFAChallenge(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		confirmed := start
		for _, f := range []model.MFAFactor{
			{ID: repository.NewID(), UserID: id, Type: model.FactorTOTP, ConfirmedAt: &confirmed, CreatedAt: start, UpdatedAt: start},
			{ID: repository.NewID(), UserID: id, Type: model.FactorTOTP, CreatedAt: start, UpdatedAt: start}, // pending
		} {
			must(t, h.repos.MFAFactors.Insert(ctx, f))
		}
		_, _ = h.svc.Login(ctx, email, "wrong", client)
		h.clock.Advance(time.Minute)

		r, err := h.svc.Login(ctx, email, password, client)
		must(t, err)
		if r.MFA == nil || r.MFA.Ticket != "mfa-ticket-"+id || len(r.MFA.Factors) != 1 || r.Tokens.SessionID != "" || r.UserID != id {
			t.Fatalf("result %+v", r)
		}
		// The password step is settled (streak cleared) but the login is not complete: no session,
		// no last_login_at, no user.logged_in.
		u := h.user(t, email)
		if u.FailedLoginCount != 0 || u.LastLoginAt != nil {
			t.Fatalf("user %+v", u)
		}
		if n, _ := h.repos.RefreshTokens.Count(ctx, nil); n != 0 {
			t.Fatalf("sessions %d", n)
		}
		if n := len(ofType[event.UserLoggedIn](h.events)); n != 0 {
			t.Fatalf("logged in events %d", n)
		}
	})
}

// N concurrent wrong passwords count N: no lost update on failed_login_count.
func TestConcurrentFailuresAreAllCounted(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		auth := h.auth
		auth.Lockout.MaxAttempts = 100
		svc := h.service(t, auth)
		h.registerAndVerify(t, email)
		hammer(t, svc, 20)
		if u := h.user(t, email); u.FailedLoginCount != 20 || u.LockedUntil != nil {
			t.Fatalf("user %+v", u)
		}
		if n := len(ofType[event.UserLoginFailed](h.events)); n != 20 {
			t.Fatalf("login failed events %d", n)
		}
	})
}

// Concurrent failures lock exactly as the sequential rule would: the threshold-th failure locks,
// the ones after it meet a live lock and are not counted.
func TestConcurrentFailuresLockExactlyAtTheThreshold(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		hammer(t, h.svc, 20)
		u := h.user(t, email)
		if u.FailedLoginCount != 5 || u.Status != model.UserStatusLocked || !u.LockedUntil.Equal(start.Add(15*time.Minute)) {
			t.Fatalf("user %+v", u)
		}
		if n := len(ofType[event.UserLoginFailed](h.events)); n != 5 {
			t.Fatalf("login failed events %d", n)
		}
		if n := len(ofType[event.UserLocked](h.events)); n != 1 {
			t.Fatalf("locked events %d", n)
		}
	})
}

func hammer(t *testing.T, svc *Service, n int) {
	t.Helper()
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			if _, err := svc.Login(ctx, email, "wrong", client); !errors.Is(err, ErrInvalidCredentials) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestAnExpiredLockRelocksOnTheFirstFailureWhenTheThresholdIsOne(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		auth := h.auth
		auth.Lockout.MaxAttempts = 1
		svc := h.service(t, auth)
		h.registerAndVerify(t, email)
		_, _ = svc.Login(ctx, email, "wrong", client)
		h.clock.Advance(16 * time.Minute)
		_, _ = svc.Login(ctx, email, "wrong", client)
		if n := len(ofType[event.UserLocked](h.events)); n != 2 {
			t.Fatalf("locked events %d", n)
		}
		if u := h.user(t, email); u.FailedLoginCount != 1 || !u.LockedUntil.Equal(start.Add(31*time.Minute)) {
			t.Fatalf("user %+v", u)
		}
	})
}

// hookHasher runs a callback while a login verifies its password.
type hookHasher struct {
	*countingHasher
	during  func()
	upgrade bool
}

func (h *hookHasher) Verify(plain, hash string) bool {
	ok := h.countingHasher.Verify(plain, hash)
	if f := h.during; f != nil {
		h.during = nil
		f()
	}
	return ok
}

func (h *hookHasher) NeedsRehash(hash string) bool {
	return h.upgrade || h.countingHasher.NeedsRehash(hash)
}

// A login is checked again where it opens its session: what changed the password or the account
// while it verified the password wins.
func TestALoginThatLosesItsPasswordOrAccountOpensNoSession(t *testing.T) {
	for name, c := range map[string]struct {
		during  func(t *testing.T, h *harness, id string)
		want    error
		factor  bool
		upgrade bool
	}{
		"reset":                 {during: func(t *testing.T, h *harness, _ string) { h.resetTo(t, newPassword) }, want: ErrInvalidCredentials},
		"reset, a rehash due":   {during: func(t *testing.T, h *harness, _ string) { h.resetTo(t, newPassword) }, want: ErrInvalidCredentials, upgrade: true},
		"reset, MFA":            {during: func(t *testing.T, h *harness, _ string) { h.resetTo(t, newPassword) }, want: ErrInvalidCredentials, factor: true},
		"reset, MFA and rehash": {during: func(t *testing.T, h *harness, _ string) { h.resetTo(t, newPassword) }, want: ErrInvalidCredentials, factor: true, upgrade: true},
		"change": {during: func(t *testing.T, h *harness, id string) {
			must(t, h.svc.ChangePassword(ctx, id, password, newPassword, ""))
		}, want: ErrInvalidCredentials},
		"disable": {during: func(t *testing.T, h *harness, id string) { must(t, h.svc.DisableUser(ctx, "operator", id)) }, want: ErrAccountDisabled},
		"disable, MFA": {during: func(t *testing.T, h *harness, id string) { must(t, h.svc.DisableUser(ctx, "operator", id)) },
			want: ErrAccountDisabled, factor: true},
		"erase": {during: func(t *testing.T, h *harness, id string) { must(t, h.svc.AnonymizeUser(ctx, "operator", id)) }, want: ErrInvalidCredentials},
		"another login rehashes": {during: func(t *testing.T, h *harness, _ string) {
			rehashed, err := h.hasher.Hash(password)
			must(t, err)
			h.set(t, email, func(u *model.User) { u.PasswordHash = &rehashed })
		}, upgrade: true},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, h *harness) {
				id := h.registerAndVerify(t, email)
				if c.factor {
					confirmed := start
					must(t, h.repos.MFAFactors.Insert(ctx, model.MFAFactor{ID: repository.NewID(), UserID: id, Type: model.FactorTOTP,
						ConfirmedAt: &confirmed, CreatedAt: start, UpdatedAt: start}))
				}
				hooked := &hookHasher{countingHasher: h.hasher, upgrade: c.upgrade}
				svc, err := New(Config{DB: h.db, Hasher: hooked, Pepper: h.pepper, Sessions: h.sessions, MFA: gate{h.repos}, Tickets: tickets{},
					Authority: h.admins, Auth: h.auth, Clock: h.clock, Events: h.events})
				must(t, err)
				hooked.during = func() { c.during(t, h, id) }
				r, err := svc.Login(ctx, email, password, client)
				if c.want == nil {
					if err != nil || r.Tokens.RefreshToken == "" {
						t.Fatalf("login: %+v %v", r, err)
					}
					return
				}
				isErr(t, err, c.want)
				if r.MFA != nil {
					t.Fatal("an MFA ticket was issued")
				}
				if list, err := h.sessions.List(ctx, id, ""); err != nil || len(list) != 0 {
					t.Fatalf("live sessions %+v %v", list, err)
				}
				if u, err := h.repos.Users.Get(ctx, id); err != nil || errors.Is(c.want, ErrInvalidCredentials) && u.PasswordHash != nil && !h.hasher.Verify(newPassword, *u.PasswordHash) {
					t.Fatalf("the old password came back: %v", err)
				}
			})
		})
	}
}

// resetTo resets the password of email by its mailbox.
func (h *harness) resetTo(t *testing.T, to string) {
	t.Helper()
	must(t, h.svc.ForgotPassword(ctx, email, client))
	resets := ofType[event.PasswordResetRequested](h.events)
	must(t, h.svc.ResetPassword(ctx, resets[len(resets)-1].ResetToken, to, client))
}

func TestHoldForSignInRefusesAnAccountThatChanged(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		hold := func(u model.User) error {
			return h.db.Tx(ctx, func(ctx context.Context) error { return h.svc.HoldForSignIn(ctx, u) })
		}
		h.register(t, email)
		read := h.user(t, email)
		must(t, hold(read))
		_, _, err := h.svc.ProveEmail(ctx, read.ID, false)
		must(t, err)
		isErr(t, hold(read), ErrInvalidCredentials) // what it signed in with went with the first proof
		must(t, hold(h.user(t, email)))
		must(t, h.svc.DisableUser(ctx, "operator", read.ID))
		isErr(t, hold(h.user(t, email)), ErrAccountDisabled)
		isErr(t, hold(model.User{ID: repository.NewID()}), ErrUserNotFound)
	})
}

// raceDB runs before once, when the next transaction begins.
type raceDB struct {
	store.Adapter
	before func()
}

func (r *raceDB) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if f := r.before; f != nil {
		r.before = nil
		f()
	}
	return r.Adapter.Tx(ctx, fn)
}

func TestAHostsSignInIsCheckedWhereItOpensItsSession(t *testing.T) {
	for name, c := range map[string]struct {
		before func(h *harness, id string) error
		want   error
	}{
		"disabled": {func(h *harness, id string) error { return h.svc.DisableUser(ctx, "operator", id) }, ErrAccountDisabled},
		"proven": {func(h *harness, id string) error {
			_, _, err := h.svc.ProveEmail(ctx, id, false)
			return err
		}, ErrInvalidCredentials},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, h *harness) {
				h.register(t, email)
				id := h.user(t, email).ID
				auth := h.auth
				auth.Flows.RequireVerifiedEmail = false
				racing := &raceDB{Adapter: h.db}
				svc, err := New(Config{DB: racing, Hasher: h.hasher, Pepper: h.pepper, Sessions: h.sessions, MFA: gate{h.repos}, Tickets: tickets{},
					Authority: h.admins, Auth: auth, Clock: h.clock, Events: h.events})
				must(t, err)
				racing.before = func() { must(t, c.before(h, id)) }
				_, err = svc.SignIn(ctx, id, nil, client)
				isErr(t, err, c.want)
				if list, err := h.sessions.List(ctx, id, ""); err != nil || len(list) != 0 {
					t.Fatalf("live sessions %+v %v", list, err)
				}
			})
		})
	}
}
