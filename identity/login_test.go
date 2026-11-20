package identity

// Service-level port of tests/Functional/LoginEndpointTest plus the lockout, rehash and MFA
// hand-off rules of LoginService.

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
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
