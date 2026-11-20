package identity

// Service-level port of tests/Functional/RegistrationEndpointTest (the HTTP-only cases, input
// validation, belong to the endpoints) plus the stored-row contract of EmailVerificationService.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

func TestRegistration(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		t.Run("testRegisterThenVerifyHappyPath", func(t *testing.T) {
			must(t, h.svc.Register(ctx, email, password, "Ada", client))
			regs := ofType[event.UserRegistered](h.events)
			if len(regs) != 1 {
				t.Fatalf("registered events %d", len(regs))
			}
			u := h.user(t, email)
			if u.EmailVerifiedAt != nil || u.PasswordHash == nil || u.Status != model.UserStatusActive ||
				u.DisplayName == nil || *u.DisplayName != "Ada" || !u.CreatedAt.Equal(start) || regs[0].UserID != u.ID {
				t.Fatalf("user %+v", u)
			}
			if !h.hasher.Argon2id.Verify(password, *u.PasswordHash) {
				t.Fatal("stored hash does not verify")
			}

			// Only the keyed hash of the token is stored, with a 24h expiry and the client IP.
			rows, err := h.repos.EmailVerifications.ListByUser(ctx, u.ID)
			must(t, err)
			if len(rows) != 1 || rows[0].TokenHash != h.pepper.Hash("email_verify", regs[0].VerificationToken) ||
				!rows[0].ExpiresAt.Equal(start.Add(24*time.Hour)) || rows[0].IP == nil || *rows[0].IP != client.IP ||
				rows[0].Email != email || len(regs[0].VerificationToken) != 43 {
				t.Fatalf("challenge %+v", rows)
			}

			h.clock.Advance(time.Minute)
			must(t, h.svc.VerifyEmail(ctx, regs[0].VerificationToken))
			u = h.user(t, email)
			if u.EmailVerifiedAt == nil || !u.EmailVerifiedAt.Equal(start.Add(time.Minute)) {
				t.Fatalf("verified at %v", u.EmailVerifiedAt)
			}
			if got := ofType[event.UserEmailVerified](h.events); len(got) != 1 || got[0].Email != email {
				t.Fatalf("verified events %+v", got)
			}
			rows, _ = h.repos.EmailVerifications.ListByUser(ctx, u.ID)
			if rows[0].ConsumedAt == nil {
				t.Fatal("challenge not consumed")
			}
		})
	})
}

func TestRegisterIsGenericAndDoesNotDuplicateAnExistingAccount(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)
		hashes := h.hasher.hashes.Load()
		must(t, h.svc.Register(ctx, "  ADA@example.com", password, "", client))
		if n := len(ofType[event.UserRegistered](h.events)); n != 1 {
			t.Fatalf("registered events %d", n)
		}
		if h.hasher.hashes.Load() != hashes+1 {
			t.Fatal("the taken-email path must still hash once (timing parity)")
		}
		if n, _ := h.repos.Users.Count(ctx, nil); n != 1 {
			t.Fatalf("users %d", n)
		}
	})
}

func TestRegisterNormalizesTheEmail(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		must(t, h.svc.Register(ctx, "  ADA@Example.com ", password, "", client))
		if u := h.user(t, email); u.DisplayName != nil {
			t.Fatalf("display name %v", *u.DisplayName)
		}
	})
}

func TestRegisterRejectsAShortPassword(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		err := h.svc.Register(ctx, email, "short", "", client)
		var pe *PasswordError
		if !errors.As(err, &pe) || len(pe.Violations) != 1 || !errors.Is(err, ErrInvalidPassword) {
			t.Fatalf("error %v", err)
		}
		if len(ofType[event.UserRegistered](h.events)) != 0 || h.hasher.hashes.Load() != 0 {
			t.Fatal("nothing may happen before the policy passes")
		}
	})
}

func TestVerifyEmailRefusals(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		t.Run("testVerifyRejectsAnUnknownToken", func(t *testing.T) {
			err := h.svc.VerifyEmail(ctx, "not-a-real-token")
			isErr(t, err, ErrInvalidVerificationToken)
			if err.Error() != "The verification token is invalid." {
				t.Fatal(err)
			}
		})
		t.Run("an expired token", func(t *testing.T) {
			secret := h.register(t, "late@example.com")
			h.clock.Advance(24 * time.Hour)
			err := h.svc.VerifyEmail(ctx, secret)
			isErr(t, err, ErrInvalidVerificationToken)
			if err.Error() != "The verification token has expired." {
				t.Fatal(err)
			}
		})
		t.Run("a token whose user is gone", func(t *testing.T) {
			secret := h.register(t, "gone@example.com")
			must(t, h.repos.Users.Delete(ctx, h.user(t, "gone@example.com")))
			isErr(t, h.svc.VerifyEmail(ctx, secret), ErrInvalidVerificationToken)
		})
	})
}

func TestResendReissuesForAKnownUnverifiedUser(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		first := h.register(t, email)
		h.clock.Advance(time.Minute)
		must(t, h.svc.ResendVerification(ctx, " Ada@Example.com", client))

		regs := ofType[event.UserRegistered](h.events)
		if len(regs) != 2 || regs[1].VerificationToken == first {
			t.Fatalf("registered events %+v", regs)
		}
		// The original is superseded; the new one verifies.
		isErr(t, h.svc.VerifyEmail(ctx, first), ErrInvalidVerificationToken)
		must(t, h.svc.VerifyEmail(ctx, regs[1].VerificationToken))
	})
}

func TestVerifyIsIdempotent(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		secret := h.register(t, email)
		must(t, h.svc.VerifyEmail(ctx, secret))
		h.clock.Advance(48 * time.Hour) // consumed and expired, yet the user is verified
		must(t, h.svc.VerifyEmail(ctx, secret))
		if n := len(ofType[event.UserEmailVerified](h.events)); n != 1 {
			t.Fatalf("verified events %d", n)
		}
	})
}

func TestResendIsAlwaysGeneric(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		must(t, h.svc.ResendVerification(ctx, "nobody@example.com", client))
		h.registerAndVerify(t, email)
		must(t, h.svc.ResendVerification(ctx, email, client))
		if n := len(ofType[event.UserRegistered](h.events)); n != 1 {
			t.Fatalf("registered events %d", n)
		}
	})
}

// hideUsers makes the email lookup miss, as when two registrations of one address race past it.
type hideUsers struct{ store.Adapter }

func (hideUsers) FindOne(_ context.Context, table string, _ store.Criteria) (store.Row, error) {
	if table == "auth_users" {
		return nil, nil
	}
	return nil, errors.New("unexpected lookup of " + table)
}

func TestARegistrationLosingTheRaceIsTheGenericTakenPath(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)
		racing := *h
		racing.db = hideUsers{h.db}
		racing.repos = repository.New(racing.db)
		svc := racing.service(t, h.auth)

		hashes := h.hasher.hashes.Load()
		must(t, svc.Register(ctx, email, password, "", client))
		if n := len(ofType[event.UserRegistered](h.events)); n != 1 {
			t.Fatalf("registered events %d", n)
		}
		if n, _ := h.repos.Users.Count(ctx, nil); n != 1 {
			t.Fatalf("users %d", n)
		}
		if h.hasher.hashes.Load() != hashes+1 {
			t.Fatal("one hash, as on the taken path")
		}
		if n, _ := h.repos.EmailVerifications.Count(ctx, nil); n != 1 {
			t.Fatalf("verifications %d", n)
		}
	})
}

func TestConcurrentRegistrationsOfOneAddress(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		var wg sync.WaitGroup
		for range 10 {
			wg.Go(func() {
				if err := h.svc.Register(ctx, email, password, "", client); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		if n := len(ofType[event.UserRegistered](h.events)); n != 1 {
			t.Fatalf("registered events %d", n)
		}
		if n, _ := h.repos.Users.Count(ctx, nil); n != 1 {
			t.Fatalf("users %d", n)
		}
	})
}
