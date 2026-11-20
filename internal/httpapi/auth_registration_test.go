package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
)

func TestRegistrationEndpoint(t *testing.T) {
	const class = "RegistrationEndpointTest"
	run := func(name string, f func(t *testing.T, a *authCase)) {
		t.Run(name, func(t *testing.T) { f(t, authNew(t, class, name)) })
	}

	run("testRegisterThenVerifyHappyPath", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword}), http.StatusAccepted)
		regs := authEventsOf[event.UserRegistered](a.srv)
		if len(regs) != 1 {
			t.Fatalf("user.registered events: %d", len(regs))
		}
		u := a.user(authEmail)
		if u.EmailVerifiedAt != nil || u.PasswordHash == nil {
			t.Fatalf("new user: verified %v, hash %v", u.EmailVerifiedAt, u.PasswordHash)
		}
		authStatusIs(t, a.c.Post("/auth/email/verify", map[string]any{"token": regs[0].VerificationToken}), http.StatusOK)
		if a.user(authEmail).EmailVerifiedAt == nil {
			t.Fatal("user not verified")
		}
		if n := len(authEventsOf[event.UserEmailVerified](a.srv)); n != 1 {
			t.Fatalf("user.email_verified events: %d", n)
		}
	})

	run("testRegisterIsGenericAndDoesNotDuplicateAnExistingAccount", func(t *testing.T, a *authCase) {
		a.c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword})
		authStatusIs(t, a.c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword}), http.StatusAccepted)
		if n := len(authEventsOf[event.UserRegistered](a.srv)); n != 1 {
			t.Fatalf("user.registered events: %d", n)
		}
	})

	run("testRegisterNormalizesTheEmail", func(t *testing.T, a *authCase) {
		a.c.Post("/auth/register", map[string]any{"email": "  ADA@Example.com ", "password": authPassword})
		a.user(authEmail)
	})

	run("testRegisterRejectsAShortPassword", func(t *testing.T, a *authCase) {
		resp := a.c.Post("/auth/register", map[string]any{"email": authEmail, "password": "short"})
		authStatusIs(t, resp, http.StatusUnprocessableEntity)
		if _, ok := contracttest.JSON(t, resp)["errors"]; !ok {
			t.Fatal("no errors key")
		}
		if n := len(authEventsOf[event.UserRegistered](a.srv)); n != 0 {
			t.Fatalf("user.registered events: %d", n)
		}
	})

	run("testRegisterRequiresEmailAndPassword", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/register", map[string]any{"email": authEmail}), http.StatusUnprocessableEntity)
	})

	run("testVerifyRejectsAnUnknownToken", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/email/verify", map[string]any{"token": "not-a-real-token"}), http.StatusBadRequest)
	})

	run("testVerifyRequiresAToken", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/email/verify", nil), http.StatusUnprocessableEntity)
	})

	run("testRejectsAnInvalidEmailFormat", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/register", map[string]any{"email": "not-an-email", "password": authPassword}), http.StatusUnprocessableEntity)
	})

	run("testResendReissuesForAKnownUnverifiedUser", func(t *testing.T, a *authCase) {
		a.c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword})
		first := authEventsOf[event.UserRegistered](a.srv)[0].VerificationToken
		authStatusIs(t, a.c.Post("/auth/email/verify/resend", map[string]any{"email": authEmail}), http.StatusAccepted)
		regs := authEventsOf[event.UserRegistered](a.srv)
		if len(regs) != 2 || regs[1].VerificationToken == first {
			t.Fatalf("resend did not reissue a new token (%d events)", len(regs))
		}
		authStatusIs(t, a.c.Post("/auth/email/verify", map[string]any{"token": first}), http.StatusBadRequest)
		authStatusIs(t, a.c.Post("/auth/email/verify", map[string]any{"token": regs[1].VerificationToken}), http.StatusOK)
	})

	run("testResendRequiresAValidEmail", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/email/verify/resend", map[string]any{"email": "bogus"}), http.StatusUnprocessableEntity)
	})

	run("testVerifyIsIdempotent", func(t *testing.T, a *authCase) {
		a.c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword})
		tok := authEventsOf[event.UserRegistered](a.srv)[0].VerificationToken
		authStatusIs(t, a.c.Post("/auth/email/verify", map[string]any{"token": tok}), http.StatusOK)
		authStatusIs(t, a.c.Post("/auth/email/verify", map[string]any{"token": tok}), http.StatusOK)
	})

	run("testResendIsAlwaysGeneric", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/email/verify/resend", map[string]any{"email": "nobody@example.com"}), http.StatusAccepted)
		if n := len(authEventsOf[event.UserRegistered](a.srv)); n != 0 {
			t.Fatalf("user.registered events: %d", n)
		}
	})
}
