package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
)

func TestPasswordEndpoints(t *testing.T) {
	const class = "PasswordEndpointsTest"
	run := func(name string, f func(t *testing.T, a *authCase)) {
		t.Run(name, func(t *testing.T) { f(t, authNew(t, class, name)) })
	}
	forgot := func(a *authCase, email string) *http.Response {
		return a.c.Post("/auth/password/forgot", map[string]any{"email": email})
	}
	requestReset := func(t *testing.T, a *authCase) string {
		forgot(a, authEmail)
		resets := authEventsOf[event.PasswordResetRequested](a.srv)
		if len(resets) == 0 {
			t.Fatal("no password reset requested")
		}
		return resets[0].ResetToken
	}
	reset := func(a *authCase, secret, password string) *http.Response {
		return a.c.Post("/auth/password/reset", map[string]any{"token": secret, "new_password": password})
	}
	change := func(a *authCase, access, current, next string) *http.Response {
		return a.c.Post("/auth/password/change", map[string]any{"current_password": current, "new_password": next}, contracttest.Bearer(access))
	}
	login := func(a *authCase, password string) *http.Response {
		return a.c.Post("/auth/login", map[string]any{"email": authEmail, "password": password})
	}
	refresh := func(a *authCase, secret string) *http.Response {
		return a.c.Post("/auth/token/refresh", map[string]any{"refresh_token": secret})
	}
	resets := func(a *authCase) int { return len(authEventsOf[event.PasswordResetRequested](a.srv)) }

	run("testForgotIsGenericAndNotifiesAKnownUser", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		authStatusIs(t, forgot(a, authEmail), http.StatusAccepted)
		if n := resets(a); n != 1 {
			t.Fatalf("password reset events: %d", n)
		}
	})

	run("testForgotIsGenericForAnUnknownEmail", func(t *testing.T, a *authCase) {
		authStatusIs(t, forgot(a, "nobody@example.com"), http.StatusAccepted)
		if n := resets(a); n != 0 {
			t.Fatalf("password reset events: %d", n)
		}
	})

	run("testResetChangesThePasswordAndRevokesEverySession", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		_, secret := a.login(authEmail, authPassword)
		authStatusIs(t, reset(a, requestReset(t, a), authNewPassword), http.StatusOK)
		if len(authEventsOf[event.PasswordChanged](a.srv)) == 0 {
			t.Fatal("no password changed event")
		}
		authStatusIs(t, refresh(a, secret), http.StatusUnauthorized)
		authStatusIs(t, login(a, authNewPassword), http.StatusOK)
		authStatusIs(t, login(a, authPassword), http.StatusUnauthorized)
	})

	run("testResetRejectsAShortPasswordAndABadToken", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		secret := requestReset(t, a)
		authStatusIs(t, reset(a, secret, "short"), http.StatusUnprocessableEntity)
		authStatusIs(t, reset(a, "not-a-token", authNewPassword), http.StatusUnauthorized)
	})

	run("testAResetTokenCannotBeReplayed", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		secret := requestReset(t, a)
		authStatusIs(t, reset(a, secret, authNewPassword), http.StatusOK)
		authStatusIs(t, reset(a, secret, "yet another passphrase"), http.StatusUnauthorized)
	})

	run("testForgotIsGenericForADisabledUser", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		a.updateUser(authEmail, func(u *model.User) { u.Status = model.UserStatusDisabled })
		authStatusIs(t, forgot(a, authEmail), http.StatusAccepted)
		if n := resets(a); n != 0 {
			t.Fatalf("password reset events: %d", n)
		}
	})

	run("testChangeKeepsTheCurrentSessionAndRevokesTheRest", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, current := a.login(authEmail, authPassword)
		_, other := a.login(authEmail, authPassword)
		authStatusIs(t, change(a, access, authPassword, authNewPassword), http.StatusOK)
		authStatusIs(t, refresh(a, current), http.StatusOK)
		authStatusIs(t, refresh(a, other), http.StatusUnauthorized)
		authStatusIs(t, login(a, authNewPassword), http.StatusOK)
	})

	run("testChangeRejectsAWrongCurrentPasswordAndAWeakNewOne", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, _ := a.login(authEmail, authPassword)
		authStatusIs(t, change(a, access, "wrong-password", authNewPassword), http.StatusForbidden)
		authStatusIs(t, change(a, access, authPassword, "short"), http.StatusUnprocessableEntity)
	})

	run("testChangeRequiresAuthentication", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/password/change", map[string]any{"current_password": authPassword, "new_password": authNewPassword}), http.StatusUnauthorized)
	})

	run("testMeReturnsTheIdentity", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, _ := a.login(authEmail, authPassword)
		resp := a.c.Get("/auth/me", contracttest.Bearer(access))
		authStatusIs(t, resp, http.StatusOK)
		data := contracttest.JSON(t, resp)["data"].(map[string]any)
		_, orgsOK := data["orgs"].([]any)
		_, rolesOK := data["roles"].([]any)
		if data["email"] != authEmail || data["email_verified"] != true || !orgsOK || !rolesOK {
			t.Fatalf("me: %v", data)
		}
	})

	run("testMeRequiresAuthentication", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Get("/auth/me"), http.StatusUnauthorized)
	})
}
