package httpapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/model"
)

func TestLoginEndpoint(t *testing.T) {
	const class = "LoginEndpointTest"
	run := func(name string, f func(t *testing.T, a *authCase)) {
		t.Run(name, func(t *testing.T) { f(t, authNew(t, class, name)) })
	}
	creds := func(password string) map[string]any { return map[string]any{"email": authEmail, "password": password} }
	longAgo := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	run("testValidLoginIssuesAVerifiableTokenPair", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		resp := a.c.Post("/auth/login", creds(authPassword))
		authStatusIs(t, resp, http.StatusOK)
		data := contracttest.JSON(t, resp)["data"].(map[string]any)
		if data["access_token"] == "" || data["refresh_token"] == "" || data["token_type"] != "Bearer" {
			t.Fatalf("token pair: %v", data)
		}
		user := data["user"].(map[string]any)
		if user["email"] != authEmail || user["email_verified"] != true {
			t.Fatalf("user: %v", user)
		}
		if n := len(authEventsOf[event.UserLoggedIn](a.srv)); n != 1 {
			t.Fatalf("user.logged_in events: %d", n)
		}
		if _, err := a.srv.Graph().Tokens().Parse(data["access_token"].(string)); err != nil {
			t.Fatalf("access token does not verify: %v", err)
		}
	})

	run("testLoginCarriesTheSanitizedUserAgentIntoTheEvent", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		authStatusIs(t, a.c.Post("/auth/login", creds(authPassword), contracttest.Header("User-Agent", "Browser/1.0 (Functional)")), http.StatusOK)
		logins := authEventsOf[event.UserLoggedIn](a.srv)
		if len(logins) != 1 || logins[0].UserAgent == nil || *logins[0].UserAgent != "Browser/1.0 (Functional)" {
			t.Fatalf("user.logged_in: %+v", logins)
		}
		if len(logins[0].AMR) != 1 || logins[0].AMR[0] != "pwd" {
			t.Fatalf("amr: %v", logins[0].AMR)
		}
	})

	run("testWrongPasswordIsAGeneric401", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		resp := a.c.Post("/auth/login", creds("not-the-password"))
		authStatusIs(t, resp, http.StatusUnauthorized)
		if e := contracttest.JSON(t, resp)["error"]; e != "invalid_credentials" {
			t.Fatalf("error: %v", e)
		}
	})

	run("testUnknownUserIsAGeneric401", func(t *testing.T, a *authCase) {
		resp := a.c.Post("/auth/login", map[string]any{"email": "nobody@example.com", "password": authPassword})
		authStatusIs(t, resp, http.StatusUnauthorized)
		if e := contracttest.JSON(t, resp)["error"]; e != "invalid_credentials" {
			t.Fatalf("error: %v", e)
		}
	})

	run("testUnverifiedEmailIsForbidden", func(t *testing.T, a *authCase) {
		a.c.Post("/auth/register", creds(authPassword))
		resp := a.c.Post("/auth/login", creds(authPassword))
		authStatusIs(t, resp, http.StatusForbidden)
		if e := contracttest.JSON(t, resp)["error"]; e != "email_unverified" {
			t.Fatalf("error: %v", e)
		}
	})

	run("testDisabledAccountIsForbidden", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		a.updateUser(authEmail, func(u *model.User) { u.Status = model.UserStatusDisabled })
		resp := a.c.Post("/auth/login", creds(authPassword))
		authStatusIs(t, resp, http.StatusForbidden)
		if e := contracttest.JSON(t, resp)["error"]; e != "account_disabled" {
			t.Fatalf("error: %v", e)
		}
	})

	run("testRequiresEmailAndPassword", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/login", map[string]any{"email": authEmail}), http.StatusUnprocessableEntity)
	})

	run("testSuccessfulLoginStampsLastLoginAndClearsFailures", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		a.c.Post("/auth/login", creds("wrong"))
		a.c.Post("/auth/login", creds("wrong"))
		authStatusIs(t, a.c.Post("/auth/login", creds(authPassword)), http.StatusOK)
		u := a.user(authEmail)
		if u.FailedLoginCount != 0 || u.FailedLoginAt != nil || u.LastLoginAt == nil || u.LockedUntil != nil {
			t.Fatalf("user after success: %+v", u)
		}
	})

	run("testRepeatedFailuresLockTheAccount", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		for range 5 {
			a.c.Post("/auth/login", creds("wrong"))
		}
		if len(authEventsOf[event.UserLocked](a.srv)) == 0 {
			t.Fatal("no user.locked event")
		}
		authStatusIs(t, a.c.Post("/auth/login", creds(authPassword)), http.StatusUnauthorized)
	})

	run("testLockAutoExpires", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		for range 5 {
			a.c.Post("/auth/login", creds("wrong"))
		}
		if a.user(authEmail).LockedUntil == nil {
			t.Fatal("account not locked")
		}
		a.updateUser(authEmail, func(u *model.User) { u.LockedUntil = &longAgo })
		authStatusIs(t, a.c.Post("/auth/login", creds(authPassword)), http.StatusOK)
		u := a.user(authEmail)
		if u.LockedUntil != nil || u.FailedLoginCount != 0 || u.FailedLoginAt != nil {
			t.Fatalf("lock state not cleared: %+v", u)
		}
	})

	run("testFailuresOutsideTheWindowDoNotAccumulateToALock", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		for range 4 {
			a.c.Post("/auth/login", creds("wrong"))
		}
		if n := a.user(authEmail).FailedLoginCount; n != 4 {
			t.Fatalf("failed logins: %d", n)
		}
		a.updateUser(authEmail, func(u *model.User) { u.FailedLoginAt = &longAgo })
		a.c.Post("/auth/login", creds("wrong"))
		u := a.user(authEmail)
		if u.FailedLoginCount != 1 || u.LockedUntil != nil {
			t.Fatalf("stale streak not reset: %+v", u)
		}
		authStatusIs(t, a.c.Post("/auth/login", creds(authPassword)), http.StatusOK)
	})

	run("testFailedLoginsAgainstADisabledAccountNeverReEnableIt", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		a.updateUser(authEmail, func(u *model.User) { u.Status = model.UserStatusDisabled })
		for range 5 {
			authStatusIs(t, a.c.Post("/auth/login", creds("wrong")), http.StatusUnauthorized)
		}
		u := a.user(authEmail)
		if u.Status != model.UserStatusDisabled || u.FailedLoginCount != 0 || u.LockedUntil != nil {
			t.Fatalf("disabled account entered the lockout lifecycle: %+v", u)
		}
		authStatusIs(t, a.c.Post("/auth/login", creds(authPassword)), http.StatusForbidden)
	})

	run("testUnknownUserAndWrongPasswordAreIndistinguishable", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		wrong := a.c.Post("/auth/login", creds("not-the-password"))
		unknown := a.c.Post("/auth/login", map[string]any{"email": "nobody@example.com", "password": authPassword})
		authStatusIs(t, wrong, http.StatusUnauthorized)
		authStatusIs(t, unknown, http.StatusUnauthorized)
		w, u := contracttest.JSON(t, wrong)["error"], contracttest.JSON(t, unknown)["error"]
		if w != "invalid_credentials" || w != u {
			t.Fatalf("errors differ: %v vs %v", w, u)
		}
	})
}
