package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
)

func TestSessionEndpoints(t *testing.T) {
	const class = "SessionEndpointsTest"
	run := func(name string, f func(t *testing.T, a *authCase)) {
		t.Run(name, func(t *testing.T) { f(t, authNew(t, class, name)) })
	}
	refresh := func(a *authCase, secret string) *http.Response {
		return a.c.Post("/auth/token/refresh", map[string]any{"refresh_token": secret})
	}

	run("testRefreshRotatesAndDetectsReuseOfTheOldToken", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		_, first := a.login(authEmail, authPassword)
		access, rotated := authPair(t, refresh(a, first))
		if rotated == first || access == "" {
			t.Fatal("refresh did not rotate")
		}
		authStatusIs(t, refresh(a, first), http.StatusUnauthorized)
	})

	run("testRefreshRejectsUnknownTokenAndRequiresInput", func(t *testing.T, a *authCase) {
		authStatusIs(t, refresh(a, "not-a-token"), http.StatusUnauthorized)
		authStatusIs(t, a.c.Post("/auth/token/refresh", nil), http.StatusUnprocessableEntity)
	})

	run("testSessionsListFlagsTheCallingSession", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		first, _ := a.login(authEmail, authPassword)
		a.login(authEmail, authPassword)
		body := contracttest.JSON(t, a.c.Get("/auth/sessions", contracttest.Bearer(first)))
		sessions := body["data"].(map[string]any)["sessions"].([]any)
		if len(sessions) != 2 {
			t.Fatalf("sessions: %d", len(sessions))
		}
		var current []string
		for _, s := range sessions {
			if m := s.(map[string]any); m["current"] == true {
				current = append(current, m["id"].(string))
			}
		}
		if len(current) != 1 || current[0] != a.sidOf(first) {
			t.Fatalf("current sessions %v, want [%s]", current, a.sidOf(first))
		}
	})

	run("testLogoutRevokesTheCurrentSession", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, secret := a.login(authEmail, authPassword)
		authStatusIs(t, a.c.Post("/auth/logout", nil, contracttest.Bearer(access)), http.StatusOK)
		authStatusIs(t, refresh(a, secret), http.StatusUnauthorized)
		if n := len(authEventsOf[event.RefreshReuseDetected](a.srv)); n != 0 {
			t.Fatalf("refresh reuse events after logout: %d", n)
		}
	})

	run("testLogoutAllRevokesEverySession", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, first := a.login(authEmail, authPassword)
		_, second := a.login(authEmail, authPassword)
		authStatusIs(t, a.c.Post("/auth/logout-all", nil, contracttest.Bearer(access)), http.StatusOK)
		if n := len(authEventsOf[event.SessionsRevoked](a.srv)); n != 1 {
			t.Fatalf("sessions.revoked events: %d", n)
		}
		authStatusIs(t, refresh(a, first), http.StatusUnauthorized)
		authStatusIs(t, refresh(a, second), http.StatusUnauthorized)
	})

	run("testRevokeASpecificSession", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		keep, keepSecret := a.login(authEmail, authPassword)
		drop, dropSecret := a.login(authEmail, authPassword)
		authStatusIs(t, a.c.Delete("/auth/sessions/"+a.sidOf(drop), contracttest.Bearer(keep)), http.StatusOK)
		authStatusIs(t, refresh(a, dropSecret), http.StatusUnauthorized)
		authStatusIs(t, refresh(a, keepSecret), http.StatusOK)
	})

	run("testRevokingAnUnknownSessionIsNotFound", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, _ := a.login(authEmail, authPassword)
		authStatusIs(t, a.c.Delete("/auth/sessions/no-such-family", contracttest.Bearer(access)), http.StatusNotFound)
	})

	run("testProtectedEndpointsRequireAuthentication", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Post("/auth/logout", nil), http.StatusUnauthorized)
		authStatusIs(t, a.c.Post("/auth/logout-all", nil), http.StatusUnauthorized)
		authStatusIs(t, a.c.Get("/auth/sessions"), http.StatusUnauthorized)
	})
}
