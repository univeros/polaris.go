package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/repository"
)

// Port of UserAdminEndpointsTest: GET/PATCH/DELETE /users/{id} (self or admin) and
// POST /users/{id}/disable|enable (users.manage, held only by superadmins). Disabling revokes the
// target's sessions and blocks login; deletion anonymizes the account, keeping a tombstone row.
func TestUserAdminEndpoints(t *testing.T) {
	const target = "target@example.com"
	orgRun(t, "UserAdminEndpointsTest", map[string]func(*orgCase){
		"testUserReadsAndUpdatesTheirOwnProfile": func(o *orgCase) {
			session := o.login("me@example.com")
			id := o.userID("me@example.com")

			read := o.data(o.c.Get("/users/"+id, contracttest.Bearer(session.access)))
			o.equal(read["email"], "me@example.com", "email")
			o.equal(read["status"], "active", "status")

			o.status(o.c.Patch("/users/"+id, map[string]any{"display_name": "Tony"}, contracttest.Bearer(session.access)), http.StatusOK)
			o.equal(o.data(o.c.Get("/users/"+id, contracttest.Bearer(session.access)))["display_name"], "Tony", "display_name")
		},
		"testPlainUserCannotReadOrUpdateAnotherUser": func(o *orgCase) {
			alice := o.login("alice@example.com")
			o.login("bob@example.com")
			bob := o.userID("bob@example.com")

			o.status(o.c.Get("/users/"+bob, contracttest.Bearer(alice.access)), http.StatusForbidden)
			o.status(o.c.Patch("/users/"+bob, map[string]any{"display_name": "Hacked"}, contracttest.Bearer(alice.access)), http.StatusForbidden)
			o.status(o.c.Delete("/users/"+bob, contracttest.Bearer(alice.access)), http.StatusForbidden)
		},
		"testSuperadminCanReadAndUpdateAnyUser": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			o.login(target)
			id := o.userID(target)

			o.equal(o.data(o.c.Get("/users/"+id, contracttest.Bearer(admin)))["email"], target, "email")

			o.status(o.c.Patch("/users/"+id, map[string]any{"display_name": "Renamed"}, contracttest.Bearer(admin)), http.StatusOK)
			o.equal(o.data(o.c.Get("/users/"+id, contracttest.Bearer(admin)))["display_name"], "Renamed", "display_name")
		},
		"testDisableRevokesSessionsAndBlocksLogin": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			session := o.login(target)
			id := o.userID(target)

			o.status(o.c.Post("/users/"+id+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusOK)

			o.equal(o.data(o.c.Get("/users/"+id, contracttest.Bearer(admin)))["status"], "disabled", "status")
			// Existing sessions die immediately…
			o.status(o.c.Post("/auth/token/refresh", map[string]any{"refresh_token": session.refresh}), http.StatusUnauthorized)
			// …and new logins are rejected.
			o.status(o.c.Post("/auth/login", map[string]any{"email": target, "password": orgPassword}), http.StatusForbidden)
		},
		"testEnableRestoresAccess": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			o.login(target)
			id := o.userID(target)

			o.status(o.c.Post("/users/"+id+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusOK)
			o.status(o.c.Post("/users/"+id+"/enable", map[string]any{}, contracttest.Bearer(admin)), http.StatusOK)

			o.equal(o.data(o.c.Get("/users/"+id, contracttest.Bearer(admin)))["status"], "active", "status")
			o.status(o.c.Post("/auth/login", map[string]any{"email": target, "password": orgPassword}), http.StatusOK)
		},
		"testAdminCannotDisableThemselves": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			id := o.userID("operator@example.com")

			o.status(o.c.Post("/users/"+id+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusConflict)
		},
		"testPlainUserLacksPermissionToDisableOrEnable": func(o *orgCase) {
			alice := o.login("alice@example.com")
			o.login("bob@example.com")
			bob := o.userID("bob@example.com")

			o.status(o.c.Post("/users/"+bob+"/disable", map[string]any{}, contracttest.Bearer(alice.access)), http.StatusForbidden)
			o.status(o.c.Post("/users/"+bob+"/enable", map[string]any{}, contracttest.Bearer(alice.access)), http.StatusForbidden)
			// Not even on themselves: disable/enable is admin tooling.
			aliceID := o.userID("alice@example.com")
			o.status(o.c.Post("/users/"+aliceID+"/disable", map[string]any{}, contracttest.Bearer(alice.access)), http.StatusForbidden)
		},
		"testADisabledAdminsLiveTokenLosesAllAuthorityImmediately": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			second := o.usrSuperadmin("operator2@example.com", "Root Two")
			adminID := o.userID("operator@example.com")

			o.status(o.c.Post("/users/"+adminID+"/disable", map[string]any{}, contracttest.Bearer(second)), http.StatusOK)

			// The disabled admin's live token is powerless: authority is re-resolved per request.
			secondID := o.userID("operator2@example.com")
			o.status(o.c.Post("/users/"+adminID+"/enable", map[string]any{}, contracttest.Bearer(admin)), http.StatusForbidden)
			o.status(o.c.Post("/users/"+secondID+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusForbidden)
		},
		"testDisablingTwiceEmitsASingleEvent": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			o.login(target)
			id := o.userID(target)

			o.status(o.c.Post("/users/"+id+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusOK)
			o.status(o.c.Post("/users/"+id+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusOK)

			o.equal(len(orgEventsOf[event.UserDisabled](o.srv)), 1, "user.disabled events")
		},
		"testATombstoneCannotBeReEnabled": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			o.login(target)
			id := o.userID(target)

			o.status(o.c.Delete("/users/"+id, contracttest.Bearer(admin)), http.StatusOK)
			o.status(o.c.Post("/users/"+id+"/enable", map[string]any{}, contracttest.Bearer(admin)), http.StatusConflict)
		},
		"testNonAdminProbingAnUnknownIdGetsForbiddenNotNotFound": func(o *orgCase) {
			alice := o.login("alice@example.com")
			unknown := repository.NewID()

			// 403 before existence is consulted: a non-admin learns nothing about which ids exist.
			o.status(o.c.Get("/users/"+unknown, contracttest.Bearer(alice.access)), http.StatusForbidden)
			o.status(o.c.Delete("/users/"+unknown, contracttest.Bearer(alice.access)), http.StatusForbidden)
		},
		"testSelfDeleteAnonymizesAndKillsTheAccount": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			session := o.login("leaving@example.com")
			id := o.userID("leaving@example.com")

			o.status(o.c.Delete("/users/"+id, contracttest.Bearer(session.access)), http.StatusOK)

			// The row survives as a tombstone: anonymized email, nulled profile, disabled.
			read := o.data(o.c.Get("/users/"+id, contracttest.Bearer(admin)))
			email, _ := read["email"].(string)
			if strings.Contains(email, "leaving@example.com") || !strings.Contains(email, "@deleted.invalid") {
				o.t.Fatalf("email not anonymized: %q", email)
			}
			if name, ok := read["display_name"]; !ok || name != nil {
				o.t.Fatalf("display_name = %v (present %v), want null", name, ok)
			}
			o.equal(read["status"], "disabled", "status")

			// Sessions are dead and the credentials are gone.
			o.status(o.c.Post("/auth/token/refresh", map[string]any{"refresh_token": session.refresh}), http.StatusUnauthorized)
			o.status(o.c.Post("/auth/login", map[string]any{"email": "leaving@example.com", "password": orgPassword}), http.StatusUnauthorized)
		},
		"testAdminCanDeleteAUser": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			o.login(target)
			id := o.userID(target)

			o.status(o.c.Delete("/users/"+id, contracttest.Bearer(admin)), http.StatusOK)
			email, _ := o.data(o.c.Get("/users/"+id, contracttest.Bearer(admin)))["email"].(string)
			if !strings.Contains(email, "@deleted.invalid") {
				o.t.Fatalf("email not anonymized: %q", email)
			}
		},
		"testUnknownUserIsNotFoundForAdmins": func(o *orgCase) {
			admin := o.usrSuperadmin("operator@example.com", "Root")
			unknown := repository.NewID()

			o.status(o.c.Get("/users/"+unknown, contracttest.Bearer(admin)), http.StatusNotFound)
			o.status(o.c.Patch("/users/"+unknown, map[string]any{"display_name": "X"}, contracttest.Bearer(admin)), http.StatusNotFound)
			o.status(o.c.Post("/users/"+unknown+"/disable", map[string]any{}, contracttest.Bearer(admin)), http.StatusNotFound)
			o.status(o.c.Delete("/users/"+unknown, contracttest.Bearer(admin)), http.StatusNotFound)
		},
		"testRejectsBadProfileInput": func(o *orgCase) {
			session := o.login("me@example.com")
			id := o.userID("me@example.com")

			o.status(o.c.Patch("/users/"+id, map[string]any{"display_name": strings.Repeat("x", 121)}, contracttest.Bearer(session.access)), http.StatusUnprocessableEntity)
		},
		"testRequiresAuthentication": func(o *orgCase) {
			id := repository.NewID()

			o.status(o.c.Get("/users/"+id), http.StatusUnauthorized)
			o.status(o.c.Post("/users/"+id+"/disable", map[string]any{}), http.StatusUnauthorized)
		},
	})
}

// usrSuperadmin logs email in, creates orgName, links that membership to the global superadmin
// role and returns the login's access token (authority is re-resolved per request, so the token
// minted before the link works).
func (o *orgCase) usrSuperadmin(email, orgName string) string {
	o.t.Helper()
	session := o.login(email)
	o.createOrg(orgName, session.access)
	o.grantSuperadmin(o.userID(email))
	return session.access
}
