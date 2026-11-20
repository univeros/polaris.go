package httpapi_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/repository"
)

// Port of OrganizationLifecycleEndpointsTest: PATCH /orgs/{id} (org.update) and DELETE /orgs/{id}
// (org.delete, step-up), a soft delete that strips every member's authority in the organization,
// hides it from listings and blocks switching into it.
func TestOrganizationLifecycleEndpoints(t *testing.T) {
	const founder = "founder@example.com"
	rename := func(o *orgCase, org, name, token string) *http.Response {
		o.t.Helper()
		return o.c.Patch("/orgs/"+org, map[string]any{"name": name}, contracttest.Bearer(token))
	}
	remove := func(o *orgCase, org, token string) *http.Response {
		o.t.Helper()
		return o.c.Delete("/orgs/"+org, contracttest.Bearer(token))
	}
	deleted := func(o *orgCase) int { return len(orgEventsOf[event.OrganizationDeleted](o.srv)) }

	orgRun(t, "OrganizationLifecycleEndpointsTest", map[string]func(*orgCase){
		"testOwnerRenamesTheOrganization": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			resp := rename(o, org, "Acme Worldwide", owner)
			o.status(resp, http.StatusOK)
			o.equal(o.data(resp)["name"], "Acme Worldwide", "name")

			o.equal(o.data(o.c.Get("/orgs/"+org, contracttest.Bearer(owner)))["name"], "Acme Worldwide", "name read back")
		},
		"testAdminCanUpdateButNotDelete": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			admin := o.seedActiveMember(org, "admin@example.com", "admin")

			o.status(rename(o, org, "Renamed by admin", admin), http.StatusOK)
			o.status(remove(o, org, admin), http.StatusForbidden)
		},
		"testPlainMemberCanNeitherUpdateNorDelete": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			member := o.seedActiveMember(org, "member@example.com", "member")

			o.status(rename(o, org, "X", member), http.StatusForbidden)
			o.status(remove(o, org, member), http.StatusForbidden)
		},
		"testOwnerSoftDeletesTheOrganization": func(o *orgCase) {
			org, owner, session := o.orgOwnedBy(founder)

			o.status(remove(o, org, owner), http.StatusOK)
			o.equal(deleted(o), 1, "org.deleted events")

			// The owner's scoped token is powerless, the organization is unlisted and unswitchable.
			o.status(o.c.Get("/orgs/"+org, contracttest.Bearer(owner)), http.StatusForbidden)
			o.equal(len(orgMaps(o.json(o.c.Get("/orgs", contracttest.Bearer(session.access)))["data"])), 0, "listed organizations")
			o.status(o.c.Post("/auth/switch-org", map[string]any{"organization_id": org}, contracttest.Bearer(session.access)), http.StatusNotFound)
		},
		"testDeleteRevokesMembersOrgScopedSessionsAndKillsPendingInvites": func(o *orgCase) {
			org, owner, session := o.orgOwnedBy(founder)
			o.c.Post("/orgs/"+org+"/invites", map[string]any{"email": "late@example.com", "role_slugs": []string{"member"}}, contracttest.Bearer(owner))
			inviteToken := o.lastInviteToken()

			o.status(remove(o, org, owner), http.StatusOK)

			// The owner's session was scoped to the organization: its refresh token is dead.
			o.status(o.c.Post("/auth/token/refresh", map[string]any{"refresh_token": session.refresh}), http.StatusUnauthorized)

			// A pre-deletion invitation must not create a membership in the dead organization.
			invitee := o.login("late@example.com")
			o.status(o.c.Post("/auth/invites/accept", map[string]any{"token": inviteToken}, contracttest.Bearer(invitee.access)), http.StatusBadRequest)
		},
		"testDeleteIsIdempotentAndEmitsOneEvent": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(remove(o, org, owner), http.StatusOK)
			// The second call comes from a now authority-less token.
			o.status(remove(o, org, owner), http.StatusForbidden)
			o.equal(deleted(o), 1, "org.deleted events")
		},
		"testSuperadminCanManageAnyOrgAndSeesRealNotFound": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			admin := orgInvSuperadmin(o)

			o.status(rename(o, org, "Operated", admin), http.StatusOK)

			// Superadmins pass the active-organization guard, so an unknown id is a genuine 404.
			unknown := repository.NewID()
			o.status(rename(o, unknown, "X", admin), http.StatusNotFound)
			o.status(remove(o, unknown, admin), http.StatusNotFound)
		},
		"testRejectsBadNames": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(rename(o, org, "  ", owner), http.StatusUnprocessableEntity)
			o.status(rename(o, org, strings.Repeat("x", 161), owner), http.StatusUnprocessableEntity)
			o.status(o.c.Patch("/orgs/"+org, map[string]any{}, contracttest.Bearer(owner)), http.StatusUnprocessableEntity)
		},
		"testCannotManageAnInactiveOrg": func(o *orgCase) {
			_, acmeToken, session := o.orgOwnedBy(founder)
			globex := o.createOrg("Globex", session.access) // owned too, but the token is scoped to Acme

			o.status(rename(o, globex, "X", acmeToken), http.StatusForbidden)
			o.status(remove(o, globex, acmeToken), http.StatusForbidden)
		},
	})
}

// orgInvSuperadmin logs operator@example.com in, gives them an organization linked to the global
// superadmin role and returns a token re-scoped to it (its roles claim carries the override).
func orgInvSuperadmin(o *orgCase) string {
	o.t.Helper()
	session := o.login("operator@example.com")
	root := o.createOrg("Root", session.access)
	o.grantSuperadmin(o.userID("operator@example.com"))
	return o.switchOrg(session.access, root)
}
