package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
)

// Port of MemberSuspensionEndpointsTest: PATCH /orgs/{id}/members/{userId} suspends or
// reactivates a member; suspension revokes the member's org-scoped sessions at once and leaves
// their other sessions alone, under the owner-protection and last-active-owner invariants.
func TestMemberSuspensionEndpoints(t *testing.T) {
	const founder = "founder@example.com"
	suspend := map[string]any{"status": "suspended"}
	orgRun(t, "MemberSuspensionEndpointsTest", map[string]func(*orgCase){
		"testSuspensionRevokesTheMembersOrgScopedSession": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			member := o.memJoin(org, "member@example.com", "member")

			resp := o.c.Patch("/orgs/"+org+"/members/"+member.userID, suspend, contracttest.Bearer(owner))
			o.status(resp, http.StatusOK)
			o.equal(o.data(resp)["status"], "suspended", "status")
			o.equal(o.member(org, member.userID, owner)["status"], "suspended", "listed status")

			// The member's session was re-scoped to the org by switch-org, so it is revoked.
			o.status(o.memRefresh(member.refresh), http.StatusUnauthorized)
		},
		"testSuspensionLeavesSessionsOfOtherOrgsAlone": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			member := o.memJoin(org, "member@example.com", "member")
			// A second session that never switched into the org keeps its org-less context.
			unscoped := o.login("member@example.com")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+member.userID, suspend, contracttest.Bearer(owner)), http.StatusOK)

			o.status(o.memRefresh(member.refresh), http.StatusUnauthorized)
			o.status(o.memRefresh(unscoped.refresh), http.StatusOK)
		},
		"testSuspendedMemberCannotSwitchIntoTheOrgUntilReactivated": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			member := o.memJoin(org, "member@example.com", "member")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+member.userID, suspend, contracttest.Bearer(owner)), http.StatusOK)

			fresh := o.login("member@example.com")
			switchBody := map[string]any{"organization_id": org}
			o.status(o.c.Post("/auth/switch-org", switchBody, contracttest.Bearer(fresh.access)), http.StatusForbidden)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+member.userID, map[string]any{"status": "active"}, contracttest.Bearer(owner)), http.StatusOK)
			o.equal(o.member(org, member.userID, owner)["status"], "active", "listed status")
			o.status(o.c.Post("/auth/switch-org", switchBody, contracttest.Bearer(fresh.access)), http.StatusOK)
		},
		"testSuspendedMembersExistingAccessTokenIsDeniedImmediately": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			admin := o.memJoin(org, "admin@example.com", "admin")

			o.status(o.c.Get("/orgs/"+org+"/members", contracttest.Bearer(admin.scoped)), http.StatusOK)
			o.status(o.c.Patch("/orgs/"+org+"/members/"+admin.userID, suspend, contracttest.Bearer(owner)), http.StatusOK)

			// The Gate re-resolves authority on every request: the live access token loses the org.
			o.status(o.c.Get("/orgs/"+org+"/members", contracttest.Bearer(admin.scoped)), http.StatusForbidden)
		},
		"testAnOwnerCanSuspendThemselvesWhenAnotherOwnerRemains": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			o.memJoin(org, "cofounder@example.com", "owner")
			self := o.userID(founder)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+self, suspend, contracttest.Bearer(owner)), http.StatusOK)
			o.status(o.c.Get("/orgs/"+org+"/members", contracttest.Bearer(owner)), http.StatusForbidden)
		},
		"testAdminCannotSuspendAnOwner": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			owner := o.userID(founder)
			admin := o.memJoin(org, "admin@example.com", "admin")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+owner, suspend, contracttest.Bearer(admin.scoped)), http.StatusForbidden)
		},
		"testCannotSuspendTheLastActiveOwner": func(o *orgCase) {
			org, token, _ := o.orgOwnedBy(founder)
			owner := o.userID(founder)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+owner, suspend, contracttest.Bearer(token)), http.StatusConflict)
		},
		"testAnOwnerCanBeSuspendedWhenAnotherActiveOwnerRemains": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			second := o.memJoin(org, "cofounder@example.com", "owner")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+second.userID, suspend, contracttest.Bearer(owner)), http.StatusOK)
		},
		"testRejectsAnUnknownStatus": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			member := o.memJoin(org, "member@example.com", "member")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+member.userID, map[string]any{"status": "banned"}, contracttest.Bearer(owner)), http.StatusUnprocessableEntity)
			o.status(o.c.Patch("/orgs/"+org+"/members/"+member.userID, map[string]any{}, contracttest.Bearer(owner)), http.StatusUnprocessableEntity)
		},
		"testPlainMemberLacksPermissionToSuspend": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			member := o.memJoin(org, "member@example.com", "member")
			target := o.memJoin(org, "target@example.com", "member")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+target.userID, suspend, contracttest.Bearer(member.scoped)), http.StatusForbidden)
		},
		"testCannotSuspendMembersOfAnInactiveOrg": func(o *orgCase) {
			_, acme, session := o.orgOwnedBy(founder)
			globex := o.createOrg("Globex", session.access) // owns Globex too, but is scoped to Acme
			target := repository.NewID()
			o.seedMember(globex, target, "member", model.MembershipStatusActive)

			o.status(o.c.Patch("/orgs/"+globex+"/members/"+target, suspend, contracttest.Bearer(acme)), http.StatusForbidden)
		},
		"testUnknownMemberIsNotFound": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+repository.NewID(), suspend, contracttest.Bearer(owner)), http.StatusNotFound)
		},
	})
}

// memJoined is a member seeded into an organization with a session switched into it.
type memJoined struct{ userID, access, refresh, scoped string }

// memJoin logs email in, seeds them as an active roleSlug member of org and switches their session
// into it, as after a real invitation acceptance.
func (o *orgCase) memJoin(org, email, roleSlug string) memJoined {
	o.t.Helper()
	session := o.login(email)
	userID := o.userID(email)
	o.seedMember(org, userID, roleSlug, model.MembershipStatusActive)
	return memJoined{userID: userID, access: session.access, refresh: session.refresh, scoped: o.switchOrg(session.access, org)}
}

// memRefresh exchanges a refresh token.
func (o *orgCase) memRefresh(refresh string) *http.Response {
	o.t.Helper()
	return o.c.Post("/auth/token/refresh", map[string]any{"refresh_token": refresh})
}
