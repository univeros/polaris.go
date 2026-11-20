package httpapi_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

// Port of MembershipEndpointsTest: the member-management endpoints and their invariants (no
// privilege escalation, owners protected from non-owners, the last owner kept). Members beyond the
// creator are seeded directly.
func TestMembershipEndpoints(t *testing.T) {
	const founder = "founder@example.com"
	active := model.MembershipStatusActive
	orgRun(t, "MembershipEndpointsTest", map[string]func(*orgCase){
		"testListsMembersWithTheirRoles": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			o.seedMember(org, repository.NewID(), "member", active)

			list := o.members(org, owner)
			var roles []string
			for _, m := range list {
				roles = append(roles, orgStrs(m["roles"])...)
			}
			if len(list) != 2 || !slices.Contains(roles, "owner") || !slices.Contains(roles, "member") {
				o.t.Fatalf("members: %v", list)
			}
		},
		"testInvitedAndSuspendedEmailsAreGatedOnMembersInvite": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			memberToken := o.seedActiveMember(org, "member@example.com", "member")
			o.login("invited@example.com")
			invited := o.userID("invited@example.com")
			o.seedMember(org, invited, "member", model.MembershipStatusInvited)
			o.login("suspended@example.com")
			suspended := o.userID("suspended@example.com")
			o.seedMember(org, suspended, "member", model.MembershipStatusSuspended)

			// A plain members.read holder sees active members' emails only.
			emails := o.memEmails(org, memberToken)
			o.equal(emails[o.userID(founder)], founder, "founder email")
			o.equal(emails[invited], nil, "invited email")
			o.equal(emails[suspended], nil, "suspended email")

			// An owner holds members.invite and sees the full roster.
			emails = o.memEmails(org, owner)
			o.equal(emails[invited], "invited@example.com", "invited email")
			o.equal(emails[suspended], "suspended@example.com", "suspended email")
		},
		"testOwnerCanChangeAMembersRoles": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			target := repository.NewID()
			o.seedMember(org, target, "member", active)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+target+"/roles", map[string]any{"role_slugs": []string{"admin"}}, contracttest.Bearer(owner)), http.StatusOK)
			o.equal(o.rolesOf(org, target, owner), []string{"admin"}, "roles")
		},
		"testAdminCannotEscalateAMemberToOwner": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			admin := o.seedActiveMember(org, "admin@example.com", "admin")
			target := repository.NewID()
			o.seedMember(org, target, "member", active)

			// owner carries org.delete, which an admin does not hold.
			o.status(o.c.Patch("/orgs/"+org+"/members/"+target+"/roles", map[string]any{"role_slugs": []string{"owner"}}, contracttest.Bearer(admin)), http.StatusForbidden)
		},
		"testAdminCanGrantNonEscalatingRoles": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			admin := o.seedActiveMember(org, "admin@example.com", "admin")
			target := repository.NewID()
			o.seedMember(org, target, "member", active)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+target+"/roles", map[string]any{"role_slugs": []string{"admin"}}, contracttest.Bearer(admin)), http.StatusOK)
		},
		"testAdminCannotModifyAnOwner": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			owner := o.userID(founder)
			admin := o.seedActiveMember(org, "admin@example.com", "admin")

			o.status(o.c.Patch("/orgs/"+org+"/members/"+owner+"/roles", map[string]any{"role_slugs": []string{"member"}}, contracttest.Bearer(admin)), http.StatusForbidden)
		},
		"testCannotDemoteTheLastOwner": func(o *orgCase) {
			org, token, _ := o.orgOwnedBy(founder)
			owner := o.userID(founder)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+owner+"/roles", map[string]any{"role_slugs": []string{"member"}}, contracttest.Bearer(token)), http.StatusConflict)
		},
		"testCannotRemoveTheLastOwner": func(o *orgCase) {
			org, token, _ := o.orgOwnedBy(founder)
			owner := o.userID(founder)

			o.status(o.c.Delete("/orgs/"+org+"/members/"+owner, contracttest.Bearer(token)), http.StatusConflict)
		},
		"testOwnerCanRemoveANonOwnerMember": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			target := repository.NewID()
			o.seedMember(org, target, "member", active)

			o.status(o.c.Delete("/orgs/"+org+"/members/"+target, contracttest.Bearer(owner)), http.StatusOK)
			o.equal(len(o.members(org, owner)), 1, "members left")
		},
		"testCanDemoteAnOwnerWhenAnotherOwnerRemains": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			second := repository.NewID()
			o.seedMember(org, second, "owner", active)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+second+"/roles", map[string]any{"role_slugs": []string{"member"}}, contracttest.Bearer(owner)), http.StatusOK)
		},
		"testMemberLacksPermissionToManageMembers": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			member := o.seedActiveMember(org, "member@example.com", "member")
			target := repository.NewID()
			o.seedMember(org, target, "member", active)

			o.status(o.c.Patch("/orgs/"+org+"/members/"+target+"/roles", map[string]any{"role_slugs": []string{"member"}}, contracttest.Bearer(member)), http.StatusForbidden)
		},
		"testCannotManageMembersOfAnInactiveOrg": func(o *orgCase) {
			_, acme, session := o.orgOwnedBy(founder)
			globex := o.createOrg("Globex", session.access) // owns Globex too, but is scoped to Acme
			o.seedMember(globex, repository.NewID(), "member", active)

			o.status(o.c.Get("/orgs/"+globex+"/members", contracttest.Bearer(acme)), http.StatusForbidden)
		},
	})
}

// memEmails is org's roster as user id to email (nil when withheld).
func (o *orgCase) memEmails(org, token string) map[string]any {
	o.t.Helper()
	emails := map[string]any{}
	for _, m := range o.members(org, token) {
		if id, ok := m["user_id"].(string); ok {
			emails[id] = m["email"]
		}
	}
	return emails
}
