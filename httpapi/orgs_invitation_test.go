package httpapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

// Port of InvitationEndpointsTest: POST/GET /orgs/{id}/invites, DELETE /orgs/{id}/invites/{inviteId}
// and POST /auth/invites/accept. The token travels only on the member.invited event; acceptance
// enforces the email match and grants exactly the invited roles; inviting refuses active members
// and escalation.
func TestInvitationEndpoints(t *testing.T) {
	const founder = "founder@example.com"
	invite := func(o *orgCase, org, email, token string, roles ...string) *http.Response {
		o.t.Helper()
		body := map[string]any{"email": email}
		if roles != nil {
			body["role_slugs"] = roles
		}
		return o.c.Post("/orgs/"+org+"/invites", body, contracttest.Bearer(token))
	}
	accept := func(o *orgCase, token, access string) *http.Response {
		o.t.Helper()
		return o.c.Post("/auth/invites/accept", map[string]any{"token": token}, contracttest.Bearer(access))
	}
	pending := func(o *orgCase, org, token string) []map[string]any {
		o.t.Helper()
		return orgMaps(o.json(o.c.Get("/orgs/"+org+"/invites", contracttest.Bearer(token)))["data"])
	}

	orgRun(t, "InvitationEndpointsTest", map[string]func(*orgCase){
		"testInviteEmitsTokenAndShowsUpAsPending": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(invite(o, org, "new@example.com", owner, "member"), http.StatusCreated)
			if o.lastInviteToken() == "" {
				o.t.Fatal("no invite token on member.invited")
			}

			list := pending(o, org, owner)
			o.equal(len(list), 1, "pending invitations")
			o.equal(list[0]["email"], "new@example.com", "email")
			o.equal(list[0]["role_slugs"], []string{"member"}, "role_slugs")
		},
		"testAcceptCreatesAnActiveMembershipWithTheInvitedRoles": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			invite(o, org, "new@example.com", owner, "admin")
			token := o.lastInviteToken()

			invitee := o.login("new@example.com")
			resp := accept(o, token, invitee.access)
			o.status(resp, http.StatusOK)
			o.equal(o.data(resp)["organization_id"], org, "organization_id")

			o.status(o.c.Post("/auth/switch-org", map[string]any{"organization_id": org}, contracttest.Bearer(invitee.access)), http.StatusOK)
			o.equal(o.rolesOf(org, o.userID("new@example.com"), owner), []string{"admin"}, "roles")

			o.equal(len(pending(o, org, owner)), 0, "pending invitations")
		},
		"testAcceptRequiresAMatchingEmail": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			invite(o, org, "right@example.com", owner, "member")
			token := o.lastInviteToken()

			wrong := o.login("wrong@example.com")
			o.status(accept(o, token, wrong.access), http.StatusForbidden)

			// The invitation survives a mismatched attempt.
			right := o.login("right@example.com")
			o.status(accept(o, token, right.access), http.StatusOK)
		},
		"testAcceptRejectsUnknownAndConsumedTokens": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			invite(o, org, "new@example.com", owner, "member")
			token := o.lastInviteToken()

			invitee := o.login("new@example.com")
			o.status(accept(o, "not-a-real-token", invitee.access), http.StatusBadRequest)
			o.status(accept(o, token, invitee.access), http.StatusOK)
			// Single use.
			o.status(accept(o, token, invitee.access), http.StatusBadRequest)
		},
		"testAcceptRequiresAuthentication": func(o *orgCase) {
			o.status(o.c.Post("/auth/invites/accept", map[string]any{"token": "whatever"}), http.StatusUnauthorized)
		},
		"testReInviteIsIdempotentAndRotatesTheToken": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			invite(o, org, "new@example.com", owner, "member")
			first := o.lastInviteToken()

			o.status(invite(o, org, "new@example.com", owner, "member"), http.StatusCreated)
			second := o.lastInviteToken()
			if first == second {
				o.t.Fatal("re-invite did not rotate the token")
			}

			o.equal(len(pending(o, org, owner)), 1, "pending invitations")
			invitee := o.login("new@example.com")
			o.status(accept(o, first, invitee.access), http.StatusBadRequest)
			o.status(accept(o, second, invitee.access), http.StatusOK)
		},
		"testCannotInviteAnActiveMember": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			o.login("member@example.com")
			o.seedMember(org, o.userID("member@example.com"), "member", model.MembershipStatusActive)

			o.status(invite(o, org, "member@example.com", owner, "member"), http.StatusConflict)
		},
		"testASuspensionCannotBeSidesteppedByInvitations": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			invite(o, org, "suspended@example.com", owner, "member")
			token := o.lastInviteToken()
			invitee := o.login("suspended@example.com")
			o.seedMember(org, o.userID("suspended@example.com"), "member", model.MembershipStatusSuspended)

			// Accepting must not lift the suspension, and a suspended member cannot be re-invited.
			o.status(accept(o, token, invitee.access), http.StatusForbidden)
			o.status(invite(o, org, "suspended@example.com", owner, "member"), http.StatusConflict)
		},
		"testAnExpiredInvitationIsHiddenAndUnacceptableButRecyclable": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			invite(o, org, "new@example.com", owner, "member")
			stale := o.lastInviteToken()

			_, err := o.srv.DB.Update(o.ctx, "auth_invitations", store.Criteria{"organization_id": org},
				store.Data{"expires_at": time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)})
			o.must(err)

			o.equal(len(pending(o, org, owner)), 0, "pending invitations")
			invitee := o.login("new@example.com")
			o.status(accept(o, stale, invitee.access), http.StatusBadRequest)

			// Re-inviting recycles the expired row with a fresh token and expiry.
			o.status(invite(o, org, "new@example.com", owner, "member"), http.StatusCreated)
			o.equal(len(pending(o, org, owner)), 1, "pending invitations")
			o.status(accept(o, o.lastInviteToken(), invitee.access), http.StatusOK)
		},
		"testCannotRevokeAnotherOrgsInviteThroughYourOwnOrgPath": func(o *orgCase) {
			acme, acmeToken, session := o.orgOwnedBy(founder)
			globex := o.createOrg("Globex", session.access)
			globexToken := o.switchOrg(session.access, globex)
			globexInvite, _ := o.data(invite(o, globex, "new@example.com", globexToken, "member"))["id"].(string)

			// A real invite id under another organization's path reads as unknown.
			o.status(o.c.Delete("/orgs/"+acme+"/invites/"+globexInvite, contracttest.Bearer(acmeToken)), http.StatusNotFound)
		},
		"testInviterCannotGrantRolesAboveTheirOwn": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			admin := o.seedActiveMember(org, "admin@example.com", "admin")

			// owner carries org.delete, which an admin does not hold.
			o.status(invite(o, org, "new@example.com", admin, "owner"), http.StatusForbidden)
			o.status(invite(o, org, "new@example.com", admin, "admin"), http.StatusCreated)
		},
		"testRejectsUnknownRolesAndBadEmails": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(invite(o, org, "new@example.com", owner, "ceo"), http.StatusUnprocessableEntity)
			o.status(invite(o, org, "not-an-email", owner, "member"), http.StatusUnprocessableEntity)
			o.status(invite(o, org, "new@example.com", owner), http.StatusUnprocessableEntity)
		},
		"testPlainMemberLacksPermissionToInvite": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			member := o.seedActiveMember(org, "member@example.com", "member")

			o.status(invite(o, org, "new@example.com", member, "member"), http.StatusForbidden)
			o.status(o.c.Get("/orgs/"+org+"/invites", contracttest.Bearer(member)), http.StatusForbidden)
		},
		"testCannotManageInvitesOfAnInactiveOrg": func(o *orgCase) {
			_, acmeToken, session := o.orgOwnedBy(founder)
			globex := o.createOrg("Globex", session.access) // owned too, but the token is scoped to Acme

			o.status(invite(o, globex, "new@example.com", acmeToken, "member"), http.StatusForbidden)
			o.status(o.c.Get("/orgs/"+globex+"/invites", contracttest.Bearer(acmeToken)), http.StatusForbidden)
		},
		"testRevokedInviteCannotBeAccepted": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			inviteID, _ := o.data(invite(o, org, "new@example.com", owner, "member"))["id"].(string)
			token := o.lastInviteToken()

			o.status(o.c.Delete("/orgs/"+org+"/invites/"+inviteID, contracttest.Bearer(owner)), http.StatusOK)
			o.equal(len(pending(o, org, owner)), 0, "pending invitations")

			invitee := o.login("new@example.com")
			o.status(accept(o, token, invitee.access), http.StatusBadRequest)
		},
		"testRevokingAnUnknownInviteIsNotFound": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(o.c.Delete("/orgs/"+org+"/invites/"+repository.NewID(), contracttest.Bearer(owner)), http.StatusNotFound)
		},
	})
}
