package orgs

import (
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// lastInviteToken returns the plaintext token of the last MemberInvited event.
func lastInviteToken(t *testing.T, f *fixture) string {
	t.Helper()
	invited := ofType[event.MemberInvited](f.events)
	if len(invited) == 0 {
		t.Fatal("no member.invited event")
	}
	return invited[len(invited)-1].InviteToken
}

// Service side of InvitationEndpointsTest::testInviteEmitsTokenAndShowsUpAsPending.
func TestInviteEmitsTheTokenAndStoresOnlyItsHash(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		inv, err := f.svc.Invite(ctx, owner, org, "  New.Hire@Example.COM ", []string{"member", "admin"})
		must(t, err)
		if inv.Email != "new.hire@example.com" || !slices.Equal(inv.RoleSlugs, []string{"member", "admin"}) ||
			!inv.ExpiresAt.Equal(t0.Add(7*24*time.Hour)) || inv.InvitedBy != owner || !inv.CreatedAt.Equal(t0) {
			t.Errorf("invitation = %+v", inv)
		}
		token := lastInviteToken(t, f)
		if raw, err := base64.RawURLEncoding.DecodeString(token); err != nil || len(raw) != 32 {
			t.Errorf("token %q is not 32 random bytes, base64url", token)
		}
		got := ofType[event.MemberInvited](f.events)[0]
		if got.OrganizationID != org || got.Email != "new.hire@example.com" || got.InvitedBy != owner {
			t.Errorf("event = %+v", got)
		}
		row, err := f.r.Invitations.Get(ctx, inv.ID)
		must(t, err)
		if row.TokenHash != f.pepper.Hash("org_invite", token) || row.TokenHash == token {
			t.Error("only the keyed hash (context org_invite) is stored")
		}
		if !slices.Equal(row.RoleIDs, []string{f.roleID(t, org, "member"), f.roleID(t, org, "admin")}) {
			t.Errorf("role ids = %v", row.RoleIDs)
		}

		pending, err := f.svc.ListInvitations(ctx, org)
		must(t, err)
		if len(pending) != 1 || pending[0].ID != inv.ID || !slices.Equal(pending[0].RoleSlugs, []string{"member", "admin"}) ||
			pending[0].InvitedBy != owner {
			t.Errorf("pending = %+v", pending)
		}
	})
}

// Service side of testAcceptCreatesAnActiveMembershipWithTheInvitedRoles.
func TestAcceptCreatesAnActiveMembershipWithTheInvitedRoles(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		_, err := f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"admin"})
		must(t, err)
		token := lastInviteToken(t, f)
		invitee := f.user(t, "Invitee@Example.com")
		f.clock.Advance(time.Hour)

		joined, err := f.svc.AcceptInvitation(ctx, invitee, token)
		must(t, err)
		if joined != org {
			t.Errorf("joined = %q", joined)
		}
		m, err := f.r.Memberships.ByUserAndOrganization(ctx, invitee, org)
		must(t, err)
		if m.Status != model.MembershipStatusActive || m.JoinedAt == nil || !m.JoinedAt.Equal(f.clock.Now()) ||
			m.InvitedBy == nil || *m.InvitedBy != owner {
			t.Errorf("membership = %+v", m)
		}
		if got := f.rolesOf(t, org, invitee); !slices.Equal(got, []string{"admin"}) {
			t.Errorf("roles = %v", got)
		}
		if got := ofType[event.MemberJoined](f.events); len(got) != 1 || got[0] != (event.MemberJoined{OrganizationID: org, UserID: invitee, Email: "Invitee@Example.com"}) {
			t.Errorf("events = %+v", got)
		}
		pending, err := f.svc.ListInvitations(ctx, org)
		must(t, err)
		if len(pending) != 0 {
			t.Error("an accepted invitation is not pending")
		}
		// Single use.
		_, err = f.svc.AcceptInvitation(ctx, invitee, token)
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)
	})
}

func TestAcceptActivatesAnInvitedMembershipAndAddsRoles(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		invitee := f.member(t, org, "invitee@example.com", model.MembershipStatusInvited, "member")
		custom, err := f.svc.CreateRole(ctx, owner, org, NewRole{Name: "Support", Slug: "support", PermissionKeys: []string{"org.read"}})
		must(t, err)
		_, err = f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"member", "admin", "support", "admin"})
		must(t, err)
		must(t, f.svc.DeleteRole(ctx, owner, org, custom.ID))

		_, err = f.svc.AcceptInvitation(ctx, invitee, lastInviteToken(t, f))
		must(t, err)
		if got := f.rolesOf(t, org, invitee); !slices.Equal(got, []string{"admin", "member"}) {
			t.Errorf("roles = %v; held roles kept, deleted ones skipped, duplicates once", got)
		}
		m, err := f.r.Memberships.ByUserAndOrganization(ctx, invitee, org)
		must(t, err)
		if m.Status != model.MembershipStatusActive || m.InvitedBy != nil {
			t.Errorf("membership = %+v", m)
		}
	})
}

// Service side of testAcceptRequiresAMatchingEmail, testAcceptRejectsUnknownAndConsumedTokens,
// testASuspensionCannotBeSidesteppedByInvitations and the org-deleted case.
func TestAcceptRefusals(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		orgID, owner := f.orgOwnedBy(t, "founder@example.com")
		_, err := f.svc.Invite(ctx, owner, orgID, "invitee@example.com", []string{"member"})
		must(t, err)
		token := lastInviteToken(t, f)

		_, err = f.svc.AcceptInvitation(ctx, f.user(t, "someone-else@example.com"), token)
		wantForbidden(t, err, MsgInvitationEmail)
		_, err = f.svc.AcceptInvitation(ctx, "no-such-user", token)
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)
		_, err = f.svc.AcceptInvitation(ctx, owner, "unknown-token")
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)

		// Issued before the suspension, it still cannot lift it.
		invitee := f.member(t, orgID, "invitee@example.com", model.MembershipStatusSuspended)
		_, err = f.svc.AcceptInvitation(ctx, invitee, token)
		wantForbidden(t, err, MsgOwnMembershipSuspend)
		_, err = f.svc.Invite(ctx, owner, orgID, "invitee@example.com", []string{"member"})
		wantRefusal(t, err, ErrConflict, MsgMemberSuspended)

		// An invitation into a deleted organization is dead.
		late := f.user(t, "late@example.com")
		_, err = f.svc.Invite(ctx, owner, orgID, "late@example.com", []string{"member"})
		must(t, err)
		lateToken := lastInviteToken(t, f)
		org, err := f.r.Organizations.Get(ctx, orgID)
		must(t, err)
		must(t, f.svc.DeleteOrganization(ctx, org, owner))
		_, err = f.svc.AcceptInvitation(ctx, late, lateToken)
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)
		if f.count(t, "auth_memberships", store.Criteria{"user_id": late}) != 0 {
			t.Error("no membership row in a deleted organization")
		}
		if len(ofType[event.MemberJoined](f.events)) != 0 {
			t.Error("a refused accept announced a join")
		}
	})
}

// Service side of testReInviteIsIdempotentAndRotatesTheToken.
func TestReInviteRotatesTheTokenOfTheOnePendingInvitation(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		first, err := f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"member"})
		must(t, err)
		oldToken := lastInviteToken(t, f)
		f.clock.Advance(time.Hour)
		second, err := f.svc.Invite(ctx, owner, org, "INVITEE@example.com", []string{"admin"})
		must(t, err)
		newToken := lastInviteToken(t, f)

		if second.ID != first.ID || newToken == oldToken || !second.ExpiresAt.Equal(f.clock.Now().Add(InvitationTTL)) ||
			!second.CreatedAt.Equal(t0) {
			t.Errorf("first = %+v, second = %+v", first, second)
		}
		if n := f.count(t, "auth_invitations", store.Criteria{"organization_id": org}); n != 1 {
			t.Errorf("invitations = %d; want one pending per email", n)
		}
		invitee := f.user(t, "invitee@example.com")
		_, err = f.svc.AcceptInvitation(ctx, invitee, oldToken)
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)
		_, err = f.svc.AcceptInvitation(ctx, invitee, newToken)
		must(t, err)
		if got := f.rolesOf(t, org, invitee); !slices.Equal(got, []string{"admin"}) {
			t.Errorf("roles = %v; the refresh carries the new roles", got)
		}
	})
}

// Service side of testCannotInviteAnActiveMember, testInviterCannotGrantRolesAboveTheirOwn and
// testRejectsUnknownRolesAndBadEmails.
func TestInviteRefusals(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")

		_, err := f.svc.Invite(ctx, owner, org, "ADMIN@example.com", []string{"member"})
		wantRefusal(t, err, ErrConflict, MsgAlreadyMember)
		_, err = f.svc.Invite(ctx, admin, org, "new@example.com", []string{"owner"})
		wantForbidden(t, err, authz.MsgEscalation)
		_, err = f.svc.Invite(ctx, owner, org, "new@example.com", []string{"member", "ghost"})
		wantRefusal(t, err, ErrInvalid, "Unknown role for this organization: ghost")
		_, err = f.svc.Invite(ctx, owner, org, "new@example.com", nil)
		wantRefusal(t, err, ErrInvalid, MsgRolesRequired)
		if f.count(t, "auth_invitations", nil) != 0 || len(ofType[event.MemberInvited](f.events)) != 0 {
			t.Error("a refused invitation left a row or an event")
		}
		// An invited (not yet active) member can be invited again.
		f.member(t, org, "invited@example.com", model.MembershipStatusInvited)
		_, err = f.svc.Invite(ctx, admin, org, "invited@example.com", []string{"member"})
		must(t, err)
	})
}

// Service side of testAnExpiredInvitationIsHiddenAndUnacceptableButRecyclable.
func TestAnExpiredInvitationIsHiddenUnacceptableAndRecycled(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		first, err := f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"member"})
		must(t, err)
		token := lastInviteToken(t, f)
		f.clock.Advance(InvitationTTL) // expires_at <= now: expired

		pending, err := f.svc.ListInvitations(ctx, org)
		must(t, err)
		if len(pending) != 0 {
			t.Errorf("pending = %+v", pending)
		}
		invitee := f.user(t, "invitee@example.com")
		_, err = f.svc.AcceptInvitation(ctx, invitee, token)
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)

		again, err := f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"member"})
		must(t, err)
		if again.ID != first.ID {
			t.Error("the expired row is recycled")
		}
		_, err = f.svc.AcceptInvitation(ctx, invitee, lastInviteToken(t, f))
		must(t, err)
	})
}

// Service side of testCannotRevokeAnotherOrgsInviteThroughYourOwnOrgPath, testRevokedInviteCannotBeAccepted
// and testRevokingAnUnknownInviteIsNotFound.
func TestRevokeInvitation(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		other, otherOwner := f.orgOwnedBy(t, "other@example.com")
		theirs, err := f.svc.Invite(ctx, otherOwner, other, "x@example.com", []string{"member"})
		must(t, err)
		wantRefusal(t, f.svc.RevokeInvitation(ctx, org, theirs.ID), ErrNotFound, MsgInvitationNotFound)
		wantRefusal(t, f.svc.RevokeInvitation(ctx, org, "unknown"), ErrNotFound, MsgInvitationNotFound)

		inv, err := f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"member"})
		must(t, err)
		token := lastInviteToken(t, f)
		must(t, f.svc.RevokeInvitation(ctx, org, inv.ID))
		_, err = f.svc.AcceptInvitation(ctx, f.user(t, "invitee@example.com"), token)
		wantRefusal(t, err, ErrInvalidInvitation, MsgInvalidInvitation)

		// An accepted invitation is not pending: it cannot be revoked.
		_, err = f.svc.Invite(ctx, otherOwner, other, "y@example.com", []string{"member"})
		must(t, err)
		accepted := lastInviteToken(t, f)
		_, err = f.svc.AcceptInvitation(ctx, f.user(t, "y@example.com"), accepted)
		must(t, err)
		invs, err := f.r.Invitations.ListByOrganizationAndEmail(ctx, other, "y@example.com")
		must(t, err)
		wantRefusal(t, f.svc.RevokeInvitation(ctx, other, invs[0].ID), ErrNotFound, MsgInvitationNotFound)
	})
}
