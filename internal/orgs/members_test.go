package orgs

import (
	"errors"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// Service side of MembershipEndpointsTest::testListsMembersWithTheirRoles and
// testInvitedAndSuspendedEmailsAreGatedOnMembersInvite.
func TestListMembersWithRolesAndGatedEmails(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		f.member(t, org, "invited@example.com", model.MembershipStatusInvited, "member")
		f.member(t, org, "suspended@example.com", model.MembershipStatusSuspended, "admin", "member")
		f.join(t, org, "ghost-user", model.MembershipStatusActive) // user row gone

		emails := func(withPending bool) map[string]*string {
			members, err := f.svc.ListMembers(ctx, org, withPending)
			must(t, err)
			if len(members) != 4 {
				t.Fatalf("members = %+v", members)
			}
			out := map[string]*string{}
			for _, m := range members {
				out[m.Status+":"+deref(m.DisplayName)] = m.Email
				if m.UserID == owner && (len(m.Roles) != 1 || m.Roles[0] != "owner") {
					t.Errorf("owner roles = %v", m.Roles)
				}
				if m.Roles == nil {
					t.Error("roles must be a list, never nil")
				}
			}
			return out
		}
		got := emails(false)
		if deref(got["active:founder@example.com"]) != "founder@example.com" {
			t.Error("an active member's email is listed")
		}
		if got["invited:invited@example.com"] != nil || got["suspended:suspended@example.com"] != nil || got["active:"] != nil {
			t.Errorf("withheld emails leaked: %v", got)
		}
		got = emails(true)
		if deref(got["invited:invited@example.com"]) != "invited@example.com" || deref(got["suspended:suspended@example.com"]) != "suspended@example.com" {
			t.Error("members.invite holders see pending emails")
		}
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Service side of testOwnerCanChangeAMembersRoles and testAdminCanGrantNonEscalatingRoles.
func TestChangeRolesReplacesTheSetAndAnnouncesIt(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")

		must(t, f.svc.ChangeMemberRoles(ctx, owner, org, member, []string{"member", "admin"}))
		if got := f.rolesOf(t, org, member); !slices.Equal(got, []string{"admin", "member"}) {
			t.Errorf("roles = %v", got)
		}
		must(t, f.svc.ChangeMemberRoles(ctx, admin, org, member, []string{"member"}))
		if got := f.rolesOf(t, org, member); !slices.Equal(got, []string{"member"}) {
			t.Errorf("roles = %v", got)
		}
		roles := []string{"member", "member"}
		must(t, f.svc.ChangeMemberRoles(ctx, owner, org, member, roles))
		roles[0] = "mutated"
		events := ofType[event.MemberRolesChanged](f.events)
		want := event.MemberRolesChanged{OrganizationID: org, UserID: member, RoleSlugs: []string{"member", "member"}, ActorUserID: owner}
		if len(events) != 3 || !slices.Equal(events[2].RoleSlugs, want.RoleSlugs) || events[2].ActorUserID != owner ||
			events[2].UserID != member || events[2].OrganizationID != org {
			t.Errorf("events = %+v; want last %+v (the slugs as requested, copied)", events, want)
		}
		must(t, f.svc.ChangeMemberRoles(ctx, owner, org, member, nil))
		if got := f.rolesOf(t, org, member); len(got) != 0 {
			t.Errorf("roles = %v; want none", got)
		}
	})
}

// Service side of testAdminCannotEscalateAMemberToOwner, testAdminCannotModifyAnOwner,
// testCannotDemoteTheLastOwner and testCanDemoteAnOwnerWhenAnotherOwnerRemains.
func TestChangeRolesInvariants(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")

		wantForbidden(t, f.svc.ChangeMemberRoles(ctx, admin, org, member, []string{"owner"}), authz.MsgEscalation)
		wantForbidden(t, f.svc.ChangeMemberRoles(ctx, admin, org, owner, []string{"member"}), MsgOwnerModify)
		wantRefusal(t, f.svc.ChangeMemberRoles(ctx, owner, org, owner, []string{"admin"}), ErrConflict, MsgLastOwner)
		wantRefusal(t, f.svc.ChangeMemberRoles(ctx, owner, org, member, []string{"nope"}), ErrInvalid, "Unknown role for this organization: nope")
		wantRefusal(t, f.svc.ChangeMemberRoles(ctx, owner, org, "stranger", []string{"member"}), ErrNotFound, MsgMemberNotFound)
		if got := f.rolesOf(t, org, owner); !slices.Equal(got, []string{"owner"}) {
			t.Errorf("a refusal changed roles: %v", got)
		}

		// A suspended co-owner does not count: the org must keep an active owner.
		coOwner := f.member(t, org, "co@example.com", model.MembershipStatusSuspended, "owner")
		wantRefusal(t, f.svc.ChangeMemberRoles(ctx, owner, org, owner, []string{"admin"}), ErrConflict, MsgLastOwner)
		must(t, f.svc.ChangeMemberStatus(ctx, owner, org, coOwner, model.MembershipStatusActive))
		must(t, f.svc.ChangeMemberRoles(ctx, owner, org, owner, []string{"admin"}))
		if got := f.rolesOf(t, org, owner); !slices.Equal(got, []string{"admin"}) {
			t.Errorf("roles = %v", got)
		}
		if len(ofType[event.MemberRolesChanged](f.events)) != 1 {
			t.Error("only the accepted change is announced")
		}
	})
}

func TestASuperadminMayModifyOwnersButNotOrphanTheOrganization(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		other, _ := f.orgOwnedBy(t, "platform@example.com")
		operator := f.user(t, "operator@example.com")
		f.superadmin(t, other, operator)

		wantRefusal(t, f.svc.RemoveMember(ctx, operator, org, owner), ErrConflict, MsgLastOwner)
		wantRefusal(t, f.svc.ChangeMemberRoles(ctx, operator, org, owner, []string{"member"}), ErrConflict, MsgLastOwner)
		f.member(t, org, "co@example.com", model.MembershipStatusActive, "owner")
		must(t, f.svc.ChangeMemberRoles(ctx, operator, org, owner, []string{"member"}))
	})
}

// Service side of MemberSuspensionEndpointsTest.
func TestChangeStatusSuspendsAndReactivates(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member")

		must(t, f.svc.ChangeMemberStatus(ctx, owner, org, member, model.MembershipStatusSuspended))
		m, err := f.r.Memberships.ByUserAndOrganization(ctx, member, org)
		must(t, err)
		if m.Status != model.MembershipStatusSuspended || !m.UpdatedAt.Equal(t0) {
			t.Errorf("membership = %+v", m)
		}
		if got := f.sessions.revoked(); len(got) != 1 || got[0] != (revocation{member, org, model.RevokedAdmin}) {
			t.Errorf("revoked = %+v", got)
		}

		// Suspending again revokes again (a retry completes a failed revocation), announces nothing.
		must(t, f.svc.ChangeMemberStatus(ctx, owner, org, member, model.MembershipStatusSuspended))
		if len(f.sessions.revoked()) != 2 {
			t.Error("every suspend request revokes")
		}

		must(t, f.svc.ChangeMemberStatus(ctx, owner, org, member, model.MembershipStatusActive))
		if len(f.sessions.revoked()) != 2 {
			t.Error("reactivating revokes nothing")
		}
		events := ofType[event.MemberStatusChanged](f.events)
		want := []event.MemberStatusChanged{
			{OrganizationID: org, UserID: member, Status: "suspended", ActorUserID: owner},
			{OrganizationID: org, UserID: member, Status: "active", ActorUserID: owner},
		}
		if !slices.Equal(events, want) {
			t.Errorf("events = %+v", events)
		}
	})
}

func TestChangeStatusInvariants(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")
		invited := f.member(t, org, "invited@example.com", model.MembershipStatusInvited, "member")

		wantRefusal(t, f.svc.ChangeMemberStatus(ctx, owner, org, admin, "banned"), ErrInvalid, MsgBadStatus)
		wantRefusal(t, f.svc.ChangeMemberStatus(ctx, owner, org, "stranger", "suspended"), ErrNotFound, MsgMemberNotFound)
		wantRefusal(t, f.svc.ChangeMemberStatus(ctx, owner, org, invited, "active"), ErrInvalid, MsgInvitationNotYetUsed)
		wantForbidden(t, f.svc.ChangeMemberStatus(ctx, admin, org, owner, "suspended"), MsgOwnerStatus)
		wantRefusal(t, f.svc.ChangeMemberStatus(ctx, owner, org, owner, "suspended"), ErrConflict, MsgLastActiveOwner)
		if len(f.sessions.revoked()) != 0 {
			t.Error("a refused suspension revoked sessions")
		}

		// An owner can be suspended, even by themselves, while another active owner remains.
		f.member(t, org, "co@example.com", model.MembershipStatusActive, "owner")
		must(t, f.svc.ChangeMemberStatus(ctx, owner, org, owner, "suspended"))
	})
}

func TestChangeStatusReportsAFailedRevocation(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member")
		down := errors.New("db down")
		f.sessions.err = down
		if err := f.svc.ChangeMemberStatus(ctx, owner, org, member, "suspended"); !errors.Is(err, down) {
			t.Fatalf("err = %v", err)
		}
		if len(ofType[event.MemberStatusChanged](f.events)) != 0 {
			t.Error("announced before the revocation completed")
		}
	})
}

// Service side of testCannotRemoveTheLastOwner and testOwnerCanRemoveANonOwnerMember.
func TestRemoveMember(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")

		wantRefusal(t, f.svc.RemoveMember(ctx, owner, org, owner), ErrConflict, MsgLastOwner)
		wantForbidden(t, f.svc.RemoveMember(ctx, admin, org, owner), MsgOwnerRemove)
		wantRefusal(t, f.svc.RemoveMember(ctx, owner, org, "stranger"), ErrNotFound, MsgMemberNotFound)

		m, err := f.r.Memberships.ByUserAndOrganization(ctx, member, org)
		must(t, err)
		must(t, f.svc.RemoveMember(ctx, owner, org, member))
		if f.count(t, "auth_memberships", store.Criteria{"id": m.ID}) != 0 ||
			f.count(t, "auth_membership_roles", store.Criteria{"membership_id": m.ID}) != 0 {
			t.Error("the membership and its role links are gone")
		}
		if got := ofType[event.MemberRemoved](f.events); len(got) != 1 || got[0] != (event.MemberRemoved{OrganizationID: org, UserID: member, ActorUserID: owner}) {
			t.Errorf("events = %+v", got)
		}
	})
}
