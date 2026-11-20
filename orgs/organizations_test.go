package orgs

import (
	"errors"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

func TestNewRequiresItsDependencies(t *testing.T) {
	_, err := New(Config{})
	if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), "DB, Sessions, Pepper") {
		t.Fatalf("New(Config{}) = %v", err)
	}
}

// Port of OrganizationEndpointsTest::testCreateMakesTheCallerTheOwnerWithClonedRoles.
func TestCreateMakesTheCallerTheOwnerWithClonedRoles(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		userID := f.user(t, "founder@example.com")
		org, err := f.svc.CreateOrganization(ctx, "Acme Inc", "", userID)
		must(t, err)
		if org.Name != "Acme Inc" || org.Slug != "acme-inc" || org.Status != model.OrganizationStatusActive || org.CreatedBy != userID {
			t.Fatalf("org = %+v", org)
		}
		if n := f.count(t, "auth_organizations", store.Criteria{"id": org.ID, "created_by": userID, "status": "active"}); n != 1 {
			t.Errorf("organizations = %d", n)
		}
		if n := f.count(t, "auth_roles", store.Criteria{"organization_id": org.ID, "is_system": false}); n != 3 {
			t.Errorf("cloned roles = %d; want owner, admin, member", n)
		}
		if n := f.count(t, "auth_roles", store.Criteria{"organization_id": org.ID, "slug": "superadmin"}); n != 0 {
			t.Error("superadmin must never be cloned")
		}
		ownerRoleID := f.roleID(t, org.ID, "owner")
		if n := f.count(t, "auth_role_permissions", store.Criteria{"role_id": ownerRoleID}); n != 10 {
			t.Errorf("owner grants = %d; want the 10 org permissions", n)
		}
		m, err := f.r.Memberships.ByUserAndOrganization(ctx, userID, org.ID)
		must(t, err)
		if m.Status != model.MembershipStatusActive || m.JoinedAt == nil {
			t.Errorf("membership = %+v", m)
		}
		if got := f.rolesOf(t, org.ID, userID); len(got) != 1 || got[0] != "owner" {
			t.Errorf("roles = %v", got)
		}
		events := ofType[event.OrganizationCreated](f.events)
		if len(events) != 1 || events[0] != (event.OrganizationCreated{OrganizationID: org.ID, Slug: "acme-inc", OwnerUserID: userID}) {
			t.Errorf("events = %+v", events)
		}
	})
}

func TestSlugDerivation(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		userID := f.user(t, "founder@example.com")
		for name, want := range map[string]string{
			"  Ünïcode Co!": "n-code-co",
			"--ACME__42--":  "acme-42",
		} {
			org, err := f.svc.CreateOrganization(ctx, name, "", userID)
			must(t, err)
			if org.Slug != want || org.Name != name {
				t.Errorf("CreateOrganization(%q) = %q, %q; want slug %q", name, org.Name, org.Slug, want)
			}
		}
		org, err := f.svc.CreateOrganization(ctx, "Whatever", "explicit-slug", userID)
		must(t, err)
		if org.Slug != "explicit-slug" {
			t.Errorf("slug = %q; an explicit slug wins", org.Slug)
		}
		_, err = f.svc.CreateOrganization(ctx, "###", "", userID)
		wantRefusal(t, err, ErrInvalid, MsgSlugUnderivable)
	})
}

// Port of testSlugMustBeUnique and testCreateFailsClosedOnConflictLeavingNoPartialState.
func TestSlugMustBeUniqueAndConflictsLeaveNoPartialState(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		userID := f.user(t, "founder@example.com")
		_, err := f.svc.CreateOrganization(ctx, "Acme", "", userID)
		must(t, err)
		roles, memberships := f.count(t, "auth_roles", nil), f.count(t, "auth_memberships", nil)

		_, err = f.svc.CreateOrganization(ctx, "Another", "acme", userID)
		wantRefusal(t, err, ErrConflict, MsgSlugTaken)
		_, err = f.svc.CreateOrganization(ctx, "Acme", "", userID)
		wantRefusal(t, err, ErrConflict, MsgSlugTaken)

		if f.count(t, "auth_roles", nil) != roles || f.count(t, "auth_memberships", nil) != memberships ||
			f.count(t, "auth_organizations", nil) != 1 {
			t.Error("a conflict left partial state")
		}
		if len(ofType[event.OrganizationCreated](f.events)) != 1 {
			t.Error("a conflict dispatched org.created")
		}
	})
}

func TestASoftDeletedOrganizationKeepsItsSlugLocked(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		userID := f.user(t, "founder@example.com")
		org, err := f.svc.CreateOrganization(ctx, "Acme", "", userID)
		must(t, err)
		must(t, f.svc.DeleteOrganization(ctx, org, userID))
		_, err = f.svc.CreateOrganization(ctx, "Acme", "", f.user(t, "stranger@example.com"))
		wantRefusal(t, err, ErrConflict, MsgSlugTaken)
	})
}

// Port of testListReturnsOnlyTheCallersOrganizations.
func TestListReturnsOnlyTheCallersActiveOrganizations(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		mine, me := f.orgOwnedBy(t, "me@example.com")
		theirs, _ := f.orgOwnedBy(t, "them@example.com")
		suspendedIn, _ := f.orgOwnedBy(t, "other@example.com")
		f.join(t, suspendedIn, me, model.MembershipStatusSuspended, "member")
		deleted, err := f.svc.CreateOrganization(ctx, "Gone", "", me)
		must(t, err)
		must(t, f.svc.DeleteOrganization(ctx, deleted, me))

		got, err := f.svc.ListOrganizations(ctx, me)
		must(t, err)
		if len(got) != 1 || got[0].ID != mine {
			t.Errorf("ListOrganizations = %+v; want only %s (not %s)", got, mine, theirs)
		}
		none, err := f.svc.ListOrganizations(ctx, "nobody")
		must(t, err)
		if none == nil || len(none) != 0 {
			t.Errorf("ListOrganizations(nobody) = %#v; want empty, not nil", none)
		}
	})
}

// Port of OrganizationLifecycleEndpointsTest::testOwnerRenamesTheOrganization and testRejectsBadNames.
func TestUpdateRenamesTheOrganization(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		orgID, owner := f.orgOwnedBy(t, "founder@example.com")
		org, err := f.r.Organizations.Get(ctx, orgID)
		must(t, err)
		f.clock.Advance(60e9)

		updated, err := f.svc.UpdateOrganization(ctx, org, "  Renamed Inc \n", owner)
		must(t, err)
		if updated.Name != "Renamed Inc" || !updated.UpdatedAt.Equal(f.clock.Now()) || updated.Slug != org.Slug {
			t.Errorf("updated = %+v", updated)
		}
		stored, err := f.r.Organizations.Get(ctx, orgID)
		must(t, err)
		if stored.Name != "Renamed Inc" {
			t.Errorf("stored name = %q", stored.Name)
		}
		if got := ofType[event.OrganizationUpdated](f.events); len(got) != 1 || got[0] != (event.OrganizationUpdated{OrganizationID: orgID, ActorUserID: owner}) {
			t.Errorf("events = %+v", got)
		}

		for _, bad := range []string{"", "   ", strings.Repeat("a", 161)} {
			_, err := f.svc.UpdateOrganization(ctx, stored, bad, owner)
			wantRefusal(t, err, ErrInvalid, MsgOrgName)
		}
		_, err = f.svc.UpdateOrganization(ctx, stored, strings.Repeat("é", 160), owner)
		must(t, err) // 160 characters, 320 bytes
	})
}

// Port of testOwnerSoftDeletesTheOrganization, testDeleteRevokesMembersOrgScopedSessions… and
// testDeleteIsIdempotentAndEmitsOneEvent.
func TestDeleteSoftDeletesRevokesSessionsAndIsIdempotent(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		orgID, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, orgID, "member@example.com", model.MembershipStatusActive, "member")
		org, err := f.r.Organizations.Get(ctx, orgID)
		must(t, err)

		must(t, f.svc.DeleteOrganization(ctx, org, owner))
		stored, err := f.r.Organizations.Get(ctx, orgID)
		must(t, err)
		if stored.Status != model.OrganizationStatusSuspended {
			t.Errorf("status = %q", stored.Status)
		}
		want := []revocation{{owner, orgID, model.RevokedAdmin}, {member, orgID, model.RevokedAdmin}}
		if got := f.sessions.revoked(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("revoked = %+v; want %+v", got, want)
		}

		must(t, f.svc.DeleteOrganization(ctx, stored, owner))
		if got := ofType[event.OrganizationDeleted](f.events); len(got) != 1 || got[0] != (event.OrganizationDeleted{OrganizationID: orgID, ActorUserID: owner}) {
			t.Errorf("events = %+v; want one", got)
		}
		if len(f.sessions.revoked()) != 2 {
			t.Error("deleting a deleted organization revoked again")
		}
	})
}

func TestDeleteReportsFailedRevocationsAfterTryingThemAll(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		orgID, owner := f.orgOwnedBy(t, "founder@example.com")
		f.member(t, orgID, "member@example.com", model.MembershipStatusActive, "member")
		org, err := f.r.Organizations.Get(ctx, orgID)
		must(t, err)
		down := errors.New("cache down")
		f.sessions.err = down

		if err := f.svc.DeleteOrganization(ctx, org, owner); !errors.Is(err, down) {
			t.Fatalf("err = %v", err)
		}
		if len(f.sessions.revoked()) != 2 || len(ofType[event.OrganizationDeleted](f.events)) != 1 {
			t.Error("every member is tried and the deletion is announced")
		}
	})
}
