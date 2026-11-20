package orgs

import (
	"context"
	"slices"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// Messages of the membership refusals.
const (
	MsgMemberNotFound       = "The user is not a member of this organization."
	MsgOwnerModify          = "Only an owner can modify an owner."
	MsgOwnerStatus          = "Only an owner can change an owner's status."
	MsgOwnerRemove          = "Only an owner can remove an owner."
	MsgLastOwner            = "The organization must keep at least one owner."
	MsgLastActiveOwner      = "The organization must keep at least one active owner."
	MsgBadStatus            = `status must be "active" or "suspended".`
	MsgInvitationNotYetUsed = "The member has not accepted their invitation yet."
	msgUnknownRole          = "Unknown role for this organization: "
)

// Member is one membership of an organization as listed.
type Member struct {
	UserID      string
	Email       *string // nil when withheld (see ListMembers) or the user is gone
	DisplayName *string
	Status      string
	Roles       []string // role slugs
}

// ListMembers returns the organization's members with their role slugs. The email of an invited
// or suspended member is withheld unless withPendingEmails (the caller holds members.invite):
// they have not consented to, or no longer take part in, the roster.
func (s *Service) ListMembers(ctx context.Context, organizationID string, withPendingEmails bool) ([]Member, error) {
	memberships, err := s.r.Memberships.ListByOrganization(ctx, organizationID)
	if err != nil {
		return nil, wrap("list members", err)
	}
	members := make([]Member, 0, len(memberships))
	for _, m := range memberships {
		user, err := s.r.Users.Get(ctx, m.UserID)
		exists, err := found(err)
		if err != nil {
			return nil, wrap("list members", err)
		}
		roles, err := s.roleSlugsOf(ctx, m.ID)
		if err != nil {
			return nil, wrap("list members", err)
		}
		member := Member{UserID: m.UserID, Status: m.Status, Roles: roles}
		if exists {
			member.DisplayName = user.DisplayName
			if withPendingEmails || m.Status == model.MembershipStatusActive {
				member.Email = &user.Email
			}
		}
		members = append(members, member)
	}
	return members, nil
}

// ChangeMemberRoles replaces the member's roles with roleSlugs (roles of the organization) and
// dispatches event.MemberRolesChanged. Refusals, in order: ErrNotFound (not a member),
// ErrInvalid (unknown slug), forbidden (a non-owner touching an owner, or escalation), ErrConflict
// (demoting the last active owner).
func (s *Service) ChangeMemberRoles(ctx context.Context, actorUserID, organizationID, targetUserID string, roleSlugs []string) error {
	return s.changeMemberRoles(ctx, actorUserID, organizationID, targetUserID, roleSlugs, true)
}

// SetMemberRoles is ChangeMemberRoles for a trusted system actor (the host, a directory): actor is
// only recorded in the event, no actor authority or escalation is checked, and the
// last-active-owner guard still applies.
func (s *Service) SetMemberRoles(ctx context.Context, actor, organizationID, targetUserID string, roleSlugs []string) error {
	return s.changeMemberRoles(ctx, actor, organizationID, targetUserID, roleSlugs, false)
}

func (s *Service) changeMemberRoles(ctx context.Context, actorUserID, organizationID, targetUserID string, roleSlugs []string, checkActor bool) error {
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockOrganization(ctx, organizationID); err != nil {
			return err
		}
		target, err := s.memberOrFail(ctx, organizationID, targetUserID)
		if err != nil {
			return err
		}
		var wanted []string
		for _, slug := range roleSlugs {
			role, err := s.r.Roles.ByOrganizationAndSlug(ctx, &organizationID, slug)
			if ok, err := found(err); err != nil {
				return err
			} else if !ok {
				return refuse(ErrInvalid, msgUnknownRole+slug)
			}
			if !slices.Contains(wanted, role.ID) {
				wanted = append(wanted, role.ID)
			}
		}
		var targetWasOwner bool
		if checkActor {
			actor, owner, err := s.actorAndTarget(ctx, actorUserID, organizationID, target.ID, MsgOwnerModify)
			if err != nil {
				return err
			}
			if err := s.guard.CheckRoles(ctx, actor, wanted); err != nil {
				return err
			}
			targetWasOwner = owner
		} else if targetWasOwner, err = s.isOwner(ctx, actorUserID, organizationID, target.ID, false); err != nil {
			return err
		}
		ownerRoleID, err := s.ownerRoleID(ctx, organizationID)
		if err != nil {
			return err
		}
		if targetWasOwner && !slices.Contains(wanted, ownerRoleID) {
			if err := s.keepsAnotherOwner(ctx, ownerRoleID, MsgLastOwner); err != nil {
				return err
			}
		}
		held, err := s.r.MembershipRoles.ListByMembership(ctx, target.ID)
		if err != nil {
			return err
		}
		for _, link := range held {
			if i := slices.Index(wanted, link.RoleID); i >= 0 {
				wanted = slices.Delete(wanted, i, i+1)
			} else if err := s.r.MembershipRoles.Delete(ctx, link); err != nil {
				return err
			}
		}
		for _, roleID := range wanted {
			if err := s.r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: target.ID, RoleID: roleID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return wrap("change member roles", err)
	}
	s.events.Dispatch(ctx, event.MemberRolesChanged{
		OrganizationID: organizationID, UserID: targetUserID, RoleSlugs: slices.Clone(roleSlugs), ActorUserID: actorUserID,
	})
	return nil
}

// ChangeMemberStatus suspends or reactivates a member (status model.MembershipStatusActive or
// model.MembershipStatusSuspended) and dispatches event.MemberStatusChanged when it changed.
// Every suspend request, even of an already suspended member, revokes the member's sessions
// scoped to the organization (reason admin): revocation is idempotent, so retrying a suspend
// whose revocation failed completes it. Their other sessions are untouched; a reactivated member
// regains authority on the next token resolution.
//
// Refusals, in order: ErrInvalid (another status), ErrNotFound (not a member), ErrInvalid (the
// member is still invited), forbidden (a non-owner changing an owner), ErrConflict (suspending
// the last active owner).
func (s *Service) ChangeMemberStatus(ctx context.Context, actorUserID, organizationID, targetUserID, status string) error {
	return s.changeMemberStatus(ctx, actorUserID, organizationID, targetUserID, status, true)
}

// SetMemberStatus is ChangeMemberStatus for a trusted system actor acting for the organization,
// such as its SCIM directory: actor ("scim") is only recorded in the event, no actor authority is
// checked, and the last-active-owner guard and the session revocation still apply.
func (s *Service) SetMemberStatus(ctx context.Context, actor, organizationID, targetUserID, status string) error {
	return s.changeMemberStatus(ctx, actor, organizationID, targetUserID, status, false)
}

// KeepOwner runs fn in a transaction with the organization locked (as every owner-changing write
// here) and refuses with ErrConflict, rolling fn back, when fn left an organization that had an
// active owner without one. It lets a trusted system actor (a SCIM directory) change role links
// and memberships under the same guarantee as the member routes.
func (s *Service) KeepOwner(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error {
	return s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockOrganization(ctx, organizationID); err != nil {
			return err
		}
		before, err := s.activeOwners(ctx, organizationID)
		if err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		after, err := s.activeOwners(ctx, organizationID)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return refuse(ErrConflict, MsgLastActiveOwner)
		}
		return nil
	})
}

// activeOwners counts the active memberships holding the organization's owner role.
func (s *Service) activeOwners(ctx context.Context, organizationID string) (int, error) {
	ownerRoleID, err := s.ownerRoleID(ctx, organizationID)
	if err != nil || ownerRoleID == "" {
		return 0, err
	}
	links, err := s.r.MembershipRoles.ListByRole(ctx, ownerRoleID)
	if err != nil {
		return 0, err
	}
	active := 0
	for _, link := range links {
		m, err := s.r.Memberships.Get(ctx, link.MembershipID)
		if ok, err := found(err); err != nil {
			return 0, err
		} else if ok && m.Status == model.MembershipStatusActive {
			active++
		}
	}
	return active, nil
}

func (s *Service) changeMemberStatus(ctx context.Context, actorUserID, organizationID, targetUserID, status string, checkActor bool) error {
	if status != model.MembershipStatusActive && status != model.MembershipStatusSuspended {
		return refuse(ErrInvalid, MsgBadStatus)
	}
	changed := false
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockOrganization(ctx, organizationID); err != nil {
			return err
		}
		target, err := s.memberOrFail(ctx, organizationID, targetUserID)
		if err != nil {
			return err
		}
		if target.Status == model.MembershipStatusInvited {
			return refuse(ErrInvalid, MsgInvitationNotYetUsed)
		}
		targetIsOwner, err := s.isOwner(ctx, actorUserID, organizationID, target.ID, checkActor)
		if err != nil {
			return err
		}
		if status == model.MembershipStatusSuspended && target.Status == model.MembershipStatusActive && targetIsOwner {
			ownerRoleID, err := s.ownerRoleID(ctx, organizationID)
			if err != nil {
				return err
			}
			if err := s.keepsAnotherOwner(ctx, ownerRoleID, MsgLastActiveOwner); err != nil {
				return err
			}
		}
		if target.Status == status {
			return nil
		}
		changed = true
		updated := target
		updated.Status = status
		updated.UpdatedAt = s.clock.Now()
		return s.r.Memberships.Update(ctx, target, updated)
	})
	if err != nil {
		return wrap("change member status", err)
	}
	if status == model.MembershipStatusSuspended {
		if err := s.sessions.RevokeAllForOrganization(ctx, targetUserID, organizationID, model.RevokedAdmin); err != nil {
			return wrap("change member status: revoke sessions", err)
		}
	}
	if changed {
		s.events.Dispatch(ctx, event.MemberStatusChanged{
			OrganizationID: organizationID, UserID: targetUserID, Status: status, ActorUserID: actorUserID,
		})
	}
	return nil
}

// RemoveMember removes a member (their role links cascade away) and dispatches
// event.MemberRemoved. Refusals, in order: ErrNotFound (not a member), forbidden (a non-owner
// removing an owner), ErrConflict (the last active owner, even by an owner or a superadmin).
func (s *Service) RemoveMember(ctx context.Context, actorUserID, organizationID, targetUserID string) error {
	return s.removeMember(ctx, actorUserID, organizationID, targetUserID, true)
}

// DropMember is RemoveMember for a trusted system actor (the host, a directory): actor is only
// recorded in the event, no actor authority is checked, and the last-active-owner guard still
// applies.
func (s *Service) DropMember(ctx context.Context, actor, organizationID, targetUserID string) error {
	return s.removeMember(ctx, actor, organizationID, targetUserID, false)
}

func (s *Service) removeMember(ctx context.Context, actorUserID, organizationID, targetUserID string, checkActor bool) error {
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockOrganization(ctx, organizationID); err != nil {
			return err
		}
		target, err := s.memberOrFail(ctx, organizationID, targetUserID)
		if err != nil {
			return err
		}
		targetIsOwner, err := s.isOwnerFor(ctx, actorUserID, organizationID, target.ID, MsgOwnerRemove, checkActor)
		if err != nil {
			return err
		}
		if targetIsOwner {
			ownerRoleID, err := s.ownerRoleID(ctx, organizationID)
			if err != nil {
				return err
			}
			if err := s.keepsAnotherOwner(ctx, ownerRoleID, MsgLastOwner); err != nil {
				return err
			}
		}
		return s.r.Memberships.Delete(ctx, target)
	})
	if err != nil {
		return wrap("remove member", err)
	}
	s.events.Dispatch(ctx, event.MemberRemoved{OrganizationID: organizationID, UserID: targetUserID, ActorUserID: actorUserID})
	return nil
}

// lockOrganization serializes the owner-changing writes of one organization (role changes,
// suspensions, removals), so two concurrent ones can never both see a co-owner and leave the
// organization with none. It must be the first statement of the transaction: a no-op UPDATE of
// the organization's row takes its row lock on PostgreSQL and MySQL (before MySQL's snapshot is
// taken, so the owner count read next is current) and the database write lock on SQLite; the
// lock holds until commit. memstore transactions are serial already.
func (s *Service) lockOrganization(ctx context.Context, organizationID string) error {
	_, err := s.db.Update(ctx, organizationsTable, store.Criteria{"id": organizationID}, store.Data{"id": organizationID})
	return err
}

const organizationsTable = "auth_organizations"

func (s *Service) memberOrFail(ctx context.Context, organizationID, userID string) (model.Membership, error) {
	m, err := s.r.Memberships.ByUserAndOrganization(ctx, userID, organizationID)
	if ok, err := found(err); err != nil {
		return model.Membership{}, err
	} else if !ok {
		return model.Membership{}, refuse(ErrNotFound, MsgMemberNotFound)
	}
	return m, nil
}

// actorAndTarget resolves the actor's authority and whether the target membership holds the
// owner role, refusing with ownerOnly when a non-owner, non-superadmin actor targets an owner.
func (s *Service) actorAndTarget(ctx context.Context, actorUserID, organizationID, targetMembershipID, ownerOnly string) (authz.Authority, bool, error) {
	actor, err := s.resolver.Resolve(ctx, actorUserID, organizationID)
	if err != nil {
		return authz.Authority{}, false, err
	}
	slugs, err := s.roleSlugsOf(ctx, targetMembershipID)
	if err != nil {
		return authz.Authority{}, false, err
	}
	targetIsOwner := slices.Contains(slugs, authz.RoleOwner)
	if targetIsOwner && !actor.IsSuperadmin() && !slices.Contains(actor.Roles, authz.RoleOwner) {
		return authz.Authority{}, false, authz.Forbidden(ownerOnly)
	}
	return actor, targetIsOwner, nil
}

func (s *Service) roleSlugsOf(ctx context.Context, membershipID string) ([]string, error) {
	links, err := s.r.MembershipRoles.ListByMembership(ctx, membershipID)
	if err != nil {
		return nil, err
	}
	slugs := make([]string, 0, len(links))
	for _, link := range links {
		role, err := s.r.Roles.Get(ctx, link.RoleID)
		if ok, err := found(err); err != nil {
			return nil, err
		} else if ok {
			slugs = append(slugs, role.Slug)
		}
	}
	return slugs, nil
}

// ownerRoleID returns the organization's owner role id, "" when it has none.
func (s *Service) ownerRoleID(ctx context.Context, organizationID string) (string, error) {
	role, err := s.r.Roles.ByOrganizationAndSlug(ctx, &organizationID, authz.RoleOwner)
	if ok, err := found(err); !ok {
		return "", err
	}
	return role.ID, nil
}

// isOwner is whether the target membership holds the owner role, after actorAndTarget's check
// of the actor when checkActor.
func (s *Service) isOwner(ctx context.Context, actorUserID, organizationID, targetMembershipID string, checkActor bool) (bool, error) {
	return s.isOwnerFor(ctx, actorUserID, organizationID, targetMembershipID, MsgOwnerStatus, checkActor)
}

func (s *Service) isOwnerFor(ctx context.Context, actorUserID, organizationID, targetMembershipID, ownerOnly string, checkActor bool) (bool, error) {
	if checkActor {
		_, owner, err := s.actorAndTarget(ctx, actorUserID, organizationID, targetMembershipID, ownerOnly)
		return owner, err
	}
	slugs, err := s.roleSlugsOf(ctx, targetMembershipID)
	return slices.Contains(slugs, authz.RoleOwner), err
}

// keepsAnotherOwner refuses (ErrConflict, message) unless the owner role is held by more than one
// active membership: the target's demotion, suspension or removal leaves an owner behind.
func (s *Service) keepsAnotherOwner(ctx context.Context, ownerRoleID, message string) error {
	if ownerRoleID == "" {
		return refuse(ErrConflict, message)
	}
	links, err := s.r.MembershipRoles.ListByRole(ctx, ownerRoleID)
	if err != nil {
		return err
	}
	active := 0
	for _, link := range links {
		m, err := s.r.Memberships.Get(ctx, link.MembershipID)
		if ok, err := found(err); err != nil {
			return err
		} else if ok && m.Status == model.MembershipStatusActive {
			active++
		}
	}
	if active <= 1 {
		return refuse(ErrConflict, message)
	}
	return nil
}
