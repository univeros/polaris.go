package orgs

import (
	"context"
	"slices"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
)

// Messages of AddMember's refusals.
const (
	MsgOrganizationNotFound = "The organization does not exist."
	MsgUserNotFound         = "The user does not exist."
	MsgMembershipExists     = "That user already has a membership in this organization."
)

// AddMember makes userID an active member of organizationID holding roleSlugs (roles of the
// organization; none is allowed) for a trusted system actor (the host): no invitation and no
// actor authority checked. It dispatches
// event.MemberJoined. Refusals: ErrNotFound (no active organization, no user), ErrInvalid
// (unknown role slug), ErrConflict (the user already has a membership, in any status: change it
// with SetMemberRoles or SetMemberStatus).
func (s *Service) AddMember(ctx context.Context, organizationID, userID string, roleSlugs []string) error {
	var user model.User
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		org, err := s.r.Organizations.Get(ctx, organizationID)
		if ok, err := found(err); err != nil {
			return err
		} else if !ok || org.Status != model.OrganizationStatusActive {
			return refuse(ErrNotFound, MsgOrganizationNotFound)
		}
		user, err = s.r.Users.Get(ctx, userID)
		if ok, err := found(err); err != nil {
			return err
		} else if !ok {
			return refuse(ErrNotFound, MsgUserNotFound)
		}
		_, err = s.r.Memberships.ByUserAndOrganization(ctx, userID, organizationID)
		if exists, err := found(err); err != nil {
			return err
		} else if exists {
			return refuse(ErrConflict, MsgMembershipExists)
		}
		var roleIDs []string
		for _, slug := range roleSlugs {
			role, err := s.r.Roles.ByOrganizationAndSlug(ctx, &organizationID, slug)
			if ok, err := found(err); err != nil {
				return err
			} else if !ok {
				return refuse(ErrInvalid, msgUnknownRole+slug)
			}
			if !slices.Contains(roleIDs, role.ID) {
				roleIDs = append(roleIDs, role.ID)
			}
		}
		now := s.clock.Now()
		m := model.Membership{
			ID: repository.NewID(), UserID: userID, OrganizationID: organizationID,
			Status: model.MembershipStatusActive, JoinedAt: &now, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.r.Memberships.Insert(ctx, m); err != nil {
			return err
		}
		for _, roleID := range roleIDs {
			if err := s.r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: roleID}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return wrap("add member", err)
	}
	s.events.Dispatch(ctx, event.MemberJoined{OrganizationID: organizationID, UserID: userID, Email: user.Email})
	return nil
}
