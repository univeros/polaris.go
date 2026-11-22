package orgs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/strutil"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Messages of the organization refusals.
const (
	MsgSlugTaken       = "The organization slug is already taken."
	MsgSlugUnderivable = "A URL-safe slug could not be derived from the name; provide one."
	MsgOrgName         = "A name of 1-160 characters is required."
)

const maxOrgName = 160

// CreateOrganization creates an organization owned by userID, all or nothing: the organization,
// its editable copies of the owner, admin and member role templates (with their grants; never
// superadmin), and the creator's active owner membership. slug "" derives one from name
// (lowercased, runs of anything but a-z0-9 turned into "-"). It dispatches
// event.OrganizationCreated.
//
// A slug already used, even by a suspended (soft-deleted) organization, is an ErrConflict: the
// slug of a restorable organization stays locked. A name with no derivable slug is ErrInvalid.
// The name and an explicit slug are the endpoint's to validate.
func (s *Service) CreateOrganization(ctx context.Context, name, slug, userID string) (model.Organization, error) {
	if slug == "" {
		slug = strings.Trim(nonSlug.ReplaceAllString(asciiLower(name), "-"), "-")
		if slug == "" {
			return model.Organization{}, refuse(ErrInvalid, MsgSlugUnderivable)
		}
	}
	now := s.clock.Now()
	org := model.Organization{
		ID: repository.NewID(), Name: name, Slug: slug, Status: model.OrganizationStatusActive,
		CreatedBy: userID, CreatedAt: now, UpdatedAt: now,
	}
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		_, err := s.r.Organizations.BySlug(ctx, slug)
		taken, err := found(err)
		if err != nil {
			return err
		}
		if taken {
			return refuse(ErrConflict, MsgSlugTaken)
		}
		if err := s.r.Organizations.Insert(ctx, org); err != nil {
			if errors.Is(err, store.ErrDuplicate) { // lost a race for the slug
				return refuse(ErrConflict, MsgSlugTaken)
			}
			return err
		}
		ownerRoleID, err := s.cloneRoleTemplates(ctx, org.ID, now)
		if err != nil {
			return err
		}
		membership := model.Membership{
			ID: repository.NewID(), UserID: userID, OrganizationID: org.ID,
			Status: model.MembershipStatusActive, JoinedAt: &now, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.r.Memberships.Insert(ctx, membership); err != nil {
			return err
		}
		return s.r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: membership.ID, RoleID: ownerRoleID})
	})
	if err != nil {
		return model.Organization{}, wrap("create organization", err)
	}
	s.events.Dispatch(ctx, event.OrganizationCreated{OrganizationID: org.ID, Slug: org.Slug, OwnerUserID: userID})
	return org, nil
}

// cloneRoleTemplates copies the owner, admin and member templates into tenant-owned roles of the
// organization (is_system false, editable) with their grants, and returns the owner role's id.
func (s *Service) cloneRoleTemplates(ctx context.Context, organizationID string, now time.Time) (string, error) {
	ids, err := s.permissionIDsByKey(ctx)
	if err != nil {
		return "", err
	}
	var ownerRoleID string
	for _, tpl := range s.catalog.RoleTemplates() {
		if tpl.Slug == authz.RoleSuperadmin {
			continue
		}
		role := model.Role{
			ID: repository.NewID(), OrganizationID: &organizationID, Name: tpl.Name, Slug: tpl.Slug,
			Description: &tpl.Description, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.r.Roles.Insert(ctx, role); err != nil {
			return "", err
		}
		if tpl.Slug == authz.RoleOwner {
			ownerRoleID = role.ID
		}
		for _, key := range tpl.PermissionKeys {
			if id, ok := ids[key]; ok {
				if err := s.r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: role.ID, PermissionID: id}); err != nil {
					return "", err
				}
			}
		}
	}
	return ownerRoleID, nil
}

// ListOrganizations returns the active organizations userID is an active member of.
func (s *Service) ListOrganizations(ctx context.Context, userID string) ([]model.Organization, error) {
	memberships, err := s.r.Memberships.ListActiveByUser(ctx, userID)
	if err != nil {
		return nil, wrap("list organizations", err)
	}
	orgs := []model.Organization{}
	for _, m := range memberships {
		org, err := s.r.Organizations.Get(ctx, m.OrganizationID)
		if ok, err := found(err); err != nil {
			return nil, wrap("list organizations", err)
		} else if ok && org.Status == model.OrganizationStatusActive {
			orgs = append(orgs, org)
		}
	}
	return orgs, nil
}

// UpdateOrganization renames org (as read by the caller) and dispatches
// event.OrganizationUpdated. The name is trimmed; empty or over 160 characters is ErrInvalid.
func (s *Service) UpdateOrganization(ctx context.Context, org model.Organization, name, actorUserID string) (model.Organization, error) {
	name = strutil.Trim(name)
	if name == "" || utf8.RuneCountInString(name) > maxOrgName {
		return model.Organization{}, refuse(ErrInvalid, MsgOrgName)
	}
	updated := org
	updated.Name = name
	updated.UpdatedAt = s.clock.Now()
	if err := s.r.Organizations.Update(ctx, org, updated); err != nil {
		return model.Organization{}, wrap("update organization", err)
	}
	s.events.Dispatch(ctx, event.OrganizationUpdated{OrganizationID: org.ID, ActorUserID: actorUserID})
	return updated, nil
}

// DeleteOrganization soft-deletes org: status suspended, which strips
// every member's authority in it, hides it from listings and blocks switching into it; rows are
// purged later by retention tooling. Every member's sessions scoped to it are revoked (reason
// admin), so their refresh tokens stop minting empty-authority tokens. It dispatches
// event.OrganizationDeleted once: deleting a suspended organization does nothing.
//
// A failed revocation does not stop the others; the errors are joined and returned after the
// event, since the organization is deleted by then.
func (s *Service) DeleteOrganization(ctx context.Context, org model.Organization, actorUserID string) error {
	if org.Status == model.OrganizationStatusSuspended {
		return nil
	}
	updated := org
	updated.Status = model.OrganizationStatusSuspended
	updated.UpdatedAt = s.clock.Now()
	if err := s.r.Organizations.Update(ctx, org, updated); err != nil {
		return wrap("delete organization", err)
	}
	memberships, err := s.r.Memberships.ListByOrganization(ctx, org.ID)
	errs := []error{err}
	for _, m := range memberships {
		errs = append(errs, s.sessions.RevokeAllForOrganization(ctx, m.UserID, org.ID, model.RevokedAdmin))
	}
	s.events.Dispatch(ctx, event.OrganizationDeleted{OrganizationID: org.ID, ActorUserID: actorUserID})
	if err := errors.Join(errs...); err != nil {
		return wrap("delete organization: revoke sessions", err)
	}
	return nil
}

func (s *Service) permissionIDsByKey(ctx context.Context) (map[string]string, error) {
	perms, err := s.r.Permissions.List(ctx)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]string, len(perms))
	for _, p := range perms {
		ids[p.Key] = p.ID
	}
	return ids, nil
}

// wrap prefixes infrastructure errors with the operation and passes nil and refusals through
// untouched.
func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var refusal *Error
	var forbidden *authz.ForbiddenError
	if errors.As(err, &refusal) || errors.As(err, &forbidden) {
		return err
	}
	return fmt.Errorf("orgs: %s: %w", op, err)
}
