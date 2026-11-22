package orgs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Messages of the role refusals.
const (
	MsgRoleName         = "A role name is required."
	MsgRoleSlug         = "The slug must be lowercase letters, digits and hyphens."
	MsgRoleNotFound     = "The role does not exist in this organization."
	MsgSystemRole       = "System roles cannot be modified."
	MsgOwnerRole        = "The owner role cannot be modified."
	msgUnknownKey       = "Unknown permission key: "
	msgRoleSlugTakenFmt = "The role slug \"%s\" is already taken in this organization."
	msgUndeletableFmt   = "The %s role cannot be deleted."
)

var roleSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,79}$`)

// Role is an organization role with its permission keys.
type Role struct {
	ID             string
	Name           string
	Slug           string
	Description    *string
	IsSystem       bool
	PermissionKeys []string
}

// NewRole describes a custom role to create.
type NewRole struct {
	Name           string
	Slug           string // 1-80 of a-z, 0-9, "-", not starting with "-"; immutable
	Description    *string
	PermissionKeys []string
}

// RoleChanges describes a role update; a nil field is left untouched. PermissionKeys, when set,
// replaces the role's permissions (an empty list strips them all).
type RoleChanges struct {
	Name           *string
	Description    *string
	PermissionKeys *[]string
}

// ListRoles returns the organization's own roles with their permission keys.
func (s *Service) ListRoles(ctx context.Context, organizationID string) ([]Role, error) {
	keys, err := s.permissionKeysByID(ctx)
	if err != nil {
		return nil, wrap("list roles", err)
	}
	roles, err := s.r.Roles.ListByOrganization(ctx, organizationID)
	if err != nil {
		return nil, wrap("list roles", err)
	}
	out := make([]Role, 0, len(roles))
	for _, role := range roles {
		shaped, err := s.shape(ctx, role, keys)
		if err != nil {
			return nil, wrap("list roles", err)
		}
		out = append(out, shaped)
	}
	return out, nil
}

// CreateRole creates a custom role in the organization and dispatches event.RoleCreated.
// Refusals, in order: ErrInvalid (empty name, malformed slug), ErrConflict (slug used in the
// organization), ErrInvalid (a key missing from the catalog), forbidden (a key the actor does not
// hold: editing a role you hold must not be a self-escalation path).
func (s *Service) CreateRole(ctx context.Context, actorUserID, organizationID string, in NewRole) (Role, error) {
	name := trimEdges(in.Name)
	if name == "" {
		return Role{}, refuse(ErrInvalid, MsgRoleName)
	}
	if !roleSlug.MatchString(in.Slug) {
		return Role{}, refuse(ErrInvalid, MsgRoleSlug)
	}
	taken := refuse(ErrConflict, fmt.Sprintf(msgRoleSlugTakenFmt, in.Slug))
	now := s.clock.Now()
	role := model.Role{
		ID: repository.NewID(), OrganizationID: &organizationID, Name: name, Slug: in.Slug,
		Description: in.Description, CreatedAt: now, UpdatedAt: now,
	}
	var shaped Role
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		_, err := s.r.Roles.ByOrganizationAndSlug(ctx, &organizationID, in.Slug)
		if ok, err := found(err); err != nil {
			return err
		} else if ok {
			return taken
		}
		permissionIDs, err := s.grantable(ctx, actorUserID, organizationID, in.PermissionKeys)
		if err != nil {
			return err
		}
		if err := s.r.Roles.Insert(ctx, role); err != nil {
			if errors.Is(err, store.ErrDuplicate) {
				return taken
			}
			return err
		}
		if err := s.setGrants(ctx, role.ID, permissionIDs); err != nil {
			return err
		}
		shaped, err = s.shapeFresh(ctx, role)
		return err
	})
	if err != nil {
		return Role{}, wrap("create role", err)
	}
	s.events.Dispatch(ctx, event.RoleCreated{OrganizationID: organizationID, RoleID: role.ID, ActorUserID: actorUserID})
	return shaped, nil
}

// UpdateRole changes a role's name, description and/or permissions (the slug is immutable) and
// dispatches event.RoleUpdated. Refusals: ErrNotFound (an unknown id, another organization's role
// or a global system role), forbidden (a system role, the owner role, or a key the actor does not
// hold), ErrInvalid (an empty name, a key missing from the catalog).
func (s *Service) UpdateRole(ctx context.Context, actorUserID, organizationID, roleID string, ch RoleChanges) (Role, error) {
	var shaped Role
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		role, err := s.mutableRole(ctx, organizationID, roleID)
		if err != nil {
			return err
		}
		updated := role
		if ch.Name != nil {
			if updated.Name = trimEdges(*ch.Name); updated.Name == "" {
				return refuse(ErrInvalid, MsgRoleName)
			}
		}
		if ch.Description != nil {
			updated.Description = ch.Description
		}
		if ch.PermissionKeys != nil {
			permissionIDs, err := s.grantable(ctx, actorUserID, organizationID, *ch.PermissionKeys)
			if err != nil {
				return err
			}
			if err := s.setGrants(ctx, role.ID, permissionIDs); err != nil {
				return err
			}
		}
		updated.UpdatedAt = s.clock.Now()
		if err := s.r.Roles.Update(ctx, role, updated); err != nil {
			return err
		}
		shaped, err = s.shapeFresh(ctx, updated)
		return err
	})
	if err != nil {
		return Role{}, wrap("update role", err)
	}
	s.events.Dispatch(ctx, event.RoleUpdated{OrganizationID: organizationID, RoleID: roleID, ActorUserID: actorUserID})
	return shaped, nil
}

// DeleteRole deletes a custom role, detaching it from every member (cascade), and dispatches
// event.RoleDeleted. Refusals: ErrNotFound as UpdateRole; forbidden for a system role and for the
// organization's owner, admin and member roles (editable, but every flow assigns them by slug).
func (s *Service) DeleteRole(ctx context.Context, actorUserID, organizationID, roleID string) error {
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		role, err := s.mutableRole(ctx, organizationID, roleID)
		if err != nil {
			return err
		}
		if role.Slug == authz.RoleAdmin || role.Slug == authz.RoleMember {
			return authz.Forbidden(fmt.Sprintf(msgUndeletableFmt, role.Slug))
		}
		return s.r.Roles.Delete(ctx, role)
	})
	if err != nil {
		return wrap("delete role", err)
	}
	s.events.Dispatch(ctx, event.RoleDeleted{OrganizationID: organizationID, RoleID: roleID, ActorUserID: actorUserID})
	return nil
}

// Permissions returns the stored permission catalog (core and host-contributed), for building
// role UIs.
func (s *Service) Permissions(ctx context.Context) ([]authz.Permission, error) {
	perms, err := s.r.Permissions.List(ctx)
	if err != nil {
		return nil, wrap("list permissions", err)
	}
	out := make([]authz.Permission, 0, len(perms))
	for _, p := range perms {
		out = append(out, authz.Permission{Key: p.Key, Description: p.Description})
	}
	return out, nil
}

// mutableRole returns the organization's role roleID, refusing roles tenants cannot change: a
// system role, and the owner role that anchors the last-owner and owner-protection invariants.
func (s *Service) mutableRole(ctx context.Context, organizationID, roleID string) (model.Role, error) {
	role, err := s.r.Roles.Get(ctx, roleID)
	if ok, err := found(err); err != nil {
		return role, err
	} else if !ok || role.OrganizationID == nil || *role.OrganizationID != organizationID {
		return role, refuse(ErrNotFound, MsgRoleNotFound)
	}
	if role.IsSystem {
		return role, authz.Forbidden(MsgSystemRole)
	}
	if role.Slug == authz.RoleOwner {
		return role, authz.Forbidden(MsgOwnerRole)
	}
	return role, nil
}

// grantable maps keys to permission ids, refusing a key missing from the catalog (ErrInvalid),
// then one the actor does not hold (forbidden).
func (s *Service) grantable(ctx context.Context, actorUserID, organizationID string, keys []string) ([]string, error) {
	idsByKey, err := s.permissionIDsByKey(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		id, ok := idsByKey[key]
		if !ok {
			return nil, refuse(ErrInvalid, msgUnknownKey+key)
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	actor, err := s.resolver.Resolve(ctx, actorUserID, organizationID)
	if err != nil {
		return nil, err
	}
	return ids, s.guard.CheckPermissions(actor, keys)
}

// setGrants makes permissionIDs the role's grants, keeping the ones it already has.
func (s *Service) setGrants(ctx context.Context, roleID string, permissionIDs []string) error {
	grants, err := s.r.RolePermissions.ListByRole(ctx, roleID)
	if err != nil {
		return err
	}
	wanted := slices.Clone(permissionIDs)
	for _, g := range grants {
		if i := slices.Index(wanted, g.PermissionID); i >= 0 {
			wanted = slices.Delete(wanted, i, i+1)
		} else if err := s.r.RolePermissions.Delete(ctx, g); err != nil {
			return err
		}
	}
	for _, id := range wanted {
		if err := s.r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: roleID, PermissionID: id}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) shapeFresh(ctx context.Context, role model.Role) (Role, error) {
	keys, err := s.permissionKeysByID(ctx)
	if err != nil {
		return Role{}, err
	}
	return s.shape(ctx, role, keys)
}

func (s *Service) shape(ctx context.Context, role model.Role, keysByID map[string]string) (Role, error) {
	grants, err := s.r.RolePermissions.ListByRole(ctx, role.ID)
	if err != nil {
		return Role{}, err
	}
	keys := make([]string, 0, len(grants))
	for _, g := range grants {
		if key, ok := keysByID[g.PermissionID]; ok {
			keys = append(keys, key)
		}
	}
	return Role{
		ID: role.ID, Name: role.Name, Slug: role.Slug, Description: role.Description,
		IsSystem: role.IsSystem, PermissionKeys: keys,
	}, nil
}

func (s *Service) permissionKeysByID(ctx context.Context) (map[string]string, error) {
	ids, err := s.permissionIDsByKey(ctx)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]string, len(ids))
	for key, id := range ids {
		keys[id] = key
	}
	return keys, nil
}
