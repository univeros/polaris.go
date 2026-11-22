package repository

import (
	"cmp"
	"context"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// Organizations reads and writes auth_organizations.
type Organizations struct{ Table[model.Organization] }

// BySlug finds an organization by its unique slug.
func (r Organizations) BySlug(ctx context.Context, slug string) (model.Organization, error) {
	return r.FindOne(ctx, store.Criteria{"slug": slug})
}

func newOrganizations(db store.Adapter) Organizations {
	return Organizations{Table[model.Organization]{db: db, name: "auth_organizations", key: []string{"id"},
		toRow: func(o model.Organization) store.Row {
			return store.Row{
				"id": o.ID, "name": o.Name, "slug": o.Slug, "status": cmp.Or(o.Status, model.OrganizationStatusActive),
				"created_by": o.CreatedBy, "created_at": ts(o.CreatedAt), "updated_at": ts(o.UpdatedAt),
			}
		},
		fromRow: func(r *reader) model.Organization {
			return model.Organization{
				ID: r.str("id"), Name: r.str("name"), Slug: r.str("slug"), Status: r.str("status"),
				CreatedBy: r.str("created_by"), CreatedAt: r.time("created_at"), UpdatedAt: r.time("updated_at"),
			}
		},
	}}
}

// Memberships reads and writes auth_memberships.
type Memberships struct{ Table[model.Membership] }

// ByUserAndOrganization finds a user's membership of an organization (unique), in any status.
func (r Memberships) ByUserAndOrganization(ctx context.Context, userID, organizationID string) (model.Membership, error) {
	return r.FindOne(ctx, store.Criteria{"user_id": userID, "organization_id": organizationID})
}

// ListByUser returns every membership of a user, in any status.
func (r Memberships) ListByUser(ctx context.Context, userID string) ([]model.Membership, error) {
	return r.list(ctx, store.Criteria{"user_id": userID})
}

// ListActiveByUser returns a user's active memberships.
func (r Memberships) ListActiveByUser(ctx context.Context, userID string) ([]model.Membership, error) {
	return r.list(ctx, store.Criteria{"user_id": userID, "status": model.MembershipStatusActive})
}

// ListByOrganization returns every membership of an organization, in any status.
func (r Memberships) ListByOrganization(ctx context.Context, organizationID string) ([]model.Membership, error) {
	return r.list(ctx, store.Criteria{"organization_id": organizationID})
}

func newMemberships(db store.Adapter) Memberships {
	return Memberships{Table[model.Membership]{db: db, name: "auth_memberships", key: []string{"id"},
		toRow: func(m model.Membership) store.Row {
			return store.Row{
				"id": m.ID, "user_id": m.UserID, "organization_id": m.OrganizationID,
				"status": cmp.Or(m.Status, model.MembershipStatusInvited), "invited_by": store.Nullable(m.InvitedBy),
				"joined_at": tsPtr(m.JoinedAt), "created_at": ts(m.CreatedAt), "updated_at": ts(m.UpdatedAt),
			}
		},
		fromRow: func(r *reader) model.Membership {
			return model.Membership{
				ID: r.str("id"), UserID: r.str("user_id"), OrganizationID: r.str("organization_id"),
				Status: r.str("status"), InvitedBy: r.strPtr("invited_by"), JoinedAt: r.timePtr("joined_at"),
				CreatedAt: r.time("created_at"), UpdatedAt: r.time("updated_at"),
			}
		},
	}}
}

// MembershipRoles reads and writes auth_membership_roles.
type MembershipRoles struct{ Table[model.MembershipRole] }

// Get finds one membership/role link.
func (r MembershipRoles) Get(ctx context.Context, membershipID, roleID string) (model.MembershipRole, error) {
	return r.FindOne(ctx, store.Criteria{"membership_id": membershipID, "role_id": roleID})
}

// ListByMembership returns the roles a membership holds.
func (r MembershipRoles) ListByMembership(ctx context.Context, membershipID string) ([]model.MembershipRole, error) {
	return r.list(ctx, store.Criteria{"membership_id": membershipID})
}

// ListByRole returns the memberships holding a role.
func (r MembershipRoles) ListByRole(ctx context.Context, roleID string) ([]model.MembershipRole, error) {
	return r.list(ctx, store.Criteria{"role_id": roleID})
}

func newMembershipRoles(db store.Adapter) MembershipRoles {
	return MembershipRoles{Table[model.MembershipRole]{db: db, name: "auth_membership_roles", key: []string{"membership_id", "role_id"},
		toRow: func(l model.MembershipRole) store.Row {
			return store.Row{"membership_id": l.MembershipID, "role_id": l.RoleID}
		},
		fromRow: func(r *reader) model.MembershipRole {
			return model.MembershipRole{MembershipID: r.str("membership_id"), RoleID: r.str("role_id")}
		},
	}}
}

// Roles reads and writes auth_roles.
type Roles struct{ Table[model.Role] }

// ByOrganizationAndSlug finds a role by slug in an organization; a nil organizationID looks among
// the global system roles.
func (r Roles) ByOrganizationAndSlug(ctx context.Context, organizationID *string, slug string) (model.Role, error) {
	return r.FindOne(ctx, store.Criteria{"organization_id": store.Nullable(organizationID), "slug": slug})
}

// ListByOrganization returns an organization's own roles.
func (r Roles) ListByOrganization(ctx context.Context, organizationID string) ([]model.Role, error) {
	return r.list(ctx, store.Criteria{"organization_id": organizationID})
}

// ListBySlug returns every role with a slug, across organizations and system roles.
func (r Roles) ListBySlug(ctx context.Context, slug string) ([]model.Role, error) {
	return r.list(ctx, store.Criteria{"slug": slug})
}

func newRoles(db store.Adapter) Roles {
	return Roles{Table[model.Role]{db: db, name: "auth_roles", key: []string{"id"},
		toRow: func(ro model.Role) store.Row {
			return store.Row{
				"id": ro.ID, "organization_id": store.Nullable(ro.OrganizationID), "name": ro.Name, "slug": ro.Slug,
				"description": store.Nullable(ro.Description), "is_system": ro.IsSystem,
				"created_at": ts(ro.CreatedAt), "updated_at": ts(ro.UpdatedAt),
			}
		},
		fromRow: func(r *reader) model.Role {
			return model.Role{
				ID: r.str("id"), OrganizationID: r.strPtr("organization_id"), Name: r.str("name"), Slug: r.str("slug"),
				Description: r.strPtr("description"), IsSystem: r.boolean("is_system"),
				CreatedAt: r.time("created_at"), UpdatedAt: r.time("updated_at"),
			}
		},
	}}
}

// RolePermissions reads and writes auth_role_permissions.
type RolePermissions struct{ Table[model.RolePermission] }

// Get finds one role/permission grant.
func (r RolePermissions) Get(ctx context.Context, roleID, permissionID string) (model.RolePermission, error) {
	return r.FindOne(ctx, store.Criteria{"role_id": roleID, "permission_id": permissionID})
}

// ListByRole returns a role's grants.
func (r RolePermissions) ListByRole(ctx context.Context, roleID string) ([]model.RolePermission, error) {
	return r.list(ctx, store.Criteria{"role_id": roleID})
}

func newRolePermissions(db store.Adapter) RolePermissions {
	return RolePermissions{Table[model.RolePermission]{db: db, name: "auth_role_permissions", key: []string{"role_id", "permission_id"},
		toRow: func(g model.RolePermission) store.Row {
			return store.Row{"role_id": g.RoleID, "permission_id": g.PermissionID}
		},
		fromRow: func(r *reader) model.RolePermission {
			return model.RolePermission{RoleID: r.str("role_id"), PermissionID: r.str("permission_id")}
		},
	}}
}

// Permissions reads and writes auth_permissions.
type Permissions struct{ Table[model.Permission] }

// ByKey finds a permission by its unique key.
func (r Permissions) ByKey(ctx context.Context, key string) (model.Permission, error) {
	return r.FindOne(ctx, store.Criteria{"key": key})
}

// List returns every permission.
func (r Permissions) List(ctx context.Context) ([]model.Permission, error) {
	return r.list(ctx, nil)
}

func newPermissions(db store.Adapter) Permissions {
	return Permissions{Table[model.Permission]{db: db, name: "auth_permissions", key: []string{"id"},
		toRow: func(p model.Permission) store.Row {
			return store.Row{"id": p.ID, "key": p.Key, "description": p.Description}
		},
		fromRow: func(r *reader) model.Permission {
			return model.Permission{ID: r.str("id"), Key: r.str("key"), Description: r.str("description")}
		},
	}}
}

// Invitations reads and writes auth_invitations.
type Invitations struct{ Table[model.Invitation] }

// ByTokenHash finds an invitation by its peppered token hash.
func (r Invitations) ByTokenHash(ctx context.Context, hash string) (model.Invitation, error) {
	return r.FindOne(ctx, store.Criteria{"token_hash": hash})
}

// ListByOrganization returns every invitation of an organization.
func (r Invitations) ListByOrganization(ctx context.Context, organizationID string) ([]model.Invitation, error) {
	return r.list(ctx, store.Criteria{"organization_id": organizationID})
}

// ListByOrganizationAndEmail returns an organization's invitations to one email.
func (r Invitations) ListByOrganizationAndEmail(ctx context.Context, organizationID, email string) ([]model.Invitation, error) {
	return r.list(ctx, store.Criteria{"organization_id": organizationID, "email": email})
}

func newInvitations(db store.Adapter) Invitations {
	return Invitations{Table[model.Invitation]{db: db, name: "auth_invitations", key: []string{"id"},
		toRow: func(i model.Invitation) store.Row {
			return store.Row{
				"id": i.ID, "organization_id": i.OrganizationID, "email": i.Email, "role_ids": roleIDs(i.RoleIDs),
				"token_hash": i.TokenHash, "invited_by": i.InvitedBy, "expires_at": ts(i.ExpiresAt),
				"accepted_at": tsPtr(i.AcceptedAt), "created_at": ts(i.CreatedAt),
			}
		},
		fromRow: func(r *reader) model.Invitation {
			var ids []string
			r.json("role_ids", &ids)
			return model.Invitation{
				ID: r.str("id"), OrganizationID: r.str("organization_id"), Email: r.str("email"), RoleIDs: ids,
				TokenHash: r.str("token_hash"), InvitedBy: r.str("invited_by"), ExpiresAt: r.time("expires_at"),
				AcceptedAt: r.timePtr("accepted_at"), CreatedAt: r.time("created_at"),
			}
		},
	}}
}

// roleIDs encodes the role list for its JSON column: a compact array of the UUID strings, [] for
// none.
func roleIDs(ids []string) string {
	if ids == nil {
		ids = []string{}
	}
	s, _ := store.JSONValue(ids) // a []string always encodes
	return s
}
