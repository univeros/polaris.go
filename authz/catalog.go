package authz

import (
	"fmt"
	"maps"
	"slices"
)

// Core permission keys (resource.action).
const (
	OrgRead       = "org.read"
	OrgUpdate     = "org.update"
	OrgDelete     = "org.delete"
	MembersRead   = "members.read"
	MembersInvite = "members.invite"
	MembersUpdate = "members.update"
	MembersRemove = "members.remove"
	RolesRead     = "roles.read"
	RolesManage   = "roles.manage"
	UsersRead     = "users.read"
	UsersManage   = "users.manage"
	AuditRead     = "audit.read"
)

// System role slugs.
const (
	RoleOwner      = "owner"
	RoleAdmin      = "admin"
	RoleMember     = "member"
	RoleSuperadmin = "superadmin"
)

// Permission is one catalog entry.
type Permission struct {
	Key         string
	Description string
}

// corePermissions is the v1 catalog, in seed order.
var corePermissions = []Permission{
	{OrgRead, "View the organization profile"},
	{OrgUpdate, "Edit organization name and settings"},
	{OrgDelete, "Delete the organization"},
	{MembersRead, "List organization members"},
	{MembersInvite, "Send membership invitations"},
	{MembersUpdate, "Change a member's roles or suspend them"},
	{MembersRemove, "Remove a member from the organization"},
	{RolesRead, "List roles"},
	{RolesManage, "Create, update and delete custom roles and assignments"},
	{UsersRead, "Read user records (admin scope)"},
	{UsersManage, "Disable and enable users (admin scope)"},
	{AuditRead, "Read the organization's audit log"},
}

// adminScoped are the platform-admin permissions granted only to superadmin, never to org roles.
var adminScoped = []string{UsersRead, UsersManage}

// RoleTemplate is a system role: seeded once with no organization (is_system), and cloned into
// each new organization as its editable copy.
type RoleTemplate struct {
	Slug           string
	Name           string
	Description    string
	PermissionKeys []string
}

// Catalog is the code-defined permission catalog: core's permissions plus the host's and the
// plugins' contributions. It is an immutable value; the zero value is core only.
type Catalog struct {
	contributions []map[string]string
	roleGrants    map[string][]string // owner/admin/member slug → contributed keys
}

// NewCatalog returns the core catalog extended by contributions (key → description), applied in
// order: a contributed key overrides a core or earlier description in place.
func NewCatalog(contributions ...map[string]string) Catalog {
	return Catalog{contributions: slices.Clone(contributions)}
}

// Permissions returns the full catalog: core permissions in their fixed order, then contributed keys
// (sorted within each contribution, since Go maps have no order).
func (c Catalog) Permissions() []Permission {
	out := slices.Clone(corePermissions)
	at := make(map[string]int, len(out))
	for i, p := range out {
		at[p.Key] = i
	}
	for _, contribution := range c.contributions {
		keys := make([]string, 0, len(contribution))
		for k := range contribution {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if i, ok := at[k]; ok {
				out[i].Description = contribution[k]
				continue
			}
			at[k] = len(out)
			out = append(out, Permission{k, contribution[k]})
		}
	}
	return out
}

// WithRoleGrants returns a copy of c whose owner, admin and member templates also grant contributed
// permissions: grants maps a role slug to permission keys (the host's or a plugin's). Every new
// organization's copy of the role starts with them, and Seed gives a grant new to a template to
// every existing organization's copy, once. It refuses another slug (superadmin already holds
// every permission; a custom role belongs to its organization), a key the catalog lacks, and a
// core key (the system roles' core permissions are fixed).
func (c Catalog) WithRoleGrants(grants map[string][]string) (Catalog, error) {
	known := map[string]bool{}
	for _, p := range c.Permissions() {
		known[p.Key] = true
	}
	out := Catalog{contributions: c.contributions, roleGrants: maps.Clone(c.roleGrants)}
	if out.roleGrants == nil {
		out.roleGrants = map[string][]string{}
	}
	for _, slug := range slices.Sorted(maps.Keys(grants)) {
		if slug != RoleOwner && slug != RoleAdmin && slug != RoleMember {
			return Catalog{}, fmt.Errorf("authz: role permissions: %q is not a system role; use owner, admin or member (custom roles are granted per organization through /orgs/{id}/roles)", slug)
		}
		keys := slices.Clone(out.roleGrants[slug])
		for _, key := range grants[slug] {
			switch {
			case isCore(key):
				return Catalog{}, fmt.Errorf("authz: role permissions: %s on %s is a core permission; the system roles' core permissions are fixed (edit an organization's admin or member role through /orgs/{id}/roles)", key, slug)
			case !known[key]:
				return Catalog{}, fmt.Errorf("authz: role permissions: %s on %s is not in the catalog; declare it in Config.Permissions (or add the plugin that contributes it to Config.Plugins)", key, slug)
			case !slices.Contains(keys, key):
				keys = append(keys, key)
			}
		}
		slices.Sort(keys)
		out.roleGrants[slug] = keys
	}
	return out, nil
}

func isCore(key string) bool {
	return slices.ContainsFunc(corePermissions, func(p Permission) bool { return p.Key == key })
}

// RoleTemplates returns the system role templates in seed order: owner (every org permission),
// admin (owner without org.delete), member (read-only) and superadmin (every core permission).
// Contributed permissions are granted only as WithRoleGrants says.
func (c Catalog) RoleTemplates() []RoleTemplate {
	var all, orgScoped, adminRole []string
	for _, p := range corePermissions {
		all = append(all, p.Key)
		if slices.Contains(adminScoped, p.Key) {
			continue
		}
		orgScoped = append(orgScoped, p.Key)
		if p.Key != OrgDelete {
			adminRole = append(adminRole, p.Key)
		}
	}
	return []RoleTemplate{
		{RoleOwner, "Owner", "Full control of the organization, including deletion and ownership transfer", append(orgScoped, c.roleGrants[RoleOwner]...)},
		{RoleAdmin, "Administrator", "Manage the organization and its members, but cannot delete it or transfer ownership", append(adminRole, c.roleGrants[RoleAdmin]...)},
		{RoleMember, "Member", "Read-only access to the organization, its members and roles", append([]string{OrgRead, MembersRead, RolesRead}, c.roleGrants[RoleMember]...)},
		{RoleSuperadmin, "Super Admin", "Platform operator with a global override across all organizations", all},
	}
}
