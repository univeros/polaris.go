// Package authz is Polaris's role-based authorization: the
// code-defined permission catalog and its seeder, the resolver that turns a user and an active
// organization into an Authority (role slugs and permission keys), the Gate that checks it, the
// escalation guard and the session-principal resolver that puts roles into access tokens.
//
// Authority is always read from the database, never trusted from token claims, so a role or
// membership change takes effect on the next request.
package authz

import (
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
}

// NewCatalog returns the core catalog extended by contributions (key → description), applied in
// order: a contributed key overrides a core or earlier description in place.
func NewCatalog(contributions ...map[string]string) Catalog {
	return Catalog{contributions: slices.Clone(contributions)}
}

// Permissions returns the full catalog: core permissions in upstream order, then contributed keys
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

// RoleTemplates returns the system role templates in seed order: owner (every org permission),
// admin (owner without org.delete), member (read-only) and superadmin (every core permission).
// Contributed permissions are granted to no template.
func (Catalog) RoleTemplates() []RoleTemplate {
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
		{RoleOwner, "Owner", "Full control of the organization, including deletion and ownership transfer", orgScoped},
		{RoleAdmin, "Administrator", "Manage the organization and its members, but cannot delete it or transfer ownership", adminRole},
		{RoleMember, "Member", "Read-only access to the organization, its members and roles", []string{OrgRead, MembersRead, RolesRead}},
		{RoleSuperadmin, "Super Admin", "Platform operator with a global override across all organizations", all},
	}
}
