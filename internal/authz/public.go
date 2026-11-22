package authz

import pub "github.com/univeros/polaris.go/authz"

// The names of the public package authz (the v1 API), repeated here so this package's
// code and its callers inside the module read as one package.
type (
	Authority      = pub.Authority
	Caller         = pub.Caller
	Catalog        = pub.Catalog
	ForbiddenError = pub.ForbiddenError
	Permission     = pub.Permission
	RoleTemplate   = pub.RoleTemplate
)

// The public constants.
const (
	AuditRead      = pub.AuditRead
	MembersInvite  = pub.MembersInvite
	MembersRead    = pub.MembersRead
	MembersRemove  = pub.MembersRemove
	MembersUpdate  = pub.MembersUpdate
	MsgEscalation  = pub.MsgEscalation
	MsgForbidden   = pub.MsgForbidden
	OrgDelete      = pub.OrgDelete
	OrgRead        = pub.OrgRead
	OrgUpdate      = pub.OrgUpdate
	RoleAdmin      = pub.RoleAdmin
	RoleMember     = pub.RoleMember
	RoleOwner      = pub.RoleOwner
	RoleSuperadmin = pub.RoleSuperadmin
	RolesManage    = pub.RolesManage
	RolesRead      = pub.RolesRead
	UsersManage    = pub.UsersManage
	UsersRead      = pub.UsersRead
)

// The public errors.
var (
	ErrForbidden = pub.ErrForbidden
)

// The public functions.
var (
	Forbidden  = pub.Forbidden
	NewCatalog = pub.NewCatalog
)
