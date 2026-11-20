package model

import "time"

// Organization statuses (auth_organizations.status).
const (
	OrganizationStatusActive    = "active"
	OrganizationStatusSuspended = "suspended"
)

// Organization is a row of auth_organizations.
type Organization struct {
	ID        string
	Name      string
	Slug      string
	Status    string // "" is written as OrganizationStatusActive, the column default
	CreatedBy string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Membership statuses (auth_memberships.status).
const (
	MembershipStatusInvited   = "invited"
	MembershipStatusActive    = "active"
	MembershipStatusSuspended = "suspended"
)

// Membership is a row of auth_memberships: a user in an organization.
type Membership struct {
	ID             string
	UserID         string
	OrganizationID string
	Status         string // "" is written as MembershipStatusInvited, the column default
	InvitedBy      *string
	JoinedAt       *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// MembershipRole is a row of auth_membership_roles: a role held through a membership.
type MembershipRole struct {
	MembershipID string
	RoleID       string
}

// Role is a row of auth_roles; OrganizationID is nil for a global system role.
type Role struct {
	ID             string
	OrganizationID *string
	Name           string
	Slug           string
	Description    *string
	IsSystem       bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// RolePermission is a row of auth_role_permissions: a permission granted to a role.
type RolePermission struct {
	RoleID       string
	PermissionID string
}

// Permission is a row of auth_permissions.
type Permission struct {
	ID          string
	Key         string
	Description string
}

// Invitation is a row of auth_invitations.
type Invitation struct {
	ID             string
	OrganizationID string
	Email          string
	RoleIDs        []string // stored as a JSON list; nil is written as []
	TokenHash      string
	InvitedBy      string
	ExpiresAt      time.Time
	AcceptedAt     *time.Time
	CreatedAt      time.Time
}
