package repository

import "github.com/univeros/polaris-go/store"

// Repos bundles every core repository over one adapter. Run related writes atomically with
// DB.Tx, passing the ctx it gives to each repository call.
type Repos struct {
	DB                 store.Adapter
	Users              Users
	EmailVerifications EmailVerifications
	PasswordResets     PasswordResets
	RefreshTokens      RefreshTokens
	AuditLog           AuditLog
	MFAFactors         MFAFactors
	OTPChallenges      OTPChallenges
	RecoveryCodes      RecoveryCodes
	Organizations      Organizations
	Memberships        Memberships
	MembershipRoles    MembershipRoles
	Roles              Roles
	RolePermissions    RolePermissions
	Permissions        Permissions
	Invitations        Invitations
}

// New builds every core repository over db.
func New(db store.Adapter) *Repos {
	return &Repos{
		DB:                 db,
		Users:              newUsers(db),
		EmailVerifications: newEmailVerifications(db),
		PasswordResets:     newPasswordResets(db),
		RefreshTokens:      newRefreshTokens(db),
		AuditLog:           newAuditLog(db),
		MFAFactors:         newMFAFactors(db),
		OTPChallenges:      newOTPChallenges(db),
		RecoveryCodes:      newRecoveryCodes(db),
		Organizations:      newOrganizations(db),
		Memberships:        newMemberships(db),
		MembershipRoles:    newMembershipRoles(db),
		Roles:              newRoles(db),
		RolePermissions:    newRolePermissions(db),
		Permissions:        newPermissions(db),
		Invitations:        newInvitations(db),
	}
}
