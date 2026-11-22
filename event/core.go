package event

import (
	"fmt"
	"log/slog"
	"time"
)

// The core events, one struct per event. EventName returns the event's wire name; the fields are
// its payload, with nullable values as pointers. Every domain
// package (identity, mfa, organizations, session) dispatches these, and listeners (audit log,
// metrics, notifications) switch on the type or on EventName.

// Event names: the wire and audit-log identifiers. Stored audit rows and listeners match on them,
// so they never change.
const (
	NameMemberInvited          = "member.invited"
	NameMemberJoined           = "member.joined"
	NameMemberRemoved          = "member.removed"
	NameMemberRolesChanged     = "member.roles_changed"
	NameMemberStatusChanged    = "member.status_changed"
	NameMFAEnrolled            = "mfa.enrolled"
	NameMFAFactorRemoved       = "mfa.factor_removed"
	NameMFARecoveryRegenerated = "mfa.recovery_regenerated"
	NameMFARecoveryUsed        = "mfa.recovery_used"
	NameMFAStepUpCompleted     = "mfa.step_up_completed"
	NameMFAVerified            = "mfa.verified"
	NameMFAVerifyFailed        = "mfa.verify_failed"
	NameOrganizationCreated    = "org.created"
	NameOrganizationDeleted    = "org.deleted"
	NameOrganizationSwitched   = "auth.org_switched"
	NameOrganizationUpdated    = "org.updated"
	NameOTPChallengeSent       = "mfa.otp_challenge_sent"
	NameOTPVerifyFailed        = "mfa.otp_verify_failed"
	NamePasswordChanged        = "user.password_changed"
	NamePasswordResetRequested = "user.password_reset_requested"
	NameRefreshReuseDetected   = "auth.refresh_reuse_detected"
	NameRoleCreated            = "role.created"
	NameRoleDeleted            = "role.deleted"
	NameRoleUpdated            = "role.updated"
	NameSessionsRevoked        = "auth.sessions_revoked"
	NameTokenRefreshed         = "auth.token_refreshed"
	NameUserDeleted            = "user.deleted"
	NameUserDisabled           = "user.disabled"
	NameUserEmailVerified      = "user.email_verified"
	NameUserEnabled            = "user.enabled"
	NameUserLocked             = "user.locked"
	NameUserLoggedIn           = "user.logged_in"
	NameUserLoginFailed        = "user.login_failed"
	NameUserRegistered         = "user.registered"
)

// Payload values with a fixed vocabulary.
const (
	// MFAVerifyFailedTypeRecovery is MFAVerifyFailed.Type on the factor-less recovery-code path.
	MFAVerifyFailedTypeRecovery = "recovery"
	// PasswordChanged.Method values.
	PasswordMethodReset  = "reset"
	PasswordMethodChange = "change"
	// LoginFailedInvalidCredentials is the default UserLoginFailed.Reason.
	LoginFailedInvalidCredentials = "invalid_credentials"
)

const redacted = "[redacted]"

// MemberInvited: an invitation was created. InviteToken is the plaintext invitation secret for the
// notification listener; it never reaches fmt or slog output.
type MemberInvited struct {
	OrganizationID string
	Email          string
	InvitedBy      string
	InviteToken    string
}

// MemberJoined: a user accepted an invitation and became a member.
type MemberJoined struct {
	OrganizationID string
	UserID         string
	Email          string
}

// MemberRemoved: a member was removed from an organization.
type MemberRemoved struct {
	OrganizationID string
	UserID         string
	ActorUserID    string
}

// MemberRolesChanged: a member's role set was replaced; RoleSlugs is the new set.
type MemberRolesChanged struct {
	OrganizationID string
	UserID         string
	RoleSlugs      []string
	ActorUserID    string
}

// MemberStatusChanged: a membership was suspended or reactivated.
type MemberStatusChanged struct {
	OrganizationID string
	UserID         string
	Status         string
	ActorUserID    string
}

// MFAEnrolled: a factor was confirmed. Type is the factor type, nil when unknown.
type MFAEnrolled struct {
	UserID   string
	FactorID string
	Type     *string
}

// MFAFactorRemoved: a factor was deleted.
type MFAFactorRemoved struct {
	UserID   string
	FactorID string
}

// MFARecoveryRegenerated: a user's recovery codes were regenerated.
type MFARecoveryRegenerated struct {
	UserID string
}

// MFARecoveryUsed: a recovery code was spent; Remaining codes are left.
type MFARecoveryUsed struct {
	UserID    string
	Remaining int
}

// MFAStepUpCompleted: a session re-authenticated with a second factor.
type MFAStepUpCompleted struct {
	UserID    string
	SessionID string
}

// MFAVerified: the login MFA gate was cleared; FactorID is nil on the recovery-code path.
type MFAVerified struct {
	UserID   string
	FactorID *string
}

// MFAVerifyFailed: a second-factor code was refused. Type is MFAVerifyFailedTypeRecovery on the
// recovery-code path.
type MFAVerifyFailed struct {
	UserID   string
	FactorID *string
	Type     *string
}

// OrganizationCreated: an organization was created with its first owner.
type OrganizationCreated struct {
	OrganizationID string
	Slug           string
	OwnerUserID    string
}

// OrganizationDeleted: an organization was (soft-)deleted.
type OrganizationDeleted struct {
	OrganizationID string
	ActorUserID    string
}

// OrganizationSwitched: a session was re-scoped to another organization; FromOrganizationID is
// nil when the session had none.
type OrganizationSwitched struct {
	UserID             string
	FromOrganizationID *string
	ToOrganizationID   string
}

// OrganizationUpdated: an organization's profile changed.
type OrganizationUpdated struct {
	OrganizationID string
	ActorUserID    string
}

// OTPChallengeSent: a one-time code was sent over Channel (sms, email).
type OTPChallengeSent struct {
	UserID   string
	FactorID string
	Channel  string
}

// OTPVerifyFailed: a one-time code was refused; AttemptsLeft is nil when unknown.
type OTPVerifyFailed struct {
	UserID       string
	FactorID     string
	AttemptsLeft *int
}

// PasswordChanged: a password was replaced; Method is PasswordMethodReset or PasswordMethodChange.
type PasswordChanged struct {
	UserID string
	Method string
}

// PasswordResetRequested: a reset was requested. ResetToken is the plaintext secret for the
// notification listener; it never reaches fmt or slog output.
type PasswordResetRequested struct {
	UserID     string
	Email      string
	ResetToken string
}

// RefreshReuseDetected: an already-rotated refresh token was replayed and its whole family was
// revoked. IP and UserAgent are the replaying client's, nil when unknown.
type RefreshReuseDetected struct {
	UserID    string
	FamilyID  string
	IP        *string
	UserAgent *string
}

// RoleCreated: a custom role was created.
type RoleCreated struct {
	OrganizationID string
	RoleID         string
	ActorUserID    string
}

// RoleDeleted: a custom role was deleted.
type RoleDeleted struct {
	OrganizationID string
	RoleID         string
	ActorUserID    string
}

// RoleUpdated: a role's name, description or permissions changed.
type RoleUpdated struct {
	OrganizationID string
	RoleID         string
	ActorUserID    string
}

// SessionsRevoked: every session of a user was revoked (logout everywhere). Count is the number
// of sessions; Reason is a model.Revoked* value (model.RevokedLogout for a logout everywhere).
type SessionsRevoked struct {
	UserID string
	IP     *string
	Count  int
	Reason string
}

// TokenRefreshed: a refresh token was exchanged for a new pair.
type TokenRefreshed struct {
	UserID   string
	FamilyID string
}

// UserDeleted: an account was erased.
type UserDeleted struct {
	UserID      string
	ActorUserID string
}

// UserDisabled: an administrator disabled an account.
type UserDisabled struct {
	UserID      string
	ActorUserID string
}

// UserEmailVerified: an email address was verified.
type UserEmailVerified struct {
	UserID string
	Email  string
}

// UserEnabled: an administrator re-enabled an account.
type UserEnabled struct {
	UserID      string
	ActorUserID string
}

// UserLocked: too many failed logins locked an account; Until is nil when unknown.
type UserLocked struct {
	UserID string
	IP     *string
	Until  *time.Time
}

// UserLoggedIn: a session was opened. AMR lists the authentication methods; producers always set it
// (["pwd"] for a password login).
type UserLoggedIn struct {
	UserID    string
	SessionID string
	IP        *string
	UserAgent *string
	AMR       []string
}

// UserLoginFailed: a login attempt failed; Reason is LoginFailedInvalidCredentials unless the
// producer says otherwise.
type UserLoginFailed struct {
	UserID    string
	IP        *string
	UserAgent *string
	Reason    string
}

// UserRegistered: an account was created. VerificationToken ("" when created verified) is the plaintext email-verification
// secret for the notification listener; it never reaches fmt or slog output.
type UserRegistered struct {
	UserID            string
	Email             string
	VerificationToken string
}

// EventName implements Event.
func (MemberInvited) EventName() string { return NameMemberInvited }

// EventName implements Event.
func (MemberJoined) EventName() string { return NameMemberJoined }

// EventName implements Event.
func (MemberRemoved) EventName() string { return NameMemberRemoved }

// EventName implements Event.
func (MemberRolesChanged) EventName() string { return NameMemberRolesChanged }

// EventName implements Event.
func (MemberStatusChanged) EventName() string { return NameMemberStatusChanged }

// EventName implements Event.
func (MFAEnrolled) EventName() string { return NameMFAEnrolled }

// EventName implements Event.
func (MFAFactorRemoved) EventName() string { return NameMFAFactorRemoved }

// EventName implements Event.
func (MFARecoveryRegenerated) EventName() string { return NameMFARecoveryRegenerated }

// EventName implements Event.
func (MFARecoveryUsed) EventName() string { return NameMFARecoveryUsed }

// EventName implements Event.
func (MFAStepUpCompleted) EventName() string { return NameMFAStepUpCompleted }

// EventName implements Event.
func (MFAVerified) EventName() string { return NameMFAVerified }

// EventName implements Event.
func (MFAVerifyFailed) EventName() string { return NameMFAVerifyFailed }

// EventName implements Event.
func (OrganizationCreated) EventName() string { return NameOrganizationCreated }

// EventName implements Event.
func (OrganizationDeleted) EventName() string { return NameOrganizationDeleted }

// EventName implements Event.
func (OrganizationSwitched) EventName() string { return NameOrganizationSwitched }

// EventName implements Event.
func (OrganizationUpdated) EventName() string { return NameOrganizationUpdated }

// EventName implements Event.
func (OTPChallengeSent) EventName() string { return NameOTPChallengeSent }

// EventName implements Event.
func (OTPVerifyFailed) EventName() string { return NameOTPVerifyFailed }

// EventName implements Event.
func (PasswordChanged) EventName() string { return NamePasswordChanged }

// EventName implements Event.
func (PasswordResetRequested) EventName() string { return NamePasswordResetRequested }

// EventName implements Event.
func (RefreshReuseDetected) EventName() string { return NameRefreshReuseDetected }

// EventName implements Event.
func (RoleCreated) EventName() string { return NameRoleCreated }

// EventName implements Event.
func (RoleDeleted) EventName() string { return NameRoleDeleted }

// EventName implements Event.
func (RoleUpdated) EventName() string { return NameRoleUpdated }

// EventName implements Event.
func (SessionsRevoked) EventName() string { return NameSessionsRevoked }

// EventName implements Event.
func (TokenRefreshed) EventName() string { return NameTokenRefreshed }

// EventName implements Event.
func (UserDeleted) EventName() string { return NameUserDeleted }

// EventName implements Event.
func (UserDisabled) EventName() string { return NameUserDisabled }

// EventName implements Event.
func (UserEmailVerified) EventName() string { return NameUserEmailVerified }

// EventName implements Event.
func (UserEnabled) EventName() string { return NameUserEnabled }

// EventName implements Event.
func (UserLocked) EventName() string { return NameUserLocked }

// EventName implements Event.
func (UserLoggedIn) EventName() string { return NameUserLoggedIn }

// EventName implements Event.
func (UserLoginFailed) EventName() string { return NameUserLoginFailed }

// EventName implements Event.
func (UserRegistered) EventName() string { return NameUserRegistered }

// LogValue keeps the invitation token out of logs.
func (e MemberInvited) LogValue() slog.Value {
	return slog.GroupValue(slog.String("organization_id", e.OrganizationID), slog.String("email", e.Email),
		slog.String("invited_by", e.InvitedBy), slog.String("invite_token", redacted))
}

// String keeps the invitation token out of fmt output.
func (e MemberInvited) String() string { return format(e) }

// GoString keeps the invitation token out of %#v output.
func (e MemberInvited) GoString() string { return format(e) }

// LogValue keeps the reset token out of logs.
func (e PasswordResetRequested) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user_id", e.UserID), slog.String("email", e.Email),
		slog.String("reset_token", redacted))
}

// String keeps the reset token out of fmt output.
func (e PasswordResetRequested) String() string { return format(e) }

// GoString keeps the reset token out of %#v output.
func (e PasswordResetRequested) GoString() string { return format(e) }

// LogValue keeps the verification token out of logs.
func (e UserRegistered) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user_id", e.UserID), slog.String("email", e.Email),
		slog.String("verification_token", redacted))
}

// String keeps the verification token out of fmt output.
func (e UserRegistered) String() string { return format(e) }

// GoString keeps the verification token out of %#v output.
func (e UserRegistered) GoString() string { return format(e) }

func format(e interface {
	Event
	slog.LogValuer
}) string {
	return fmt.Sprintf("event.%s%s", e.EventName(), e.LogValue().String())
}
