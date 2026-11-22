// Package model holds core's records as plain Go values, one struct per table of
// schema.Core(). Datetimes are time.Time (UTC, stored to the second); nullable columns are
// pointers; JSON columns are typed. The repository package reads and writes them.
package model

import (
	"encoding/json"
	"time"
)

// User statuses (auth_users.status).
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
	UserStatusLocked   = "locked"
)

// User is a row of auth_users.
type User struct {
	ID               string
	Email            string
	EmailVerifiedAt  *time.Time
	PasswordHash     *string
	DisplayName      *string
	Status           string // "" is written as UserStatusActive, the column default
	MFAEnforced      bool
	FailedLoginCount int
	FailedLoginAt    *time.Time
	LockedUntil      *time.Time
	LastLoginAt      *time.Time
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// EmailVerification is a row of auth_email_verifications.
type EmailVerification struct {
	ID         string
	UserID     string
	Email      string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	IP         *string
	CreatedAt  time.Time
}

// PasswordReset is a row of auth_password_resets.
type PasswordReset struct {
	ID         string
	UserID     string
	Email      string
	TokenHash  string
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	IP         *string
	CreatedAt  time.Time
}

// Refresh-token revocation reasons (auth_refresh_tokens.revoked_reason).
const (
	RevokedRotated        = "rotated"
	RevokedLogout         = "logout"
	RevokedReuseDetected  = "reuse_detected"
	RevokedAdmin          = "admin"
	RevokedPasswordChange = "password_change"
)

// RefreshToken is a row of auth_refresh_tokens: one rotation of a session (FamilyID is the
// session id).
type RefreshToken struct {
	ID             string
	UserID         string
	OrganizationID *string
	FamilyID       string
	ParentID       *string
	TokenHash      string
	UserAgent      *string
	IP             *string
	MFA            bool
	AMR            *string
	AuthTime       *int64 // Unix seconds
	ExpiresAt      time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
	RevokedReason  *string
	CreatedAt      time.Time
}

// AuditLogEntry is a row of auth_audit_log, append only.
type AuditLogEntry struct {
	ID             string
	ActorUserID    *string
	OrganizationID *string
	Event          string
	IP             *string
	UserAgent      *string
	// Metadata is stored verbatim. PHP writes json_encode($metadata) with default flags: keys in
	// insertion order, "\/" and \uXXXX escapes, and "[]" for no metadata (nil is written as "[]").
	Metadata  json.RawMessage
	CreatedAt time.Time
}
