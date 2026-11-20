package model

import "time"

// MFA factor types (auth_mfa_factors.type).
const (
	FactorTOTP  = "totp"
	FactorSMS   = "sms"
	FactorEmail = "email"
)

// MFAFactor is a row of auth_mfa_factors.
type MFAFactor struct {
	ID              string
	UserID          string
	Type            string
	Label           *string
	SecretEncrypted *string
	PhoneE164       *string
	Email           *string
	IsDefault       bool
	ConfirmedAt     *time.Time
	LastUsedAt      *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// OTP challenge channels (auth_otp_challenges.channel).
const (
	ChannelSMS   = "sms"
	ChannelEmail = "email"
	ChannelTOTP  = "totp"
)

// DefaultMaxAttempts is the column default of auth_otp_challenges.max_attempts.
const DefaultMaxAttempts = 5

// OTPChallenge is a row of auth_otp_challenges.
type OTPChallenge struct {
	ID          string
	UserID      string
	FactorID    *string
	Purpose     string
	Channel     string
	CodeHash    *string
	Destination *string
	Attempts    int
	MaxAttempts int // 0 is written as DefaultMaxAttempts, the column default
	ExpiresAt   time.Time
	ConsumedAt  *time.Time
	IP          *string
	CreatedAt   time.Time
}

// RecoveryCode is a row of auth_recovery_codes.
type RecoveryCode struct {
	ID        string
	UserID    string
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}
