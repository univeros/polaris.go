package identity

import (
	"context"
	"errors"
)

// ErrInvalidConfig: New was given an incomplete Config.
var ErrInvalidConfig = errors.New("identity: invalid configuration")

func refuse(kind error, message string) error { return &Error{Kind: kind, Message: message} }

// Client-facing messages: clients may match on them, so they do not change.
const (
	msgInvalidCredentials = "Invalid email or password."
	msgWrongPassword      = "The current password is incorrect."
	msgDisabled           = "This account is disabled."
	msgUnverified         = "Email address is not verified."
	msgBadVerification    = "The verification token is invalid."
	msgExpiredVerify      = "The verification token has expired."
	msgBadReset           = "The reset token is invalid or expired."
	msgUserNotFound       = "The user does not exist."
	msgSelfDisable        = "You cannot disable your own account."
	msgTombstone          = "The account has been anonymized and cannot be re-enabled."
	msgDisplayNameTooLong = "The display name must be 120 characters or fewer."
	msgOwnAccountOnly     = "You may only manage your own account."
	msgInvalidEmail       = "A valid email address is required."
	msgEmailTaken         = "The email address is already registered."
)

func enforce(ctx context.Context, p PasswordPolicy, password string) error {
	if v := p.Validate(ctx, password); len(v) > 0 {
		return &PasswordError{Violations: v}
	}
	return nil
}
