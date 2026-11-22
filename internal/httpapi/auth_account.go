package httpapi

import (
	"context"
	"errors"
	"net/http"
	"unicode/utf8"

	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/internal/strutil"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/manifest"
)

const (
	authDisplayNameMax  = 120
	authRegisterGeneric = "If the address can be registered, a verification message has been sent."
	authResendGeneric   = "If the address is registered and unverified, a new verification message has been sent."
	authForgotGeneric   = "If an account exists for that address, a password reset link has been sent."
	authInvalidEmail    = "A valid email address is required."
)

func authMessage(status int, message string) endpoint.Result {
	return endpoint.JSON(status, map[string]any{"message": message})
}

func authStatus(status string) endpoint.Result {
	return endpoint.Data(http.StatusOK, map[string]any{"status": status})
}

// authPolicy answers the 422 of a new password failing the policy; ok is false for any other error.
func authPolicy(err error) (endpoint.Result, bool) {
	var pe *identity.PasswordError
	if errors.As(err, &pe) {
		return endpoint.Unprocessable(pe.Violations), true
	}
	return endpoint.Result{}, false
}

func (a *authAPI) register(ctx context.Context, in *endpoint.Input) endpoint.Result {
	email := strutil.Trim(in.String("email"))
	password := in.String("password")
	if email == "" || password == "" {
		return endpoint.Unprocessable([]string{"An email and password are required."})
	}
	if !manifest.IsEmail(email) {
		return endpoint.Unprocessable([]string{authInvalidEmail})
	}
	displayName, _ := in.Value("display_name").(string)
	displayName = strutil.Trim(displayName)
	if utf8.RuneCountInString(displayName) > authDisplayNameMax {
		return endpoint.Unprocessable([]string{"The display name is too long."})
	}
	if err := services.Of(a.g).Identity.Register(ctx, email, password, displayName, endpoint.Client(ctx)); err != nil {
		if r, ok := authPolicy(err); ok {
			return r
		}
		return a.fail(ctx, "register", err)
	}
	return authMessage(http.StatusAccepted, authRegisterGeneric)
}

func (a *authAPI) verifyEmail(ctx context.Context, in *endpoint.Input) endpoint.Result {
	secret := strutil.Trim(in.String("token"))
	if secret == "" {
		return endpoint.Unprocessable([]string{"A verification token is required."})
	}
	switch err := services.Of(a.g).Identity.VerifyEmail(ctx, secret); {
	case errors.Is(err, identity.ErrInvalidVerificationToken):
		return authMessage(http.StatusBadRequest, "The verification token is invalid or has expired.")
	case err != nil:
		return a.fail(ctx, "verify email", err)
	}
	return authMessage(http.StatusOK, "Email verified.")
}

func (a *authAPI) resendVerification(ctx context.Context, in *endpoint.Input) endpoint.Result {
	email := strutil.Trim(in.String("email"))
	if email == "" || !manifest.IsEmail(email) {
		return endpoint.Unprocessable([]string{authInvalidEmail})
	}
	if err := services.Of(a.g).Identity.ResendVerification(ctx, email, endpoint.Client(ctx)); err != nil {
		return a.fail(ctx, "resend verification", err)
	}
	return authMessage(http.StatusAccepted, authResendGeneric)
}

func (a *authAPI) forgotPassword(ctx context.Context, in *endpoint.Input) endpoint.Result {
	email := strutil.Trim(in.String("email"))
	if email == "" || !manifest.IsEmail(email) {
		return endpoint.Unprocessable([]string{authInvalidEmail})
	}
	if err := services.Of(a.g).Identity.ForgotPassword(ctx, email, endpoint.Client(ctx)); err != nil {
		return a.fail(ctx, "forgot password", err)
	}
	return authMessage(http.StatusAccepted, authForgotGeneric)
}

func (a *authAPI) resetPassword(ctx context.Context, in *endpoint.Input) endpoint.Result {
	secret := strutil.Trim(in.String("token"))
	newPassword := in.String("new_password")
	if secret == "" || newPassword == "" {
		return endpoint.Unprocessable([]string{"A token and new password are required."})
	}
	err := services.Of(a.g).Identity.ResetPassword(ctx, secret, newPassword, endpoint.Client(ctx))
	if r, ok := authPolicy(err); ok {
		return r
	}
	switch {
	case errors.Is(err, identity.ErrInvalidResetToken):
		return endpoint.Error(http.StatusUnauthorized, "invalid_token", "The reset token is invalid or has expired.")
	case err != nil:
		return a.fail(ctx, "reset password", err)
	}
	return authStatus("password_reset")
}

func (a *authAPI) changePassword(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok, userID, ok := authSubject(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	current := in.String("current_password")
	newPassword := in.String("new_password")
	if current == "" || newPassword == "" {
		return endpoint.Unprocessable([]string{"The current and new passwords are required."})
	}
	err := services.Of(a.g).Identity.ChangePassword(ctx, userID, current, newPassword, authSessionID(tok))
	if r, ok := authPolicy(err); ok {
		return r
	}
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials):
		return endpoint.Error(http.StatusForbidden, "invalid_credentials", "The current password is incorrect.")
	case errors.Is(err, identity.ErrAccountDisabled):
		return endpoint.Error(http.StatusForbidden, "account_disabled", "This account is disabled.")
	case err != nil:
		return a.fail(ctx, "change password", err)
	}
	return authStatus("password_changed")
}
