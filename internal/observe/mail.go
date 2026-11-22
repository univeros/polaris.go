package observe

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/repository"
)

// tombstoneSuffix ends the email of an erased (anonymized) user, who is never mailed.
const tombstoneSuffix = "@deleted.invalid"

// MailUsers finds a recipient by id; repository.Users is the implementation. A missing user is
// repository.ErrNotFound.
type MailUsers interface {
	Get(ctx context.Context, id string) (model.User, error)
}

// Mail returns the listener that turns user-facing core events into emails on m:
//
//	user.registered                → verify_email               {token}           to the event's email
//	user.password_reset_requested  → password_reset             {token}           to the event's email
//	member.invited                 → org_invite                 {token, organization_id} to the invitee
//	user.locked                    → account_locked             {ip}              to the user
//	user.password_changed          → password_changed           {method}          to the user
//	mfa.enrolled                   → mfa_enrolled               {factor_id}       to the user
//	mfa.factor_removed             → mfa_factor_removed         {factor_id}       to the user
//	mfa.recovery_regenerated       → recovery_codes_regenerated {}                to the user
//	mfa.recovery_used              → recovery_code_used         {remaining}       to the user
//
// The token-carrying events forward their single-use plaintext token: the one place it may
// travel. The others look the user up in users; unknown users and erased ones (a tombstone email)
// are skipped. SMS codes are sent by the OTP flow itself, not here.
//
// A failure is logged on logger (nil: slog.Default()) and swallowed: a notification never breaks
// the operation that triggered it.
func Mail(m notify.Mailer, users MailUsers, logger *slog.Logger) event.Listener {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, e event.Event) {
		if err := sendMail(ctx, m, users, e); err != nil {
			logger.ErrorContext(ctx, "Notification failed for "+e.EventName(), "event", e.EventName(), "reason", err.Error())
		}
	}
}

func sendMail(ctx context.Context, m notify.Mailer, users MailUsers, e event.Event) error {
	toUser := func(userID, template string, data map[string]any) error {
		u, err := users.Get(ctx, userID)
		if errors.Is(err, repository.ErrNotFound) || err == nil && strings.HasSuffix(u.Email, tombstoneSuffix) {
			return nil
		}
		if err != nil {
			return err
		}
		return m.Send(ctx, u.Email, template, data)
	}
	switch e := e.(type) {
	case event.UserRegistered:
		if e.VerificationToken == "" { // created verified (Users().Create): nothing to verify
			return nil
		}
		return m.Send(ctx, e.Email, notify.TemplateVerifyEmail, map[string]any{"token": e.VerificationToken})
	case event.PasswordResetRequested:
		return m.Send(ctx, e.Email, notify.TemplatePasswordReset, map[string]any{"token": e.ResetToken})
	case event.MemberInvited:
		return m.Send(ctx, e.Email, notify.TemplateOrgInvite, map[string]any{"token": e.InviteToken, "organization_id": e.OrganizationID})
	case event.UserLocked:
		var ip any
		if e.IP != nil {
			ip = *e.IP
		}
		return toUser(e.UserID, notify.TemplateAccountLocked, map[string]any{"ip": ip})
	case event.PasswordChanged:
		return toUser(e.UserID, notify.TemplatePasswordChanged, map[string]any{"method": e.Method})
	case event.MFAEnrolled:
		return toUser(e.UserID, notify.TemplateMFAEnrolled, map[string]any{"factor_id": e.FactorID})
	case event.MFAFactorRemoved:
		return toUser(e.UserID, notify.TemplateMFAFactorRemoved, map[string]any{"factor_id": e.FactorID})
	case event.MFARecoveryRegenerated:
		return toUser(e.UserID, notify.TemplateRecoveryCodesRegenerated, map[string]any{})
	case event.MFARecoveryUsed:
		return toUser(e.UserID, notify.TemplateRecoveryCodeUsed, map[string]any{"remaining": e.Remaining})
	}
	return nil
}
