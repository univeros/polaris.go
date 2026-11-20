package messaging

import (
	"context"
	"slices"

	"github.com/univeros/polaris.go/notify"
)

// CoreTemplates maps the templates core asks its Mailer for onto the plugin's keys; a name not
// listed goes as "email.<name>".
var CoreTemplates = map[string]string{
	notify.TemplateVerifyEmail:              "email.verify",
	notify.TemplatePasswordReset:            "email.reset_password",
	notify.TemplateOrgInvite:                "email.invite",
	notify.TemplateOTPCode:                  "email.otp",
	notify.TemplateAccountLocked:            "email.account_locked",
	notify.TemplatePasswordChanged:          "email.password_changed",
	notify.TemplateMFAEnrolled:              "email.mfa_enrolled",
	notify.TemplateMFAFactorRemoved:         "email.mfa_factor_removed",
	notify.TemplateRecoveryCodesRegenerated: "email.recovery_codes_regenerated",
	notify.TemplateRecoveryCodeUsed:         "email.recovery_code_used",
}

// essentialCore are the core mails quiet mode never drops.
var essentialCore = []string{notify.TemplateVerifyEmail, notify.TemplatePasswordReset, notify.TemplateOrgInvite, notify.TemplateOTPCode}

// mailer is core's notify.Mailer over the sender: a refused or undelivered mail is logged by the
// sender and never fails the operation that asked for it.
type mailer struct{ p *Plugin }

func (m mailer) Send(ctx context.Context, to, template string, data map[string]any) error {
	key, ok := CoreTemplates[template]
	if !ok {
		key = KindEmail + "." + template
	}
	_, err := m.p.sender.Send(ctx, Message{Kind: KindEmail, To: to, Template: key, Vars: data,
		Essential: slices.Contains(essentialCore, template)}, nil)
	if swallowed(err) {
		return nil
	}
	return err
}

// smsSender is core's notify.SMSSender: core renders the code message itself, so its text goes as
// the sms.otp template, essential, through the policy and the channels.
type smsSender struct{ p *Plugin }

func (s smsSender) Send(ctx context.Context, to, message string) error {
	_, err := s.p.sender.Deliver(ctx, Message{Kind: KindSMS, To: to, Template: "sms.otp", Text: message, Essential: true}, nil)
	if swallowed(err) {
		return nil
	}
	return err
}
