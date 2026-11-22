package notify

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// The templates Polaris asks a Mailer to render.
const (
	TemplateVerifyEmail              = "verify_email"
	TemplatePasswordReset            = "password_reset"
	TemplateOrgInvite                = "org_invite"
	TemplateOTPCode                  = "otp_code"
	TemplateAccountLocked            = "account_locked"
	TemplatePasswordChanged          = "password_changed"
	TemplateMFAEnrolled              = "mfa_enrolled"
	TemplateMFAFactorRemoved         = "mfa_factor_removed"
	TemplateRecoveryCodeUsed         = "recovery_code_used"
	TemplateRecoveryCodesRegenerated = "recovery_codes_regenerated"
)

var subjects = map[string]string{
	TemplateVerifyEmail:              "Verify your email address",
	TemplatePasswordReset:            "Reset your password",
	TemplateOrgInvite:                "You have been invited to an organization",
	TemplateOTPCode:                  "Your verification code",
	TemplateAccountLocked:            "Your account has been locked",
	TemplatePasswordChanged:          "Your password was changed",
	TemplateMFAEnrolled:              "A new authentication factor was added",
	TemplateMFAFactorRemoved:         "An authentication factor was removed",
	TemplateRecoveryCodeUsed:         "A recovery code was used",
	TemplateRecoveryCodesRegenerated: "Your recovery codes were regenerated",
}

// Subject is the plain-text subject of template, "Account notification" for unknown ones.
// The application owns its wording; this is the working default for mail adapters.
func Subject(template string) string {
	if s, ok := subjects[template]; ok {
		return s
	}
	return "Account notification"
}

// Text is the plain-text body of template rendered with data. Templates without a dedicated
// body list their data, one "key: value" line each, keys sorted.
func Text(template string, data map[string]any) string {
	value := func(key string) string {
		s, _ := scalar(data[key])
		return s
	}
	switch template {
	case TemplateVerifyEmail:
		return fmt.Sprintf("Use this token to verify your email address:\n\n%s\n", value("token"))
	case TemplatePasswordReset:
		return fmt.Sprintf("Use this token to reset your password. If you did not ask for a reset, ignore this message.\n\n%s\n", value("token"))
	case TemplateOrgInvite:
		return fmt.Sprintf("You have been invited to join organization %s. Use this token to accept the invitation:\n\n%s\n", value("organization_id"), value("token"))
	case TemplateOTPCode:
		ttl, _ := strconv.Atoi(value("ttl"))
		return fmt.Sprintf("Your verification code is %s. It expires in %d seconds.\n", value("code"), ttl)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Notification: %s\n", template)
	for _, key := range slices.Sorted(maps.Keys(data)) {
		s, ok := scalar(data[key])
		if !ok {
			s = encode(data[key])
		}
		fmt.Fprintf(&b, "%s: %s\n", key, s)
	}
	return b.String()
}

// scalar renders a scalar v as template text: strings as is, true "1", false "", integers in
// decimal, floats in the shortest form without an exponent. ok is false for nil and non-scalar
// values.
func scalar(v any) (string, bool) {
	switch v := v.(type) {
	case string:
		return v, true
	case bool:
		if v {
			return "1", true
		}
		return "", true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(v), true
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	}
	return "", false
}

func encode(v any) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Sprint(v)
	}
	return strings.TrimSuffix(b.String(), "\n")
}
