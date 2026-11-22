package notify

import (
	"strings"
	"testing"
)

func TestKnownTemplatesRenderTheirDataAndUnknownOnesListIt(t *testing.T) {
	eq := func(got, want string) {
		t.Helper()
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	eq(Subject(TemplateOTPCode), "Your verification code")
	eq(Subject("something_else"), "Account notification")
	eq(Text(TemplateOTPCode, map[string]any{"code": "123456", "ttl": 300}), "Your verification code is 123456. It expires in 300 seconds.\n")
	if got := Text(TemplateVerifyEmail, map[string]any{"token": "tok-1"}); !strings.Contains(got, "tok-1\n") {
		t.Errorf("verify_email = %q", got)
	}
	if got := Text(TemplateOrgInvite, map[string]any{"token": "t", "organization_id": "org-1"}); !strings.Contains(got, "organization org-1") {
		t.Errorf("org_invite = %q", got)
	}
	eq(Text(TemplateMFAEnrolled, map[string]any{"factor_id": "f-1", "meta": map[string]any{"a": 1}}), "Notification: mfa_enrolled\nfactor_id: f-1\nmeta: {\"a\":1}\n")
}

func TestEveryTemplateTextIsVerbatim(t *testing.T) {
	data := map[string]any{"token": "T", "organization_id": "O", "code": "C", "ttl": "300"}
	for template, want := range map[string]string{
		TemplateVerifyEmail:   "Use this token to verify your email address:\n\nT\n",
		TemplatePasswordReset: "Use this token to reset your password. If you did not ask for a reset, ignore this message.\n\nT\n",
		TemplateOrgInvite:     "You have been invited to join organization O. Use this token to accept the invitation:\n\nT\n",
		TemplateOTPCode:       "Your verification code is C. It expires in 300 seconds.\n",
	} {
		if got := Text(template, data); got != want {
			t.Errorf("%s = %q, want %q", template, got, want)
		}
	}
	for template, want := range map[string]string{
		TemplateVerifyEmail: "Verify your email address", TemplatePasswordReset: "Reset your password",
		TemplateOrgInvite: "You have been invited to an organization", TemplateOTPCode: "Your verification code",
		TemplateAccountLocked: "Your account has been locked", TemplatePasswordChanged: "Your password was changed",
		TemplateMFAEnrolled: "A new authentication factor was added", TemplateMFAFactorRemoved: "An authentication factor was removed",
		TemplateRecoveryCodeUsed: "A recovery code was used", TemplateRecoveryCodesRegenerated: "Your recovery codes were regenerated",
	} {
		if got := Subject(template); got != want {
			t.Errorf("subject %s = %q, want %q", template, got, want)
		}
	}
}

func TestScalarsRenderAsTextAndOthersAsJSON(t *testing.T) {
	got := Text("custom", map[string]any{
		"b_true": true, "c_false": false, "d_float": 1.5, "e_whole": 2.0, "f_int64": int64(-7),
		"g_nil": nil, "h_list": []string{"x/y", "<z>"}, "i_uint": uint8(3),
	})
	want := "Notification: custom\nb_true: true\nc_false: false\nd_float: 1.5\ne_whole: 2\nf_int64: -7\ng_nil: null\nh_list: [\"x/y\",\"<z>\"]\ni_uint: 3\n"
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
	// Non-scalar values in a known template render empty.
	if got := Text(TemplateOTPCode, map[string]any{"code": []int{1}, "ttl": "abc"}); got != "Your verification code is . It expires in 0 seconds.\n" {
		t.Errorf("got %q", got)
	}
	// An unencodable value does not break the mail.
	if got := Text("x", map[string]any{"f": func() {}}); !strings.HasPrefix(got, "Notification: x\nf: ") {
		t.Errorf("got %q", got)
	}
}
