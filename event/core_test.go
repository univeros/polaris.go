package event

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestCoreEventNames(t *testing.T) {
	events := []struct {
		e    Event
		name string
	}{
		{MemberInvited{}, "member.invited"},
		{MemberJoined{}, "member.joined"},
		{MemberRemoved{}, "member.removed"},
		{MemberRolesChanged{}, "member.roles_changed"},
		{MemberStatusChanged{}, "member.status_changed"},
		{MFAEnrolled{}, "mfa.enrolled"},
		{MFAFactorRemoved{}, "mfa.factor_removed"},
		{MFARecoveryRegenerated{}, "mfa.recovery_regenerated"},
		{MFARecoveryUsed{}, "mfa.recovery_used"},
		{MFAStepUpCompleted{}, "mfa.step_up_completed"},
		{MFAVerified{}, "mfa.verified"},
		{MFAVerifyFailed{}, "mfa.verify_failed"},
		{OrganizationCreated{}, "org.created"},
		{OrganizationDeleted{}, "org.deleted"},
		{OrganizationSwitched{}, "auth.org_switched"},
		{OrganizationUpdated{}, "org.updated"},
		{OTPChallengeSent{}, "mfa.otp_challenge_sent"},
		{OTPVerifyFailed{}, "mfa.otp_verify_failed"},
		{PasswordChanged{}, "user.password_changed"},
		{PasswordResetRequested{}, "user.password_reset_requested"},
		{RefreshReuseDetected{}, "auth.refresh_reuse_detected"},
		{RoleCreated{}, "role.created"},
		{RoleDeleted{}, "role.deleted"},
		{RoleUpdated{}, "role.updated"},
		{SessionsRevoked{}, "auth.sessions_revoked"},
		{TokenRefreshed{}, "auth.token_refreshed"},
		{UserDeleted{}, "user.deleted"},
		{UserDisabled{}, "user.disabled"},
		{UserEmailVerified{}, "user.email_verified"},
		{UserEnabled{}, "user.enabled"},
		{UserLocked{}, "user.locked"},
		{UserLoggedIn{}, "user.logged_in"},
		{UserLoginFailed{}, "user.login_failed"},
		{UserRegistered{}, "user.registered"},
	}
	if len(events) != 34 {
		t.Fatalf("%d events", len(events))
	}
	for _, c := range events {
		if c.e.EventName() != c.name {
			t.Errorf("%T: %q, want %q", c.e, c.e.EventName(), c.name)
		}
	}
}

func TestSecretsAreRedacted(t *testing.T) {
	const secret = "s3cr3t-token"
	for _, e := range []interface {
		Event
		slog.LogValuer
	}{
		MemberInvited{OrganizationID: "o", Email: "a@example.com", InvitedBy: "u", InviteToken: secret},
		PasswordResetRequested{UserID: "u", Email: "a@example.com", ResetToken: secret},
		UserRegistered{UserID: "u", Email: "a@example.com", VerificationToken: secret},
	} {
		var buf bytes.Buffer
		slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "event", e)
		out := fmt.Sprintf("%v %+v %#v %s", e, e, e, buf.String())
		if strings.Contains(out, secret) || !strings.Contains(out, "a@example.com") || !strings.Contains(out, e.EventName()) {
			t.Errorf("%T leaks or loses fields: %s", e, out)
		}
	}
}
