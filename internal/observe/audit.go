// Package observe has the observability listeners of the core events (docs/auth/events.md): the
// audit trail written to auth_audit_log and the event counter. Subscribe them to the event.Bus
// next to notify.Listener. Both fail open: losing an audit row or a metric never breaks the
// operation that already happened.
package observe

import (
	"context"
	"log/slog"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
)

// AuditWriter appends audit rows; repository.AuditLog is the implementation.
type AuditWriter interface {
	Insert(ctx context.Context, entry model.AuditLogEntry) error
}

// dateAtom is PHP's DATE_ATOM.
const dateAtom = "2006-01-02T15:04:05-07:00"

// AuditLog returns the listener that persists every core event to the append-only audit log
// (upstream AuditLogListener). Each event maps to a whitelist: the actor, the organization, the
// client IP and user agent when the event carries them, and a small metadata blob of
// event-specific ids encoded byte for byte as PHP does. Secrets (verification, reset and invite
// tokens) are in no mapping, so a new event field cannot leak without a change here. Other events
// are ignored.
//
// A failed write is logged on logger (nil: slog.Default()) and swallowed: the domain write
// committed before the event fired. Alert on that log if audit delivery must be guaranteed.
// clk stamps created_at (nil: clock.System).
func AuditLog(w AuditWriter, clk clock.Clock, logger *slog.Logger) event.Listener {
	if clk == nil {
		clk = clock.System{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, e event.Event) {
		rec, ok := auditRecord(e)
		if !ok {
			return
		}
		rec.ID = repository.NewID()
		rec.Event = e.EventName()
		rec.CreatedAt = clk.Now()
		if err := w.Insert(ctx, rec); err != nil {
			logger.ErrorContext(ctx, "Audit log write failed for "+rec.Event, "event", rec.Event, "reason", err.Error())
		}
	}
}

// auditRecord maps a core event to its row (without id, name and time), as upstream's match arms.
func auditRecord(e event.Event) (model.AuditLogEntry, bool) {
	var (
		actor, org, ip, ua *string
		meta               []field
	)
	switch e := e.(type) {
	case event.UserRegistered:
		actor, meta = &e.UserID, []field{{"email", e.Email}}
	case event.UserEmailVerified:
		actor, meta = &e.UserID, []field{{"email", e.Email}}
	case event.UserLoggedIn:
		actor, ip, ua, meta = &e.UserID, e.IP, e.UserAgent, []field{{"session_id", e.SessionID}, {"amr", e.AMR}}
	case event.UserLoginFailed:
		actor, ip, ua, meta = &e.UserID, e.IP, e.UserAgent, []field{{"reason", e.Reason}}
	case event.UserLocked:
		var until *string
		if e.Until != nil {
			s := e.Until.Format(dateAtom)
			until = &s
		}
		actor, ip, meta = &e.UserID, e.IP, []field{{"until", until}}
	case event.PasswordChanged:
		actor, meta = &e.UserID, []field{{"method", e.Method}}
	case event.PasswordResetRequested:
		actor, meta = &e.UserID, []field{{"email", e.Email}}
	case event.UserDisabled:
		actor, meta = &e.ActorUserID, []field{{"user_id", e.UserID}}
	case event.UserEnabled:
		actor, meta = &e.ActorUserID, []field{{"user_id", e.UserID}}
	case event.UserDeleted:
		actor, meta = &e.ActorUserID, []field{{"user_id", e.UserID}}
	case event.TokenRefreshed:
		actor, meta = &e.UserID, []field{{"family_id", e.FamilyID}}
	case event.RefreshReuseDetected:
		actor, ip, ua, meta = &e.UserID, e.IP, e.UserAgent, []field{{"family_id", e.FamilyID}}
	case event.SessionsRevoked:
		actor, ip, meta = &e.UserID, e.IP, []field{{"count", e.Count}, {"reason", e.Reason}}
	case event.OrganizationSwitched:
		actor, org, meta = &e.UserID, &e.ToOrganizationID, []field{{"from_organization_id", e.FromOrganizationID}}
	case event.MFAEnrolled:
		actor, meta = &e.UserID, []field{{"factor_id", e.FactorID}, {"type", e.Type}}
	case event.MFAFactorRemoved:
		actor, meta = &e.UserID, []field{{"factor_id", e.FactorID}}
	case event.MFAVerified:
		actor, meta = &e.UserID, []field{{"factor_id", e.FactorID}}
	case event.MFAVerifyFailed:
		actor, meta = &e.UserID, []field{{"factor_id", e.FactorID}, {"type", e.Type}}
	case event.MFAStepUpCompleted:
		actor, meta = &e.UserID, []field{{"session_id", e.SessionID}}
	case event.MFARecoveryRegenerated:
		actor = &e.UserID
	case event.MFARecoveryUsed:
		actor, meta = &e.UserID, []field{{"remaining", e.Remaining}}
	case event.OTPChallengeSent:
		actor, meta = &e.UserID, []field{{"factor_id", e.FactorID}, {"channel", e.Channel}}
	case event.OTPVerifyFailed:
		actor, meta = &e.UserID, []field{{"factor_id", e.FactorID}, {"attempts_left", e.AttemptsLeft}}
	case event.OrganizationCreated:
		actor, org, meta = &e.OwnerUserID, &e.OrganizationID, []field{{"slug", e.Slug}}
	case event.OrganizationUpdated:
		actor, org = &e.ActorUserID, &e.OrganizationID
	case event.OrganizationDeleted:
		actor, org = &e.ActorUserID, &e.OrganizationID
	case event.RoleCreated:
		actor, org, meta = &e.ActorUserID, &e.OrganizationID, []field{{"role_id", e.RoleID}}
	case event.RoleUpdated:
		actor, org, meta = &e.ActorUserID, &e.OrganizationID, []field{{"role_id", e.RoleID}}
	case event.RoleDeleted:
		actor, org, meta = &e.ActorUserID, &e.OrganizationID, []field{{"role_id", e.RoleID}}
	case event.MemberInvited:
		actor, org, meta = &e.InvitedBy, &e.OrganizationID, []field{{"email", e.Email}}
	case event.MemberJoined:
		actor, org, meta = &e.UserID, &e.OrganizationID, []field{{"email", e.Email}}
	case event.MemberRolesChanged:
		actor, org, meta = &e.ActorUserID, &e.OrganizationID, []field{{"user_id", e.UserID}, {"role_slugs", e.RoleSlugs}}
	case event.MemberStatusChanged:
		actor, org, meta = &e.ActorUserID, &e.OrganizationID, []field{{"user_id", e.UserID}, {"status", e.Status}}
	case event.MemberRemoved:
		actor, org, meta = &e.ActorUserID, &e.OrganizationID, []field{{"user_id", e.UserID}}
	default:
		return model.AuditLogEntry{}, false
	}
	return model.AuditLogEntry{ActorUserID: actor, OrganizationID: org, IP: ip, UserAgent: ua, Metadata: phpJSON(meta)}, true
}
