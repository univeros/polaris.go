package audit

import (
	"context"
	"log/slog"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
)

// Recorder turns domain events into audit events: every core event maps to a catalogued,
// redacted event; an Auditable event of another package is written as it describes itself;
// anything else is ignored. Record is the programmatic way to emit one.
type Recorder struct {
	catalog *Catalog
	sink    Sink
	clock   clock.Clock
	logger  *slog.Logger
}

// NewRecorder returns a recorder writing to sink.
func NewRecorder(catalog *Catalog, sink Sink, clk clock.Clock, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{catalog: catalog, sink: sink, clock: clk, logger: logger}
}

// Record checks e's name against the catalog (an unknown name wraps ErrUnknownName and no sink
// sees it), redacts its data and writes it to every sink. OccurredAt defaults to now.
func (r *Recorder) Record(ctx context.Context, e Event) error {
	if err := r.catalog.Check(e.Name); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = r.clock.Now()
	}
	e.Data = Redact(e.Data)
	return r.sink.Write(ctx, e.normalized())
}

// Listen is the event listener. A refused event is logged: the operation it observes already
// happened.
func (r *Recorder) Listen(ctx context.Context, ev event.Event) {
	var e Event
	if a, ok := ev.(Auditable); ok {
		e = a.AuditEvent(r.clock.Now())
	} else if e, ok = mapCore(ev); !ok {
		return
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = r.clock.Now()
	}
	if err := r.Record(ctx, e); err != nil {
		r.logger.ErrorContext(ctx, "Audit event not recorded", "event", ev.EventName(), "reason", err.Error())
	}
}

// userEvent is an event a user did to themselves.
func userEvent(name, userID string, data map[string]any) Event {
	return Event{Name: name, ActorType: ActorUser, ActorID: userID, SubjectID: userID, Data: data}
}

// orgEvent is an event in an organization; the subject defaults to the actor.
func orgEvent(name, actorID, organizationID, subjectID string, data map[string]any) Event {
	if subjectID == "" {
		subjectID = actorID
	}
	return Event{Name: name, ActorType: ActorUser, ActorID: actorID, SubjectID: subjectID, OrganizationID: organizationID, Data: data}
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func ptr[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}

func list(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// mapCore maps a core event as upstream's Recorder does.
func mapCore(ev event.Event) (Event, bool) {
	var e Event
	switch v := ev.(type) {
	case event.UserRegistered:
		e = userEvent(UserSignedUp, v.UserID, map[string]any{"email": v.Email})
	case event.UserEmailVerified:
		e = userEvent(UserEmailVerified, v.UserID, map[string]any{"email": v.Email})
	case event.UserLoggedIn:
		e = userEvent(SessionSignedIn, v.UserID, map[string]any{"amr": list(v.AMR)})
		e.IP, e.UserAgent, e.SessionID = str(v.IP), str(v.UserAgent), v.SessionID
	case event.UserLoginFailed:
		e = userEvent(SessionSignInFailed, v.UserID, map[string]any{"reason": v.Reason})
		e.IP, e.UserAgent = str(v.IP), str(v.UserAgent)
	case event.UserLocked:
		var until any
		if v.Until != nil {
			until = v.Until.UTC().Format(dateAtom)
		}
		e = userEvent(UserLocked, v.UserID, map[string]any{"until": until})
		e.IP = str(v.IP)
	case event.PasswordChanged:
		e = userEvent(PasswordChanged, v.UserID, map[string]any{"method": v.Method})
	case event.PasswordResetRequested:
		e = userEvent(PasswordResetRequested, v.UserID, map[string]any{"email": v.Email})
	case event.UserDisabled:
		e = Event{Name: UserDisabled, ActorType: ActorUser, ActorID: v.ActorUserID, SubjectID: v.UserID}
	case event.UserEnabled:
		e = Event{Name: UserEnabled, ActorType: ActorUser, ActorID: v.ActorUserID, SubjectID: v.UserID}
	case event.UserDeleted:
		e = Event{Name: UserDeleted, ActorType: ActorUser, ActorID: v.ActorUserID, SubjectID: v.UserID}
	case event.TokenRefreshed:
		e = userEvent(SessionRotated, v.UserID, map[string]any{"family_id": v.FamilyID})
	case event.RefreshReuseDetected:
		e = userEvent(SessionReuseDetected, v.UserID, map[string]any{"family_id": v.FamilyID})
		e.IP, e.UserAgent = str(v.IP), str(v.UserAgent)
	case event.SessionsRevoked:
		e = userEvent(SessionRevokedAll, v.UserID, map[string]any{"count": v.Count, "reason": v.Reason})
		e.IP = str(v.IP)
	case event.OrganizationSwitched:
		e = orgEvent(SessionOrganizationSwitched, v.UserID, v.ToOrganizationID, v.UserID, map[string]any{"from_organization_id": ptr(v.FromOrganizationID)})
	case event.MFAEnrolled:
		e = userEvent(MFAEnabled, v.UserID, map[string]any{"factor_id": v.FactorID, "type": ptr(v.Type)})
	case event.MFAFactorRemoved:
		e = userEvent(MFADisabled, v.UserID, map[string]any{"factor_id": v.FactorID})
	case event.MFAVerified:
		e = userEvent(MFAChallengePassed, v.UserID, map[string]any{"factor_id": ptr(v.FactorID)})
	case event.MFAVerifyFailed:
		e = userEvent(MFAChallengeFailed, v.UserID, map[string]any{"factor_id": ptr(v.FactorID), "type": ptr(v.Type)})
	case event.OTPVerifyFailed:
		e = userEvent(MFAChallengeFailed, v.UserID, map[string]any{"factor_id": v.FactorID, "attempts_left": ptr(v.AttemptsLeft)})
	case event.MFAStepUpCompleted:
		e = userEvent(MFAStepUpCompleted, v.UserID, nil)
		e.SessionID = v.SessionID
	case event.OTPChallengeSent:
		e = userEvent(MFACodeSent, v.UserID, map[string]any{"factor_id": v.FactorID, "channel": v.Channel})
	case event.MFARecoveryRegenerated:
		e = userEvent(MFABackupCodesRegenerated, v.UserID, nil)
	case event.MFARecoveryUsed:
		e = userEvent(MFABackupCodeUsed, v.UserID, map[string]any{"remaining": v.Remaining})
	default:
		return mapOrg(ev)
	}
	return e, true
}

func mapOrg(ev event.Event) (Event, bool) {
	var e Event
	switch v := ev.(type) {
	case event.OrganizationCreated:
		e = orgEvent(OrgCreated, v.OwnerUserID, v.OrganizationID, "", map[string]any{"slug": v.Slug})
	case event.OrganizationUpdated:
		e = orgEvent(OrgUpdated, v.ActorUserID, v.OrganizationID, "", nil)
	case event.OrganizationDeleted:
		e = orgEvent(OrgDeleted, v.ActorUserID, v.OrganizationID, "", nil)
	case event.RoleCreated:
		e = orgEvent(OrgRoleCreated, v.ActorUserID, v.OrganizationID, "", map[string]any{"role_id": v.RoleID})
	case event.RoleUpdated:
		e = orgEvent(OrgRoleUpdated, v.ActorUserID, v.OrganizationID, "", map[string]any{"role_id": v.RoleID})
	case event.RoleDeleted:
		e = orgEvent(OrgRoleDeleted, v.ActorUserID, v.OrganizationID, "", map[string]any{"role_id": v.RoleID})
	case event.MemberInvited:
		e = orgEvent(OrgMemberInvited, v.InvitedBy, v.OrganizationID, "", map[string]any{"email": v.Email})
	case event.MemberJoined:
		e = orgEvent(OrgMemberJoined, v.UserID, v.OrganizationID, v.UserID, map[string]any{"email": v.Email})
	case event.MemberRolesChanged:
		e = orgEvent(OrgMemberRolesChanged, v.ActorUserID, v.OrganizationID, v.UserID, map[string]any{"role_slugs": list(v.RoleSlugs)})
	case event.MemberStatusChanged:
		e = orgEvent(OrgMemberStatusChanged, v.ActorUserID, v.OrganizationID, v.UserID, map[string]any{"status": v.Status})
	case event.MemberRemoved:
		e = orgEvent(OrgMemberRemoved, v.ActorUserID, v.OrganizationID, v.UserID, nil)
	default:
		return Event{}, false
	}
	return e, true
}
