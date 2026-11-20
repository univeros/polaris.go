package sso

import (
	"time"

	"github.com/univeros/polaris-go/plugins/audit"
)

// The sso.* event (and audit) names.
const (
	AuditProviderCreated   = "sso.provider_created"
	AuditProviderUpdated   = "sso.provider_updated"
	AuditProviderDeleted   = "sso.provider_deleted"
	AuditDomainAdded       = "sso.domain_added"
	AuditDomainVerified    = "sso.domain_verified"
	AuditDomainDeleted     = "sso.domain_deleted"
	AuditSignedIn          = "sso.signed_in"
	AuditAssertionRejected = "sso.assertion_rejected"
	AuditSLOCompleted      = "sso.slo_completed"
)

var auditNames = map[string]string{
	AuditProviderCreated:   "An SSO provider was added to an organization",
	AuditProviderUpdated:   "An SSO provider was changed",
	AuditProviderDeleted:   "An SSO provider was removed",
	AuditDomainAdded:       "A domain was added to an organization for SSO routing",
	AuditDomainVerified:    "A domain was verified",
	AuditDomainDeleted:     "A domain was removed",
	AuditSignedIn:          "A user signed in through an SSO provider",
	AuditAssertionRejected: "An SSO assertion or token was rejected (reason)",
	AuditSLOCompleted:      "A single logout completed",
}

// Event is what happened through SSO: a domain event the host may listen to, and the audit record
// the audit plugin keeps. A member's action on the organization's providers has the user as its
// actor (audit.ActorUser), an operator's audit.ActorAdmin or audit.ActorAPIKey, the engine's own
// (a rejection, an IdP's logout) audit.ActorSystem. A rejection's Data carries the reason.
type Event struct {
	Name           string
	ActorType      string
	ActorID        string
	SubjectID      string
	OrganizationID string
	Data           map[string]any
	IP             string
	UserAgent      string
}

// EventName implements event.Event.
func (e Event) EventName() string { return e.Name }

// AuditEvent implements audit.Auditable.
func (e Event) AuditEvent(now time.Time) audit.Event {
	return audit.Event{Name: e.Name, OccurredAt: now, ActorType: e.ActorType, ActorID: e.ActorID, SubjectID: e.SubjectID,
		OrganizationID: e.OrganizationID, IP: e.IP, UserAgent: e.UserAgent, Data: e.Data}
}
