package scim

import (
	"time"

	"github.com/univeros/polaris-go/plugins/audit"
)

// The scim.* event (and audit) names.
const (
	AuditConnectionCreated        = "scim.connection_created"
	AuditConnectionRotated        = "scim.connection_rotated"
	AuditConnectionDecommissioned = "scim.connection_decommissioned"
	AuditUserCreated              = "scim.user_created"
	AuditUserUpdated              = "scim.user_updated"
	AuditUserDeactivated          = "scim.user_deactivated"
	AuditUserReactivated          = "scim.user_reactivated"
	AuditUserDeleted              = "scim.user_deleted"
	AuditGroupCreated             = "scim.group_created"
	AuditGroupUpdated             = "scim.group_updated"
	AuditGroupDeleted             = "scim.group_deleted"
	AuditRequestRejected          = "scim.request_rejected"
)

var auditNames = map[string]string{
	AuditConnectionCreated:        "A SCIM connection was created for an organization",
	AuditConnectionRotated:        "A SCIM connection token was rotated",
	AuditConnectionDecommissioned: "A SCIM connection was decommissioned",
	AuditUserCreated:              "A directory provisioned a user",
	AuditUserUpdated:              "A directory updated a user",
	AuditUserDeactivated:          "A directory deactivated a user",
	AuditUserReactivated:          "A directory reactivated a user",
	AuditUserDeleted:              "A directory deleted (anonymised) a user",
	AuditGroupCreated:             "A directory created a group (a role)",
	AuditGroupUpdated:             "A directory changed a group or its members",
	AuditGroupDeleted:             "A directory deleted a group",
	AuditRequestRejected:          "A SCIM request was refused (reason)",
}

// Event is what happened through SCIM: a domain event the host may listen to, and the audit
// record the audit plugin keeps. A directory's request has the connection as its actor
// (audit.ActorAPIKey); an organization member's action on a connection the user
// (audit.ActorUser), with the connection as the subject; an operator's audit.ActorAdmin or
// audit.ActorAPIKey.
type Event struct {
	Name           string
	ActorType      string
	ActorID        string
	SubjectID      string
	OrganizationID string
	Data           map[string]any // always carries connection_name
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
