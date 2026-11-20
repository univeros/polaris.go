package apikeys

import (
	"time"

	"github.com/univeros/polaris-go/plugins/audit"
)

// The api_keys.* event (and audit) names.
const (
	AuditCreated = "api_keys.created"
	AuditUpdated = "api_keys.updated"
	AuditRotated = "api_keys.rotated"
	AuditRevoked = "api_keys.revoked"
)

// Event is what happened to a key: a domain event the host may listen to, and the audit record
// the audit plugin keeps (actor the acting user, subject the key).
type Event struct {
	Name           string // AuditCreated, AuditUpdated, AuditRotated or AuditRevoked
	ActorID        string
	KeyID          string
	OwnerType      string
	OwnerID        string
	OrganizationID string
	Data           map[string]any
	IP             string
	UserAgent      string
}

// EventName implements event.Event.
func (e Event) EventName() string { return e.Name }

// AuditEvent implements audit.Auditable.
func (e Event) AuditEvent(now time.Time) audit.Event {
	data := map[string]any{"owner_type": e.OwnerType, "owner_id": e.OwnerID}
	for k, v := range e.Data {
		data[k] = v
	}
	return audit.Event{Name: e.Name, OccurredAt: now, ActorType: audit.ActorUser, ActorID: e.ActorID, SubjectID: e.KeyID,
		OrganizationID: e.OrganizationID, IP: e.IP, UserAgent: e.UserAgent, Data: data}
}
