package social

import (
	"time"

	"github.com/univeros/polaris.go/plugins/audit"
)

// The social.* event (and audit) names.
const (
	EventSignedIn       = "social.signed_in"
	EventSignedUp       = "social.signed_up"
	EventLinked         = "social.linked"
	EventUnlinked       = "social.unlinked"
	EventTokenRefreshed = "social.token_refreshed"
	EventRejected       = "social.rejected"
)

// Event is what happened to a provider account: a domain event the host may listen to and the
// audit record the audit plugin keeps. UserID is "" for a refused sign-in nobody is known for.
type Event struct {
	Name      string
	UserID    string
	Provider  string
	Data      map[string]any
	IP        string
	UserAgent string
}

// EventName implements event.Event.
func (e Event) EventName() string { return e.Name }

// AuditEvent implements audit.Auditable: the user is actor and subject, the system when none.
func (e Event) AuditEvent(now time.Time) audit.Event {
	data := map[string]any{"provider": e.Provider}
	for k, v := range e.Data {
		data[k] = v
	}
	actor := audit.ActorUser
	if e.UserID == "" {
		actor = audit.ActorSystem
	}
	return audit.Event{Name: e.Name, OccurredAt: now, ActorType: actor, ActorID: e.UserID, SubjectID: e.UserID, IP: e.IP, UserAgent: e.UserAgent, Data: data}
}
