package agents

import (
	"time"

	"github.com/univeros/polaris.go/plugins/audit"
)

// The agent.* event (and audit) names.
const (
	EventRegistered      = "agent.registered"
	EventEnrolled        = "agent.enrolled"
	EventSuspended       = "agent.suspended"
	EventResumed         = "agent.resumed"
	EventRevoked         = "agent.revoked"
	EventGrantRequested  = "agent.grant.requested"
	EventGrantApproved   = "agent.grant.approved"
	EventGrantDenied     = "agent.grant.denied"
	EventGrantRevoked    = "agent.grant.revoked"
	EventGrantExhausted  = "agent.grant.exhausted"
	EventExecuted        = "agent.executed"
	EventExecutionDenied = "agent.execution_denied"
	EventReceiptSealed   = "agent.receipt.sealed"
	// A host the server does not know asked to register an agent, and a person denied it; approving is
	// EventEnrolled.
	EventRegistrationRequested = "agent.registration.requested"
	EventRegistrationDenied    = "agent.registration.denied"
)

var auditNames = map[string]string{
	EventRegistered:      "An agent was registered by its owner (name, mode, auth, organization)",
	EventEnrolled:        "A host enrolled an agent (host, name, mode, auth); the actor is the person who approved an unknown host's",
	EventSuspended:       "An agent was suspended",
	EventResumed:         "A suspended agent was resumed",
	EventRevoked:         "An agent was revoked: its tokens, grants and approvals ended, its receipt chain sealed",
	EventGrantRequested:  "An agent asked for capabilities (capabilities, approval method, user code, binding message)",
	EventGrantApproved:   "A capability grant was approved (capability, how, budget)",
	EventGrantDenied:     "A capability grant was denied (capability)",
	EventGrantRevoked:    "A capability grant was revoked (capability)",
	EventGrantExhausted:  "A capability grant spent its budget (capability)",
	EventExecuted:        "An agent executed a capability (capability, receipt, outcome)",
	EventExecutionDenied: "An agent was refused an execution (capability, error)",
	EventReceiptSealed:   "An agent's receipt chain was sealed with a final receipt (receipt, seq)",

	EventRegistrationRequested: "A host the server does not know asked to register an agent (host, name, capabilities)",
	EventRegistrationDenied:    "A person denied the registration of an agent of a host the server does not know (host, name)",
}

// Event is what happened to or through an agent: a domain event the host may listen to (a CIBA
// push on agent.grant.requested with method "ciba", say) and the audit record. Where the agent
// acts the actor is the agent (ActorType "agent") and the subject its owner; where a person acts,
// the actor and subject are that user; the policy and listeners act as "system".
type Event struct {
	Name           string // one of the Event* names
	AgentID        string
	ActorType      string // audit.ActorAgent, audit.ActorUser or audit.ActorSystem
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
	data := map[string]any{"agent_id": e.AgentID}
	for k, v := range e.Data {
		data[k] = v
	}
	return audit.Event{Name: e.Name, OccurredAt: now, ActorType: e.ActorType, ActorID: e.ActorID, SubjectID: e.SubjectID,
		OrganizationID: e.OrganizationID, IP: e.IP, UserAgent: e.UserAgent, Data: data}
}

// client is where a request came from, for the events.
type client struct{ ip, userAgent string }

func byAgent(name string, a Agent, data map[string]any, c client) Event {
	return Event{Name: name, AgentID: a.ID, ActorType: audit.ActorAgent, ActorID: a.ID, SubjectID: a.Subject(),
		OrganizationID: a.OrganizationID, Data: data, IP: c.ip, UserAgent: c.userAgent}
}

// decidedRegistration is the event of a person's decision on an unknown host's registration.
func decidedRegistration(r registration, a Agent, approved bool, userID string, c client) Event {
	data := map[string]any{"host_id": a.HostID, "host_key": r.HostThumbprint, "host_name": r.HostName, "name": r.Name, "mode": r.Mode, "auth": AuthPrivateKeyJWT}
	if approved {
		return byUser(EventEnrolled, a, userID, data, c)
	}
	return byUser(EventRegistrationDenied, a, userID, data, c)
}

func byUser(name string, a Agent, userID string, data map[string]any, c client) Event {
	return Event{Name: name, AgentID: a.ID, ActorType: audit.ActorUser, ActorID: userID, SubjectID: userID,
		OrganizationID: a.OrganizationID, Data: data, IP: c.ip, UserAgent: c.userAgent}
}

func bySystem(name string, a Agent, data map[string]any) Event {
	return Event{Name: name, AgentID: a.ID, ActorType: audit.ActorSystem, SubjectID: a.Subject(),
		OrganizationID: a.OrganizationID, Data: data}
}
