package oauth

import (
	"context"
	"time"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/plugins/audit"
)

// The oauth.* event names (also the audit catalog entries).
const (
	EventClientCreated  = "oauth.client_created"
	EventClientUpdated  = "oauth.client_updated"
	EventClientDeleted  = "oauth.client_deleted"
	EventConsentGranted = "oauth.consent_granted"
	EventConsentDenied  = "oauth.consent_denied"
	EventConsentRevoked = "oauth.consent_revoked"
	EventTokenIssued    = "oauth.token_issued"
	EventTokenRefused   = "oauth.token_refused"
	EventTokenRevoked   = "oauth.token_revoked"
	EventRefreshReused  = "oauth.refresh_reused"
	EventDeviceDecided  = "oauth.device_decided"
	EventCIBARequested  = "oauth.ciba_requested"
	EventCIBADecided    = "oauth.ciba_decided"
)

// AuditCatalog describes each oauth.* event, for the audit plugin's catalog.
func AuditCatalog() map[string]string {
	return map[string]string{
		EventClientCreated:  "An OAuth client was registered (client id, name, organization, how)",
		EventClientUpdated:  "An OAuth client was changed (what)",
		EventClientDeleted:  "An OAuth client was deleted",
		EventConsentGranted: "A user granted a client scopes (client id, scopes)",
		EventConsentDenied:  "A user refused a client (client id)",
		EventConsentRevoked: "A user revoked a client's consent and its tokens (client id)",
		EventTokenIssued:    "Tokens were issued (client id, grant, scopes, DPoP-bound, actor)",
		EventTokenRefused:   "A token request was refused (client id, grant, error)",
		EventTokenRevoked:   "A token was revoked (client id, kind)",
		EventRefreshReused:  "A rotated refresh token was presented again: its family was revoked (client id)",
		EventDeviceDecided:  "A user approved or denied a device (client id, decision)",
		EventCIBARequested:  "A client asked a user to approve a sign-in (client id, binding message)",
		EventCIBADecided:    "A user approved or denied a backchannel request (client id, decision)",
	}
}

// Event is what happened at the provider: the name, the user who acted or was acted for ("" for
// none: the system), the client and the details. The host listens to oauth.ciba_requested to
// notify the user; the audit plugin records every one with Data plus client_id.
type Event struct {
	Name           string
	UserID         string
	ClientID       string
	OrganizationID string
	Data           map[string]any
	IP             string
	UserAgent      string
}

// EventName implements event.Event.
func (e Event) EventName() string { return e.Name }

// AuditEvent implements audit.Auditable: the user as actor and subject (the system without one),
// client_id with the details.
func (e Event) AuditEvent(now time.Time) audit.Event {
	data := map[string]any{"client_id": e.ClientID}
	for k, v := range e.Data {
		data[k] = v
	}
	actorType := audit.ActorUser
	if e.UserID == "" {
		actorType = audit.ActorSystem
	}
	return audit.Event{Name: e.Name, OccurredAt: now, ActorType: actorType, ActorID: e.UserID, SubjectID: e.UserID,
		OrganizationID: e.OrganizationID, IP: e.IP, UserAgent: e.UserAgent, Data: data}
}

// AuditNames adds the oauth.* names to the audit plugin's catalog (audit.NameProvider).
func (*Plugin) AuditNames() map[string]string { return AuditCatalog() }

// emit dispatches an event carrying the request's client context.
func (p *Plugin) emit(ctx context.Context, name, userID, clientID, organizationID string, data map[string]any) {
	c := endpoint.Client(ctx)
	if data == nil {
		data = map[string]any{}
	}
	p.graph.Events().Dispatch(ctx, Event{Name: name, UserID: userID, ClientID: clientID, OrganizationID: organizationID,
		Data: data, IP: c.IP, UserAgent: c.UserAgent})
}
