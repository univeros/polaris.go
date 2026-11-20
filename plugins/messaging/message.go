package messaging

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/univeros/polaris-go/plugins/audit"
)

// The kinds of message, each served by the channels that support it.
const (
	KindEmail = "email"
	KindSMS   = "sms"
)

// Errors a send answers besides a store or template failure. Neither breaks the operation that
// asked for the message: core's ports log them and carry on.
var (
	// ErrRefused: the policy refused the send (the recipient's cap, or quiet mode).
	ErrRefused = errors.New("messaging: refused by the policy")
	// ErrUndelivered: no channel of the message's kind (nor the fallback) delivered it.
	ErrUndelivered = errors.New("messaging: no channel delivered the message")
	// ErrTemplateNotFound: no override nor bundled string has the template in the locale or the
	// default locale.
	ErrTemplateNotFound = errors.New("messaging: template not found")
)

// Message is what a channel sends: an email (Subject, Text, optional HTML) or an SMS (Text) to one
// recipient, with the template and variables it was rendered from, so the policy and the audit can
// name it without carrying its body. It holds data only, so a queue can serialize it (JSON).
type Message struct {
	Kind           string         `json:"kind"`
	To             string         `json:"to"`
	Template       string         `json:"template"` // "email.verify", "sms.otp"
	Text           string         `json:"text"`
	Subject        string         `json:"subject,omitempty"` // email only
	HTML           string         `json:"html,omitempty"`    // "" when the template has none
	Locale         string         `json:"locale,omitempty"`  // "" means the plugin's default
	Vars           map[string]any `json:"vars,omitempty"`
	OrganizationID string         `json:"organization_id,omitempty"` // whose template overrides apply
	// Essential messages (a verification, a reset, a code) are never dropped by quiet mode.
	Essential bool `json:"essential,omitempty"`
}

// Receipt is what a delivery answers: the channel that took the message, the provider's id when it
// gives one, when. A queued receipt is an Outbox's: a worker delivers the message later.
type Receipt struct {
	Channel    string
	ProviderID string
	SentAt     time.Time
	Queued     bool
}

// ChannelQueued is the channel name of a queued receipt.
const ChannelQueued = "queued"

// Queued is the receipt an Outbox answers when it took a message for later delivery.
func Queued(at time.Time) Receipt {
	return Receipt{Channel: ChannelQueued, SentAt: at, Queued: true}
}

// AuditSent is the event (and audit) name of a delivery.
const AuditSent = "messaging.sent"

// Sent is dispatched after every delivery and recorded by the audit plugin as messaging.sent: the
// channel, the template, the recipient hashed and the provider's id; never the body.
type Sent struct {
	Kind           string
	Template       string
	RecipientHash  string // hex SHA-256 of the lower-cased recipient
	Channel        string
	ProviderID     string // "" when the provider gave none
	OrganizationID string
	Fallback       bool // delivered to the alternative recipient
}

// EventName implements event.Event.
func (Sent) EventName() string { return AuditSent }

// AuditEvent implements audit.Auditable: a system event of the message's organization.
func (e Sent) AuditEvent(now time.Time) audit.Event {
	return audit.Event{Name: AuditSent, OccurredAt: now, ActorType: audit.ActorSystem, OrganizationID: e.OrganizationID,
		Data: map[string]any{
			"kind": e.Kind, "template": e.Template, "recipient_hash": e.RecipientHash, "channel": e.Channel,
			"provider_id": nullable(e.ProviderID), "fallback": e.Fallback,
		}}
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// hashRecipient is the recipient as the policy keys and the audit names it.
func hashRecipient(to string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(to)))
	return hex.EncodeToString(sum[:])
}
