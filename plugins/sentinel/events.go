package sentinel

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/univeros/polaris.go/plugins/audit"
)

// The sentinel.* event (and audit) names.
const (
	AuditEvaluated     = "sentinel.evaluated"
	AuditIPRuleCreated = "sentinel.ip_rule_created"
	AuditIPRuleDeleted = "sentinel.ip_rule_deleted"
	AuditUnblocked     = "sentinel.unblocked"
)

var auditNames = map[string]string{
	AuditEvaluated:     "The sentinel judged an attempt (score, signals, action)",
	AuditIPRuleCreated: "An operator added an IP rule",
	AuditIPRuleDeleted: "An operator removed an IP rule",
	AuditUnblocked:     "An operator cleared the counters of an email or an address",
}

// Evaluated is dispatched whenever a signal spoke, and recorded as sentinel.evaluated: the kind,
// the score, the action (and whether it was enforced), the signals and their reasons, the email
// hashed, the IP and user agent; never the password nor the captcha token.
type Evaluated struct {
	Attempt  Attempt
	Decision Decision
}

// EventName implements event.Event.
func (Evaluated) EventName() string { return AuditEvaluated }

// AuditEvent implements audit.Auditable.
func (e Evaluated) AuditEvent(now time.Time) audit.Event {
	var emailHash any
	if e.Attempt.Email != "" {
		emailHash = sha256Hex(e.Attempt.Email)
	}
	return audit.Event{Name: AuditEvaluated, OccurredAt: now, ActorType: audit.ActorSystem, IP: e.Attempt.IP, UserAgent: e.Attempt.UserAgent,
		Data: map[string]any{
			"kind": e.Attempt.Kind, "email_hash": emailHash, "score": e.Decision.Score, "action": e.Decision.Action,
			"enforced": e.Decision.Enforced, "signals": e.Decision.Signals(), "reasons": e.Decision.Reasons(),
		}}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
