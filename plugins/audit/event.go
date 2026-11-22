package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// Actor types.
const (
	ActorUser   = "user"
	ActorAdmin  = "admin"
	ActorAPIKey = "api_key"
	ActorAgent  = "agent"
	ActorSystem = "system"
)

// hashedTimeLayout is how occurred_at enters the hash: RFC 3339 to the second with UTC written
// "+00:00". Chains hashed by earlier releases keep verifying only while it stays the same; the
// wire form is timestamp's.
const hashedTimeLayout = "2006-01-02T15:04:05-07:00"

// timestamp is the wire form of a time: RFC 3339 in UTC, to the second ("2026-09-11T10:00:00Z").
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// Redacted replaces what Redact strips.
const Redacted = "[redacted]"

var secretKey = regexp.MustCompile(`(?i)password|secret|token|code|otp|private_key|credential`)

// Event is one row of polaris_audit_event: what happened, to whom, by whom, where from, and the
// event's own (redacted) data. Empty strings are NULL on the wire and in the table. With the hash
// chain on, PrevHash and Hash link it to the previous row.
type Event struct {
	ID             string
	Name           string
	OccurredAt     time.Time
	ActorType      string // ActorSystem when ActorID is ""
	ActorID        string
	SubjectID      string
	OrganizationID string
	SessionID      string
	IP             string
	UserAgent      string
	Data           map[string]any
	RequestID      string
	PrevHash       string
	Hash           string

	stored string // the data column as read, for the hash verification
}

// Auditable is a domain event of another package that describes its own audit record (api-keys'
// events); the recorder writes it after checking its name and redacting its data.
type Auditable interface {
	AuditEvent(now time.Time) Event
}

// Sensitive marks a value Redact always strips, whatever its key.
type Sensitive struct{ Value any }

// String keeps the value out of fmt output.
func (Sensitive) String() string { return Redacted }

// GoString keeps the value out of %#v output.
func (Sensitive) GoString() string { return Redacted }

// Redact returns a copy of data without what must never be persisted: any key matching
// password|secret|token|code|otp|private_key|credential (any case, any depth) and any Sensitive
// value, each replaced by Redacted.
func Redact(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for k, v := range data {
		if _, ok := v.(Sensitive); ok || secretKey.MatchString(k) {
			out[k] = Redacted
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		return Redact(v)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			if _, ok := item.(Sensitive); ok {
				out[i] = Redacted
				continue
			}
			out[i] = redactValue(item)
		}
		return out
	}
	return v
}

// Map is the event's wire shape, as the query routes answer it.
func (e Event) Map() map[string]any {
	data := e.Data
	if data == nil {
		data = map[string]any{}
	}
	return map[string]any{
		"id":              e.ID,
		"name":            e.Name,
		"occurred_at":     timestamp(e.OccurredAt),
		"actor_type":      e.ActorType,
		"actor_id":        null(e.ActorID),
		"subject_id":      null(e.SubjectID),
		"organization_id": null(e.OrganizationID),
		"session_id":      null(e.SessionID),
		"ip":              null(e.IP),
		"user_agent":      null(e.UserAgent),
		"data":            data,
		"request_id":      null(e.RequestID),
	}
}

// MarshalJSON encodes the wire shape.
func (e Event) MarshalJSON() ([]byte, error) { return json.Marshal(e.Map()) }

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// normalized fills the defaults Record applies: the actor type, UTC time to the second.
func (e Event) normalized() Event {
	if e.ActorID == "" || e.ActorType == "" {
		e.ActorType = ActorSystem
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Second)
	return e
}

// canonicalJSON encodes v in the form the audit trail stores and hashes: slashes unescaped, HTML
// characters unescaped, every non-ASCII character as a \uXXXX escape (surrogate pairs above the
// BMP), an empty object as []. Chains hashed by earlier releases keep verifying only while these
// bytes stay the same.
func canonicalJSON(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(emptyAsList(v)); err != nil {
		return "", fmt.Errorf("audit: encode: %w", err)
	}
	raw := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); {
		r, size := utf8.DecodeRune(raw[i:])
		i += size
		switch {
		case r < utf8.RuneSelf:
			out = append(out, byte(r)) //nolint:gosec // G115: r < utf8.RuneSelf, so it fits a byte
		case r < 0x10000:
			out = fmt.Appendf(out, `\u%04x`, r)
		default:
			r -= 0x10000
			out = fmt.Appendf(out, `\u%04x\u%04x`, 0xd800+(r>>10), 0xdc00+(r&0x3ff))
		}
	}
	return string(out), nil
}

// emptyAsList maps empty objects to empty lists at any depth: the stored and hashed form writes
// both as [].
func emptyAsList(v any) any {
	switch v := v.(type) {
	case map[string]any:
		if len(v) == 0 {
			return []any{}
		}
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = emptyAsList(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = emptyAsList(item)
		}
		return out
	}
	return v
}
