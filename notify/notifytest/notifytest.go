// Package notifytest has recording notify drivers for tests: they keep what they were asked to
// send so a test can assert the recipient and read the one-time code.
package notifytest

import (
	"context"
	"maps"
	"slices"
	"sync"
)

// Mail is one email a Mailer was asked to send.
type Mail struct {
	To       string
	Template string
	Data     map[string]any
}

// Mailer is a notify.Mailer that records every email. The zero value is ready to use.
type Mailer struct {
	mu   sync.Mutex
	sent []Mail
}

// Send records the email.
func (m *Mailer) Send(_ context.Context, to, template string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, Mail{To: to, Template: template, Data: maps.Clone(data)})
	return nil
}

// Sent returns a copy of the emails recorded so far, oldest first.
func (m *Mailer) Sent() []Mail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.sent)
}

// SMS is one message an SMSSender was asked to send.
type SMS struct {
	To      string
	Message string
}

// SMSSender is a notify.SMSSender that records every message. The zero value is ready to use.
type SMSSender struct {
	mu   sync.Mutex
	sent []SMS
}

// Send records the message.
func (s *SMSSender) Send(_ context.Context, to, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, SMS{To: to, Message: message})
	return nil
}

// Sent returns a copy of the messages recorded so far, oldest first.
func (s *SMSSender) Sent() []SMS {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.sent)
}
