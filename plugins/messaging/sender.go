package messaging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/ratelimit"
)

// Channel delivers messages: an email transport, an SMS provider, a log, memory in tests. Send
// answers the provider's message id ("" when it gives none); an error makes the sender try the
// next channel of the kind, then the fallback.
type Channel interface {
	Name() string
	Supports(kind string) bool
	Send(ctx context.Context, m Message) (providerID string, err error)
}

// Outbox is where a send goes once the policy allowed it. nil (the default) delivers on the
// request. A queue implementation stores the message and its alternatives (both plain data),
// answers Queued(now), and its worker calls Sender.Dispatch with them, which asks no policy and
// never comes back to the outbox.
type Outbox interface {
	Push(ctx context.Context, m Message, alternatives map[string]string) (Receipt, error)
}

// Suppressor is quiet mode: it says whether a non-essential message should be dropped (the
// sentinel plugin's: a recipient challenged or blocked in the last hour). Essential messages
// always go.
type Suppressor interface {
	Suppresses(ctx context.Context, m Message) bool
}

// Cap is a send budget per recipient: Limit messages in Window.
type Cap struct {
	Limit  int
	Window time.Duration
}

// DefaultCap applies when Config.Caps names neither the template, nor its kind, nor "*".
var DefaultCap = Cap{Limit: 5, Window: 10 * time.Minute}

// Sender is the one way out: render, ask the policy, hand to the outbox, deliver through the first
// channel of the message's kind (falling back to an alternative recipient when the policy has a
// fallback kind), dispatch messaging.sent. Safe for concurrent use.
type Sender struct {
	channels      []Channel
	render        *renderer
	rates         ratelimit.Store
	caps          map[string]Cap
	fallback      map[string]string
	suppressor    func() Suppressor
	outbox        Outbox
	events        event.Dispatcher
	logger        *slog.Logger
	clock         clock.Clock
	defaultLocale string
}

// Send renders m.Template for m.To in m.Locale (default: the plugin's) with m.Vars and the
// overrides of m.OrganizationID, filling Text, Subject and HTML, then Delivers it. alternatives
// (kind => recipient, e.g. {"email": user.Email}) serve the policy's fallback.
func (s *Sender) Send(ctx context.Context, m Message, alternatives map[string]string) (Receipt, error) {
	if m.Locale == "" {
		m.Locale = s.defaultLocale
	}
	tpl, err := s.render.render(ctx, m.Template, m.Locale, m.Vars, m.OrganizationID)
	if err != nil {
		return Receipt{}, err
	}
	m.Subject, m.Text, m.HTML = tpl.Subject, tpl.Text, tpl.HTML
	return s.Deliver(ctx, m, alternatives)
}

// Deliver sends an already rendered message: the policy first (ErrRefused), then the outbox (a
// queued receipt) or the channels (ErrUndelivered when none delivered).
func (s *Sender) Deliver(ctx context.Context, m Message, alternatives map[string]string) (Receipt, error) {
	if m.Locale == "" {
		m.Locale = s.defaultLocale
	}
	allowed, err := s.allows(ctx, m)
	if err != nil {
		return Receipt{}, err
	}
	if !allowed {
		s.logger.InfoContext(ctx, "messaging: not sent, the policy refused it", "template", m.Template, "recipient", hashRecipient(m.To))
		return Receipt{}, ErrRefused
	}
	if s.outbox != nil {
		return s.outbox.Push(ctx, m, alternatives)
	}
	return s.Dispatch(ctx, m, alternatives)
}

// Dispatch delivers a message the policy already allowed: the channels of its kind, then the
// fallback. It asks no policy and uses no outbox: a queue's worker calls it with what it received.
func (s *Sender) Dispatch(ctx context.Context, m Message, alternatives map[string]string) (Receipt, error) {
	if r, ok := s.attempt(ctx, m, false); ok {
		return r, nil
	}
	kind := s.fallback[m.Kind]
	to := alternatives[kind]
	if kind == "" || to == "" {
		return Receipt{}, ErrUndelivered
	}
	alt := m
	alt.Kind, alt.To, alt.Template = kind, to, sibling(m.Template, kind)
	tpl, err := s.render.render(ctx, alt.Template, alt.Locale, alt.Vars, alt.OrganizationID)
	if err != nil {
		return Receipt{}, err
	}
	alt.Subject, alt.Text, alt.HTML = tpl.Subject, tpl.Text, tpl.HTML
	if r, ok := s.attempt(ctx, alt, true); ok {
		return r, nil
	}
	return Receipt{}, ErrUndelivered
}

func (s *Sender) attempt(ctx context.Context, m Message, fallback bool) (Receipt, bool) {
	for _, ch := range s.channels {
		if !ch.Supports(m.Kind) {
			continue
		}
		id, err := ch.Send(ctx, m)
		if err != nil {
			s.logger.WarnContext(ctx, "messaging: channel failed", "channel", ch.Name(), "template", m.Template, "reason", err.Error())
			continue
		}
		r := Receipt{Channel: ch.Name(), ProviderID: id, SentAt: s.clock.Now()}
		s.events.Dispatch(ctx, Sent{Kind: m.Kind, Template: m.Template, RecipientHash: hashRecipient(m.To),
			Channel: r.Channel, ProviderID: id, OrganizationID: m.OrganizationID, Fallback: fallback})
		return r, true
	}
	s.logger.ErrorContext(ctx, "messaging: no channel delivered the message", "template", m.Template, "kind", m.Kind)
	return Receipt{}, false
}

// allows counts the send against the recipient's cap (template, else kind, else "*").
func (s *Sender) allows(ctx context.Context, m Message) (bool, error) {
	if !m.Essential {
		if q := s.suppressor(); q != nil && q.Suppresses(ctx, m) {
			return false, nil
		}
	}
	c, ok := s.caps[m.Template]
	if !ok {
		if c, ok = s.caps[m.Kind]; !ok {
			if c, ok = s.caps["*"]; !ok {
				c = DefaultCap
			}
		}
	}
	res, err := s.rates.Hit(ctx, "polaris:messaging:"+m.Template+":"+hashRecipient(m.To), c.Limit, c.Window)
	if err != nil {
		return false, fmt.Errorf("messaging: policy: %w", err)
	}
	return res.Allowed, nil
}

// sibling is the same purpose on another kind: sms.otp => email.otp.
func sibling(template, kind string) string {
	if _, rest, ok := strings.Cut(template, "."); ok {
		return kind + "." + rest
	}
	return kind + "." + template
}

// swallowed reports whether err is nil or an outcome a core port logs and ignores.
func swallowed(err error) bool {
	return err == nil || errors.Is(err, ErrRefused) || errors.Is(err, ErrUndelivered)
}
