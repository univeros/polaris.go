// Package messaging is the messaging plugin (port of polaris/messaging): core's verification,
// reset, invitation, one-time-code and security messages rendered from templates you can override
// per instance and per organization, translated (en, es, de, fr, pt bundled), capped per recipient,
// and sent through the channels you choose (SMTP, Twilio, Vonage, any HTTP SMS API, a log, memory
// in tests). Registered with Config.Mailer and Config.SMS left nil, it becomes core's mailer and
// SMS sender:
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db, // Mailer and SMS nil: the plugin provides them
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), messaging.New(messaging.Config{
//			Email: &messaging.SMTP{Addr: "smtp.example.com:587", From: "noreply@example.com",
//				Auth: smtp.PlainAuth("", user, pass, "smtp.example.com")},
//			SMS: &messaging.Twilio{AccountSID: sid, AuthToken: token, From: "+15550000000"},
//		})},
//	})
//
// With the audit plugin registered every delivery is a messaging.sent audit record (channel,
// template, recipient hash, provider id; never the body). The plugin's Sender serves the
// application's own messages too:
//
//	msg.Sender().Send(ctx, messaging.Message{Kind: messaging.KindEmail, To: u.Email,
//		Template: "email.new_device", Vars: map[string]any{"ip": ip, "user_agent": ua}}, nil)
package messaging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/wiring"
)

// ID is the plugin id.
const ID = "messaging"

// Config configures the plugin; the zero value logs every message (the development default) under
// upstream's policy.
type Config struct {
	// Email and SMS are the main channels of each kind; Channels are more, tried after them in
	// order (any kind). With none at all every message goes to the log.
	Email    Channel
	SMS      Channel
	Channels []Channel

	// Locale is the default locale; "" means "en".
	Locale string
	// Templates are the instance's overrides, locale => key => template.
	Templates map[string]map[string]Template
	// Strings add to (or replace) the bundled strings, locale => id ("email.otp.text") => string.
	Strings map[string]map[string]string
	// Translator replaces the bundled strings (Strings is then ignored).
	Translator Translator

	// Caps bound the sends per recipient, by template ("sms.otp"), kind ("sms") or "*"; nil means
	// {"*": DefaultCap}.
	Caps map[string]Cap
	// Fallback maps a kind to the kind tried when no channel of the first delivered and the send
	// named an alternative recipient; nil means sms => email, an empty map disables it.
	Fallback map[string]string
	// Suppressor is quiet mode; nil takes the sentinel plugin's when it is registered.
	Suppressor Suppressor
	// Outbox defers delivery (a queue); nil delivers on the request.
	Outbox Outbox
}

// Plugin is the messaging plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg       Config
	sender    *Sender
	templates *Templates
}

// New returns the plugin.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_messaging_template.
func (*Plugin) Schema() []schema.Model { return Models() }

// AuditNames adds messaging.sent to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string {
	return map[string]string{AuditSent: "A message was sent (channel, template, recipient hash, provider id)"}
}

// Ports serves core's Mailer and SMS ports (used when Config.Mailer / Config.SMS are nil).
func (p *Plugin) Ports() wiring.Ports {
	return wiring.Ports{Mailer: mailer{p}, SMS: smsSender{p}}
}

// Init builds the sender.
func (p *Plugin) Init(g *wiring.Graph) error {
	c := p.cfg
	if c.Locale == "" {
		c.Locale = "en"
	}
	var channels []Channel
	for _, ch := range append([]Channel{c.Email, c.SMS}, c.Channels...) {
		if ch != nil {
			channels = append(channels, ch)
		}
	}
	if len(channels) == 0 {
		channels = []Channel{&Log{Logger: g.Logger()}}
	}
	if c.Caps == nil {
		c.Caps = map[string]Cap{"*": DefaultCap}
	}
	for name, cp := range c.Caps {
		if cp.Limit < 1 || cp.Window < time.Second {
			return fmt.Errorf("messaging: Config.Caps[%q] is %+v: want a Limit ≥ 1 and a Window ≥ 1s", name, cp)
		}
	}
	if c.Fallback == nil {
		c.Fallback = map[string]string{KindSMS: KindEmail}
	}
	translator := c.Translator
	if translator == nil {
		translator = Strings(c.Strings)
	}
	p.templates = &Templates{db: g.DB(), clock: g.Clock(), instance: c.Templates}
	p.sender = &Sender{
		channels: channels, rates: g.RateStore(), caps: c.Caps, fallback: c.Fallback, outbox: c.Outbox,
		render: &renderer{templates: p.templates, translator: translator, defaultLocale: c.Locale},
		events: g.Events(), logger: g.Logger(), clock: g.Clock(), defaultLocale: c.Locale,
		suppressor: func() Suppressor { return c.Suppressor },
	}
	if c.Suppressor == nil {
		// Resolved at send time: the sentinel's services exist once every Init has run.
		if q, ok := g.Plugin("sentinel").(quietMode); ok {
			p.sender.suppressor = func() Suppressor { return sentinelQuiet{q} }
		}
	}
	return nil
}

// quietMode is what the sentinel plugin offers (no import: either plugin works alone).
type quietMode interface {
	QuietFor(ctx context.Context, kind, recipient string) bool
}

type sentinelQuiet struct{ q quietMode }

func (s sentinelQuiet) Suppresses(ctx context.Context, m Message) bool {
	return s.q.QuietFor(ctx, m.Kind, m.To)
}

// Sender is the plugin's sender, for the application's own messages and a queue's worker.
func (p *Plugin) Sender() *Sender { return p.sender }

// Templates stores organizations' template overrides.
func (p *Plugin) Templates() *Templates { return p.templates }

// Of returns the messaging plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// SendTemplate sends one template to a recipient, essential (no quiet mode), to check a channel
// and a template: upstream's "polaris messaging:send <to> <template> --vars=… --locale=…" until
// cmd/polaris exists. The kind is the template's prefix (sms.* is an SMS, anything else an email);
// varsJSON is a JSON object ("" for none); locale "" means the default.
func (p *Plugin) SendTemplate(ctx context.Context, to, template, varsJSON, locale string) (Receipt, error) {
	var vars map[string]any
	if strings.TrimSpace(varsJSON) != "" {
		dec := json.NewDecoder(strings.NewReader(varsJSON))
		dec.UseNumber()
		if err := dec.Decode(&vars); err != nil || vars == nil {
			return Receipt{}, errors.New("messaging: --vars must be a JSON object")
		}
	}
	kind := KindEmail
	if strings.HasPrefix(template, KindSMS+".") {
		kind = KindSMS
	}
	return p.sender.Send(ctx, Message{Kind: kind, To: to, Template: template, Vars: vars, Locale: locale, Essential: true}, nil)
}
