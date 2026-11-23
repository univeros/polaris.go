# plugins/messaging

Core's verification, reset, invitation, one-time-code and security messages, rendered from templates
you can override per instance and per organization, translated (`en`, `es`, `de`, `fr`, `pt`
bundled), capped per recipient and sent through the channels you choose: SMTP, Twilio, Vonage, any
HTTP SMS API, a log, memory in tests. Registered with `Config.Mailer` and `Config.SMS` left nil, it
becomes core's mailer and SMS sender. Works without audit.

## Install

```go
import "github.com/univeros/polaris.go/plugins/messaging"

cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), messaging.New(messaging.Config{
	Email: &messaging.SMTP{Addr: "smtp.example.com:587", From: "noreply@example.com",
		Auth: smtp.PlainAuth("", user, pass, "smtp.example.com")},
	SMS: &messaging.Twilio{AccountSID: sid, AuthToken: token, From: "+15550000000"},
}))
p, err := polaris.New(cfg) // leave cfg.Mailer and cfg.SMS nil: the plugin serves them
_, err = p.Migrate(ctx)    // creates polaris_messaging_template
```

## Config

The zero value logs every message (the development default).

| Field | Default | Purpose |
| --- | --- | --- |
| `Email`, `SMS` | none | main channel of each kind; with no channel at all nothing is delivered: each message is logged with its recipient and template only (never the body: it holds codes and reset links), and a warning says so at startup |
| `Channels` | none | more channels, tried after them in order (any kind) |
| `Locale` | `"en"` | default locale |
| `Templates` | none | instance overrides, `locale => key => messaging.Template{Subject, Text, HTML}` |
| `Strings` | none | add to or replace bundled strings, `locale => "email.otp.text" => string` |
| `Translator` | bundled + `Strings` | replaces the bundled strings (`Strings` then ignored) |
| `Caps` | `{"*": messaging.DefaultCap}` (5 per 10 min) | per recipient, keyed by template (`"sms.otp"`), kind (`"sms"`) or `"*"` |
| `Fallback` | `sms => email` | kind tried when no channel of the first delivered; empty map disables |
| `Suppressor` | sentinel's quiet mode when registered | drops non-essential messages |
| `Outbox` | nil (deliver on the request) | a queue; its worker calls `Sender.Dispatch` |

Channels: `messaging.SMTP` (net/smtp, STARTTLS when offered), `messaging.Twilio`,
`messaging.Vonage`, `messaging.HTTPSMS` (your `Request` builder for any provider), `messaging.Log`
(recipient and template; `&messaging.Log{Bodies: true}` also logs subject, body and variables, for
a developer's machine only: whoever reads that log can sign in as the recipient),
`messaging.NewMemory(name, kinds...)`; or implement `messaging.Channel`. A failing channel hands the
message to the next one of its kind, then the fallback.

## Routes

None. The plugin serves core's Mailer and SMS ports through `wiring.PortsProvider`
(`Plugin.Ports()`), so core's own routes (`/auth/register`, `/auth/password/forgot`, …) send through
it. Precedence: `Config.Mailer` / `Config.SMS`, then the first plugin providing them, then core's
log drivers.

## Events and permissions

Dispatches `messaging.sent` (`messaging.AuditSent`, a `messaging.Sent`) after every delivery; with
the audit plugin it is an audit record (channel, template, recipient hash, provider id; never the
body). No permissions.

## Problems

None over HTTP. A send answers `messaging.ErrRefused` (cap or quiet mode),
`messaging.ErrUndelivered` or `messaging.ErrTemplateNotFound`; core's ports log these and carry on.

## Host integration

- Your own messages: `messaging.Of(g).Sender().Send(ctx, messaging.Message{Kind: messaging.KindEmail,
  To: u.Email, Template: "email.new_device", Vars: map[string]any{"ip": ip}}, nil)`. Bundled keys:
  `messaging.TemplateKeys`; core's names map through `messaging.CoreTemplates`.
- Set `Message.Essential` for messages quiet mode must never drop. Core's verifications, resets, codes,
  invitations and account-change mails are. A recipient's `Caps` bound essential messages too.
- Organization branding: `Plugin.Templates().Set(ctx, orgID, key, locale, tpl)`, `Remove`,
  `Override`; a message with `OrganizationID` uses them.
- Check a channel and a template: `Plugin.SendTemplate(ctx, to, template, varsJSON, locale)`.
- Quiet mode matches recipients case-insensitively.
- Variables render as text: strings as they are, numbers in plain form, booleans as `true` /
  `false`; in the HTML part they are escaped with `html.EscapeString`.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/messaging`.
