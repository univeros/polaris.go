// Package notify delivers one-time codes and account notifications by email and SMS.
//
// Pass production adapters (SES, SMTP, Twilio, …) as a [Mailer] and an [SMSSender]. The
// defaults, [LogMailer] and [LogSMS], write the message (one-time code included) to the log
// instead of sending it and warn loudly when built: fine in development, never in production.
// [DiscardMailer] and [DiscardSMS] drop everything, for deployments without that channel.
// Recording fakes for tests are in notify/notifytest.
package notify

import (
	"context"
	"log/slog"
)

// Mailer delivers a transactional email. template is a logical name (the Template constants)
// that the adapter renders with data; [Subject] and [Text] are a working plain-text rendering.
type Mailer interface {
	Send(ctx context.Context, to, template string, data map[string]any) error
}

// SMSSender delivers an SMS to a phone number in E.164 form (+14155550101).
type SMSSender interface {
	Send(ctx context.Context, to, message string) error
}

// LogMailer is the development Mailer: it logs instead of sending, codes included.
type LogMailer struct{ logger *slog.Logger }

// NewLogMailer returns a LogMailer on logger (nil means slog.Default()) and logs a warning that
// codes are written to the log, so a forgotten production binding is loud.
func NewLogMailer(logger *slog.Logger) *LogMailer {
	logger = orDefault(logger)
	logger.Warn("Polaris is using the development Log email driver; one-time codes will be WRITTEN TO THE LOG, not delivered. Bind a production adapter before going live.")
	return &LogMailer{logger: logger}
}

// Send implements Mailer.
func (m *LogMailer) Send(ctx context.Context, to, template string, data map[string]any) error {
	m.logger.InfoContext(ctx, "Polaris dev email (not delivered)", "to", to, "template", template, "context", data)
	return nil
}

// LogSMS is the development SMSSender: it logs instead of sending, codes included.
type LogSMS struct{ logger *slog.Logger }

// NewLogSMS returns a LogSMS on logger (nil means slog.Default()) and logs a warning that codes
// are written to the log, so a forgotten production binding is loud.
func NewLogSMS(logger *slog.Logger) *LogSMS {
	logger = orDefault(logger)
	logger.Warn("Polaris is using the development Log SMS driver; one-time codes will be WRITTEN TO THE LOG, not delivered. Bind a production adapter before going live.")
	return &LogSMS{logger: logger}
}

// Send implements SMSSender.
func (s *LogSMS) Send(ctx context.Context, to, message string) error {
	s.logger.InfoContext(ctx, "Polaris dev SMS (not delivered)", "to", to, "message", message)
	return nil
}

// DiscardMailer drops every email, for deployments that disable the email channel.
type DiscardMailer struct{}

// Send implements Mailer.
func (DiscardMailer) Send(context.Context, string, string, map[string]any) error { return nil }

// DiscardSMS drops every SMS, for deployments that disable the SMS channel.
type DiscardSMS struct{}

// Send implements SMSSender.
func (DiscardSMS) Send(context.Context, string, string) error { return nil }

func orDefault(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
