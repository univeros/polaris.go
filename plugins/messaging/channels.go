package messaging

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"time"
)

// Log is the development channel: every message, body included, goes to the logger (nil:
// slog.Default()). It supports every kind.
type Log struct{ Logger *slog.Logger }

// Name implements Channel.
func (*Log) Name() string { return "log" }

// Supports implements Channel.
func (*Log) Supports(string) bool { return true }

// Send implements Channel.
func (l *Log) Send(ctx context.Context, m Message) (string, error) {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.InfoContext(ctx, "messaging: message (not delivered: log channel)", "kind", m.Kind, "template", m.Template,
		"to", m.To, "subject", m.Subject, "text", m.Text, "html", m.HTML, "vars", m.Vars)
	return "", nil
}

// Memory keeps every message, for tests. NewMemory names it and limits its kinds; SetFailing makes
// it fail. Safe for concurrent use.
type Memory struct {
	name    string
	kinds   []string
	mu      sync.Mutex
	failing bool
	sent    []Message
}

// NewMemory returns a Memory channel named name ("memory" when empty) supporting kinds (every
// kind when none).
func NewMemory(name string, kinds ...string) *Memory {
	if name == "" {
		name = "memory"
	}
	return &Memory{name: name, kinds: kinds}
}

// Name implements Channel.
func (c *Memory) Name() string { return c.name }

// Supports implements Channel.
func (c *Memory) Supports(kind string) bool {
	return len(c.kinds) == 0 || slices.Contains(c.kinds, kind)
}

// Send records the message; its provider id is "<name>-<n>".
func (c *Memory) Send(_ context.Context, m Message) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failing {
		return "", fmt.Errorf("%s is down", c.name)
	}
	c.sent = append(c.sent, m)
	return fmt.Sprintf("%s-%d", c.name, len(c.sent)), nil
}

// SetFailing makes every later Send fail (true) or succeed (false).
func (c *Memory) SetFailing(failing bool) { c.mu.Lock(); c.failing = failing; c.mu.Unlock() }

// Messages returns a copy of the messages sent so far, oldest first.
func (c *Memory) Messages() []Message { c.mu.Lock(); defer c.mu.Unlock(); return slices.Clone(c.sent) }

// SMTP sends email through an SMTP server with net/smtp (STARTTLS when the server offers it). The
// message is text/plain, or multipart/alternative with the HTML part when the template has one,
// UTF-8, quoted-printable.
type SMTP struct {
	Addr string    // "host:port"
	Auth smtp.Auth // nil for none; smtp.PlainAuth(...) usually
	From string    // the sender address, "noreply@example.com" or "Acme <noreply@example.com>"

	send func(addr string, a smtp.Auth, from string, to []string, msg []byte) error // smtp.SendMail; tests swap it
}

// Name implements Channel.
func (*SMTP) Name() string { return "smtp" }

// Supports implements Channel: email only.
func (*SMTP) Supports(kind string) bool { return kind == KindEmail }

// Send implements Channel; the provider id is the generated Message-ID.
func (s *SMTP) Send(_ context.Context, m Message) (string, error) {
	from, err := mail.ParseAddress(s.From)
	if err != nil {
		return "", fmt.Errorf("smtp: From %q: %w", s.From, err)
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return "", fmt.Errorf("smtp: recipient: %w", err)
	}
	id, body, err := compose(from, to, m, time.Now())
	if err != nil {
		return "", err
	}
	send := s.send
	if send == nil {
		send = smtp.SendMail
	}
	if err := send(s.Addr, s.Auth, from.Address, []string{to.Address}, body); err != nil {
		return "", fmt.Errorf("smtp: %w", err)
	}
	return id, nil
}

// compose writes the RFC 5322 message; id is its Message-ID.
func compose(from, to *mail.Address, m Message, now time.Time) (id string, msg []byte, err error) {
	if strings.ContainsAny(m.Subject, "\r\n") {
		return "", nil, errors.New("smtp: the subject has a line break")
	}
	random := make([]byte, 16)
	_, _ = rand.Read(random)
	_, domain, _ := strings.Cut(from.Address, "@")
	id = "<" + hex.EncodeToString(random) + "@" + domain + ">"

	var b bytes.Buffer
	header := func(name, value string) { fmt.Fprintf(&b, "%s: %s\r\n", name, value) }
	header("From", from.String())
	header("To", to.String())
	header("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	header("Date", now.Format(time.RFC1123Z))
	header("Message-ID", id)
	header("MIME-Version", "1.0")
	if m.HTML == "" {
		header("Content-Type", "text/plain; charset=utf-8")
		header("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := qpTo(&b, m.Text); err != nil {
			return "", nil, err
		}
		return id, b.Bytes(), nil
	}
	mw := multipart.NewWriter(&b)
	header("Content-Type", "multipart/alternative; boundary="+mw.Boundary())
	b.WriteString("\r\n")
	for _, part := range []struct{ typ, body string }{{"text/plain", m.Text}, {"text/html", m.HTML}} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type": {part.typ + "; charset=utf-8"}, "Content-Transfer-Encoding": {"quoted-printable"}})
		if err != nil {
			return "", nil, err
		}
		if err := qpTo(w, part.body); err != nil {
			return "", nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return "", nil, err
	}
	return id, b.Bytes(), nil
}

func qpTo(w io.Writer, s string) error {
	q := quotedprintable.NewWriter(w)
	if _, err := q.Write([]byte(s)); err != nil {
		return err
	}
	return q.Close()
}
