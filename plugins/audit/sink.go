package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/univeros/polaris.go/repository"
)

// Webhook headers.
const (
	SignatureHeader = "X-Polaris-Signature"
	DeliveryHeader  = "X-Polaris-Delivery"
)

// Sink receives recorded events: the database (always), and the extra sinks of Config.Sinks
// (LogSink, FileSink, WebhookSink, or the host's own). A failing sink is logged and never breaks
// the operation it observes.
type Sink interface {
	Write(ctx context.Context, events ...Event) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, events ...Event) error

// Write implements Sink.
func (f SinkFunc) Write(ctx context.Context, events ...Event) error { return f(ctx, events...) }

// chain writes to every sink in order, fail-open.
type chain struct {
	sinks  []Sink
	logger *slog.Logger
}

func (c chain) Write(ctx context.Context, events ...Event) error {
	for _, s := range c.sinks {
		if err := s.Write(ctx, events...); err != nil {
			c.logger.ErrorContext(ctx, "Audit sink failed", "sink", fmt.Sprintf("%T", s), "reason", err.Error())
		}
	}
	return nil
}

// databaseSink is the default sink: the store, hash chain included.
type databaseSink struct{ store *Store }

func (d databaseSink) Write(ctx context.Context, events ...Event) error {
	for _, e := range events {
		if _, err := d.store.Write(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

// LogSink writes one log record per event ("audit <name>"), the event as the "audit" attribute.
type LogSink struct {
	Logger *slog.Logger // nil: slog.Default()
	Level  slog.Level   // zero: Info
}

// Write implements Sink.
func (l LogSink) Write(ctx context.Context, events ...Event) error {
	logger := l.Logger
	if logger == nil {
		logger = slog.Default()
	}
	for _, e := range events {
		logger.Log(ctx, l.Level, "audit "+e.Name, "name", e.Name, "audit", e.Map())
	}
	return nil
}

// FileSink appends JSON lines, one event per line: for development and tail-based shippers.
type FileSink struct {
	Path string
	mu   sync.Mutex
}

// Write implements Sink.
func (f *FileSink) Write(_ context.Context, events ...Event) error {
	if len(events) == 0 {
		return nil
	}
	var b bytes.Buffer
	for _, e := range events {
		line, err := canonicalJSON(e.Map())
		if err != nil {
			return err
		}
		b.WriteString(line + "\n")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.OpenFile(f.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: cannot append to the audit file %s: %w", f.Path, err)
	}
	if _, err := file.Write(b.Bytes()); err != nil {
		_ = file.Close()
		return fmt.Errorf("audit: cannot append to the audit file %s: %w", f.Path, err)
	}
	return file.Close()
}

// WebhookSink POSTs a batch {"events": [...]} to URL, signed with HMAC-SHA256 of the body
// (X-Polaris-Signature: sha256=<hex>) and identified by X-Polaris-Delivery. A transport failure,
// a 429 or a 5xx is retried with a growing pause (200 ms × attempt); any other status ≥ 300 is
// final.
type WebhookSink struct {
	URL      string
	Secret   string
	Client   *http.Client        // nil: http.DefaultClient
	Attempts int                 // 0: 3
	Sleep    func(time.Duration) // nil: time.Sleep; tests pass a no-op
}

// Write implements Sink.
func (s WebhookSink) Write(ctx context.Context, events ...Event) error {
	if len(events) == 0 {
		return nil
	}
	list := make([]any, len(events))
	for i, e := range events {
		list[i] = e.Map()
	}
	encoded, err := canonicalJSON(map[string]any{"events": list})
	if err != nil {
		return err
	}
	body := []byte(encoded)
	client, attempts, sleep := s.Client, s.Attempts, s.Sleep
	if client == nil {
		client = http.DefaultClient
	}
	if attempts <= 0 {
		attempts = 3
	}
	if sleep == nil {
		sleep = time.Sleep
	}
	mac := hmac.New(sha256.New, []byte(s.Secret))
	mac.Write(body)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	delivery := repository.NewID()
	last := "no attempt made"
	for attempt := 1; attempt <= attempts; attempt++ {
		status, err := s.post(ctx, client, body, signature, delivery)
		if err == nil && status < 300 {
			return nil
		}
		if err != nil {
			last = err.Error()
		} else {
			last = fmt.Sprintf("HTTP %d", status)
			if status != http.StatusTooManyRequests && status < 500 {
				break
			}
		}
		if attempt < attempts {
			sleep(time.Duration(attempt*200) * time.Millisecond)
		}
	}
	return fmt.Errorf("audit: webhook %s failed after %d attempt(s): %s", s.URL, attempts, last)
}

func (s WebhookSink) post(ctx context.Context, client *http.Client, body []byte, signature, delivery string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(DeliveryHeader, delivery)
	req.Header.Set(SignatureHeader, signature)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}
