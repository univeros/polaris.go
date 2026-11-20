package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

var ctx = context.Background()

func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func TestLogSMSLogsTheRecipientAndMessage(t *testing.T) {
	var buf bytes.Buffer
	s := NewLogSMS(slog.New(slog.NewJSONHandler(&buf, nil)))
	if err := s.Send(ctx, "+14155550101", "Your code is 123456"); err != nil {
		t.Fatal(err)
	}

	recs := records(t, &buf)
	// Record 0 is the construction-time warning that this dev driver writes codes to the log.
	if len(recs) != 2 || recs[0]["level"] != "WARN" || !strings.Contains(recs[0]["msg"].(string), "WRITTEN TO THE LOG") {
		t.Fatalf("records = %v", recs)
	}
	if recs[1]["msg"] != "Polaris dev SMS (not delivered)" || recs[1]["to"] != "+14155550101" || recs[1]["message"] != "Your code is 123456" {
		t.Fatalf("record = %v", recs[1])
	}
}

func TestLogMailerLogsTheRecipientTemplateAndData(t *testing.T) {
	var buf bytes.Buffer
	m := NewLogMailer(slog.New(slog.NewJSONHandler(&buf, nil)))
	if err := m.Send(ctx, "ada@example.com", TemplateOTPCode, map[string]any{"code": "123456", "ttl": 300}); err != nil {
		t.Fatal(err)
	}

	recs := records(t, &buf)
	if len(recs) != 2 || recs[0]["level"] != "WARN" {
		t.Fatalf("records = %v", recs)
	}
	ctxData, _ := recs[1]["context"].(map[string]any)
	if recs[1]["to"] != "ada@example.com" || recs[1]["template"] != "otp_code" || ctxData["code"] != "123456" || ctxData["ttl"] != 300.0 {
		t.Fatalf("record = %v", recs[1])
	}
}

func TestLogDriversWithANilLoggerUseTheDefault(t *testing.T) {
	_ = NewLogSMS(nil).Send(ctx, "+14155550101", "x")
	_ = NewLogMailer(nil).Send(ctx, "a@b.c", "otp_code", nil)
}

func TestDiscardDriversAreSilentNoOps(t *testing.T) {
	if err := (DiscardSMS{}).Send(ctx, "+14155550101", "ignored"); err != nil {
		t.Fatal(err)
	}
	if err := (DiscardMailer{}).Send(ctx, "ada@example.com", TemplateOTPCode, map[string]any{"code": "123456"}); err != nil {
		t.Fatal(err)
	}
}
