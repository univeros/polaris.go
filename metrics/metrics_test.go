package metrics

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
)

func TestLogWritesEachCounterAsADebugRecord(t *testing.T) {
	var buf bytes.Buffer
	m := NewLog(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	m.Counter(context.Background(), "polaris.auth.events", 1, map[string]string{"event": "polaris.user.registered"})

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["level"] != "DEBUG" || rec["msg"] != "metric polaris.auth.events +1" || rec["name"] != "polaris.auth.events" || rec["value"] != 1.0 {
		t.Fatalf("record = %v", rec)
	}
	if attrs, _ := rec["attributes"].(map[string]any); attrs["event"] != "polaris.user.registered" {
		t.Fatalf("attributes = %v", rec["attributes"])
	}
}

func TestLogWithANilLoggerUsesTheDefault(t *testing.T) {
	NewLog(nil).Counter(context.Background(), "n", 2, nil)
}
