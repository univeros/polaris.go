// Package metrics is where Polaris counts its domain events. Pass your metrics client as a
// [Metrics]; the default, [Log], writes each increment as a debug log record.
package metrics

import (
	"context"
	"log/slog"
	"strconv"
)

// Metrics counts named events. Implementations are safe for concurrent use.
type Metrics interface {
	Counter(ctx context.Context, name string, value float64, attributes map[string]string)
}

// Log is the default Metrics: every counter increment is a slog debug record.
type Log struct{ logger *slog.Logger }

// NewLog returns a Metrics writing to logger; nil means slog.Default().
func NewLog(logger *slog.Logger) *Log {
	if logger == nil {
		logger = slog.Default()
	}
	return &Log{logger: logger}
}

// Counter implements Metrics.
func (l *Log) Counter(ctx context.Context, name string, value float64, attributes map[string]string) {
	l.logger.DebugContext(ctx, "metric "+name+" +"+strconv.FormatFloat(value, 'f', -1, 64),
		"name", name, "value", value, "attributes", attributes)
}
