package observe

import (
	"context"
	"maps"
	"sync"
	"testing"

	"github.com/univeros/polaris.go/event"
)

type point struct {
	name  string
	value float64
	attrs map[string]string
}

type recordingMetrics struct {
	mu     sync.Mutex
	points []point
}

func (r *recordingMetrics) Counter(_ context.Context, name string, value float64, attributes map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.points = append(r.points, point{name, value, attributes})
}

// Port of MetricsListenerTest.
func TestMetricsCountsCoreEventsByName(t *testing.T) {
	m := &recordingMetrics{}
	listen := Metrics(m)
	listen(ctx, event.UserLoggedIn{UserID: "user-1", SessionID: "session-1"})
	listen(ctx, &event.UserLoginFailed{UserID: "user-1"})
	listen(ctx, event.RefreshReuseDetected{UserID: "user-1", FamilyID: "family-1"})
	listen(ctx, event.UserRegistered{UserID: "user-1", Email: "new@example.com", VerificationToken: "verification-secret-token"})
	listen(ctx, unknownEvent{}) // outside the core event package

	want := []string{"user.logged_in", "user.login_failed", "auth.refresh_reuse_detected", "user.registered"}
	if len(m.points) != len(want) {
		t.Fatalf("points = %+v", m.points)
	}
	for i, name := range want {
		p := m.points[i]
		if p.name != MetricCounter || p.value != 1 || !maps.Equal(p.attrs, map[string]string{"event": name}) {
			t.Errorf("point %d = %+v; want event=%s", i, p, name)
		}
	}
}
