package observe

import (
	"context"
	"reflect"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/metrics"
)

// MetricCounter is the counter every core event increments, with its name in the "event"
// attribute.
const MetricCounter = "polaris.auth.events"

var corePackage = reflect.TypeFor[event.UserLoggedIn]().PkgPath()

// Metrics returns the listener that counts every core event on m (upstream MetricsListener): one
// MetricCounter increment with attribute event=<event name>, so alerts filter on e.g.
// event=auth.refresh_reuse_detected. Only the core events of package event count (upstream counts
// the Polaris\Event namespace only); a plugin's events are its own to measure.
func Metrics(m metrics.Metrics) event.Listener {
	return func(ctx context.Context, e event.Event) {
		t := reflect.TypeOf(e)
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if t.PkgPath() != corePackage {
			return
		}
		m.Counter(ctx, MetricCounter, 1, map[string]string{"event": e.EventName()})
	}
}
