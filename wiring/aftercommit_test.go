package wiring

import (
	"context"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
)

// queueing is an adapter whose transactions queue AfterCommit functions; open says whether ctx is
// inside one.
type queueing struct {
	store.Adapter
	open   bool
	queued []func()
}

func (q *queueing) AfterCommit(_ context.Context, fn func()) bool {
	if q.open {
		q.queued = append(q.queued, fn)
	}
	return q.open
}

// wrapped is an adapter around another one, as telemetry/otel's.
type wrapped struct{ store.Adapter }

func (w wrapped) Unwrap() store.Adapter { return w.Adapter }

func TestEventsWaitForTheCommitOfAWrappedAdapter(t *testing.T) {
	var got []string
	var bus event.Bus
	bus.Subscribe(func(_ context.Context, e event.Event) { got = append(got, e.EventName()) })
	tx := &queueing{Adapter: memstore.New(schema.Core()...), open: true}
	d := deferUntilCommit(wrapped{tx}, &bus)

	d.Dispatch(context.Background(), event.UserRegistered{})
	if len(got) != 0 || len(tx.queued) != 1 {
		t.Fatalf("inside a transaction: dispatched %v, queued %d", got, len(tx.queued))
	}
	tx.queued[0]()
	tx.open = false
	d.Dispatch(context.Background(), event.UserDeleted{})
	if len(got) != 2 || got[0] != event.NameUserRegistered || got[1] != event.NameUserDeleted {
		t.Fatalf("after the commit, then outside one: %v", got)
	}

	if d := deferUntilCommit(memstore.New(), &bus); d != event.Dispatcher(&bus) {
		t.Fatal("an adapter without AfterCommit keeps the dispatcher as it is")
	}
}
