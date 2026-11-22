package wiring

import (
	"context"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/store"
)

// afterCommitter is an adapter that runs functions after the transaction ctx carries commits
// (sqlstore.Store.AfterCommit).
type afterCommitter interface {
	AfterCommit(ctx context.Context, fn func()) bool
}

// deferUntilCommit wraps next so that an event raised inside a transaction of db is dispatched
// after that transaction commits, and never when it rolls back. db, or an adapter it wraps
// (Unwrap, as telemetry/otel's does), must implement AfterCommit; otherwise next is returned as
// it is and events are dispatched at once.
func deferUntilCommit(db store.Adapter, next event.Dispatcher) event.Dispatcher {
	for a := db; a != nil; {
		if tx, ok := a.(afterCommitter); ok {
			return afterCommit{tx: tx, next: next}
		}
		u, ok := a.(interface{ Unwrap() store.Adapter })
		if !ok {
			break
		}
		a = u.Unwrap()
	}
	return next
}

type afterCommit struct {
	tx   afterCommitter
	next event.Dispatcher
}

func (d afterCommit) Dispatch(ctx context.Context, e event.Event) {
	if !d.tx.AfterCommit(ctx, func() { d.next.Dispatch(ctx, e) }) {
		d.next.Dispatch(ctx, e)
	}
}
