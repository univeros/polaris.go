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

// committerOf is db's AfterCommit, or that of an adapter it wraps (Unwrap, as telemetry/otel's
// does); nil when none has one.
func committerOf(db store.Adapter) afterCommitter {
	for a := db; a != nil; {
		if tx, ok := a.(afterCommitter); ok {
			return tx
		}
		u, ok := a.(interface{ Unwrap() store.Adapter })
		if !ok {
			break
		}
		a = u.Unwrap()
	}
	return nil
}

// Deferred returns l delayed to the commit: an event raised inside a transaction of DB (a
// sqlstore.Store.Tx, Polaris's own or the host's) reaches l right after the outermost commit, in
// order, and never if it rolls back; outside one, at once. Use it for a listener whose effect
// leaves the database (mail, SMS, a webhook, a queue), so nothing goes out for work that did not
// commit. A listener that writes to the store with ctx needs no wrapper: it runs inside the
// transaction and commits or rolls back with the action. Config.Listeners are wrapped this way;
// Config.TxListeners are not. Under sqlstore.WithTx (the host's own *sql.Tx, whose commit
// Polaris does not see) and on an adapter without AfterCommit, l runs at once.
func (g *Graph) Deferred(l event.Listener) event.Listener {
	tx := g.committer
	if tx == nil {
		return l
	}
	return func(ctx context.Context, e event.Event) {
		if !tx.AfterCommit(ctx, func() { l(ctx, e) }) {
			l(ctx, e)
		}
	}
}
