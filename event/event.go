// Package event is the domain-event port, the Go form of PSR-14 in PHP Polaris. Every event is a
// struct whose EventName() equals the PHP event's NAME constant (user.logged_in, agent.executed, …).
package event

import (
	"context"
	"sync"
)

// Event is any domain event.
type Event interface{ EventName() string }

// Listener receives every dispatched event and ignores the ones it does not handle.
type Listener func(ctx context.Context, e Event)

// Dispatcher delivers events. The host may supply its own (a queue, a bus); Bus is the default.
type Dispatcher interface {
	Dispatch(ctx context.Context, e Event)
}

// Bus is a synchronous in-process dispatcher: listeners run in subscription order on the caller's
// goroutine.
type Bus struct {
	mu        sync.RWMutex
	listeners []Listener
}

// Subscribe adds listeners.
func (b *Bus) Subscribe(l ...Listener) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.listeners = append(b.listeners, l...)
}

// Dispatch implements Dispatcher.
func (b *Bus) Dispatch(ctx context.Context, e Event) {
	b.mu.RLock()
	ls := b.listeners
	b.mu.RUnlock()
	for _, l := range ls {
		l(ctx, e)
	}
}

// Nop discards every event.
type Nop struct{}

func (Nop) Dispatch(context.Context, Event) {}
