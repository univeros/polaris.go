// Package event is the domain-event port. Every event is a struct with a stable EventName()
// (user.logged_in, agent.executed, …).
//
// Package event is part of the plugin SDK (wiring, endpoint, manifest, event, token): what a
// third-party plugin builds on. API.md states what is stable.
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
