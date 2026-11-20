// Package clock is the time port. Tests freeze it; production uses System.
package clock

import (
	"sync"
	"time"
)

// Clock returns the current time.
type Clock interface{ Now() time.Time }

// System is the wall clock, in UTC.
type System struct{}

func (System) Now() time.Time { return time.Now().UTC() }

// Frozen is a settable clock for tests.
type Frozen struct {
	mu sync.Mutex
	t  time.Time
}

// NewFrozen returns a clock stopped at t.
func NewFrozen(t time.Time) *Frozen { return &Frozen{t: t.UTC()} }

func (f *Frozen) Now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.t }

// Set moves the clock to t.
func (f *Frozen) Set(t time.Time) { f.mu.Lock(); f.t = t.UTC(); f.mu.Unlock() }

// Advance moves the clock forward by d.
func (f *Frozen) Advance(d time.Duration) { f.mu.Lock(); f.t = f.t.Add(d); f.mu.Unlock() }
