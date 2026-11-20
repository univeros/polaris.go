// Package cache is the short-lived key/value port Polaris uses for rate-limit counters, replay
// guards, flow state and the access-token denylist.
//
// Values are bytes: callers encode, so an in-process cache and a shared one (Redis, Memcached)
// behave the same. The default [Memory] lives in one process; run more than one replica and the
// rate limits and replay guards only hold if you pass a shared Cache, whose Add is atomic across
// the replicas (see [Cache]).
package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris.go/clock"
)

// Cache stores values with a time to live. Implementations are safe for concurrent use.
type Cache interface {
	// Get returns the value and true, or nil and false when the key is absent or expired.
	Get(ctx context.Context, key string) ([]byte, bool, error)
	// Set stores value for ttl. A ttl <= 0 is already expired: it stores nothing and removes any
	// previous value.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete removes the key; an absent key is not an error.
	Delete(ctx context.Context, key string) error
	// Add stores value for ttl only when key is absent (or expired) and reports whether it did.
	// It is the single-use primitive behind every replay guard (request JWT, DPoP proof and client
	// assertion jti), so it must be atomic across every process sharing the cache: two concurrent
	// Adds of one key must never both return true. On Redis that is SET key value NX PX ttl; on
	// Memcached, add. A ttl <= 0 stores nothing and returns false.
	Add(ctx context.Context, key string, value []byte, ttl time.Duration) (added bool, err error)
}

// ErrInvalidKey reports an empty key or one with a character PSR-16 reserves ({}()/\@:).
var ErrInvalidKey = errors.New("cache: invalid key")

const reservedKeyChars = `{}()/\@:`

// ValidateKey returns ErrInvalidKey for an empty key or one with a reserved character.
// Implementations call it so keys stay portable across backends.
func ValidateKey(key string) error {
	if key == "" {
		return fmt.Errorf("%w: a cache key must be a non-empty string", ErrInvalidKey)
	}
	if strings.ContainsAny(key, reservedKeyChars) {
		return fmt.Errorf("%w: %q contains a character reserved by PSR-16 (%s)", ErrInvalidKey, key, reservedKeyChars)
	}
	return nil
}

// sweepFloor is the entry count below which Memory never sweeps.
const sweepFloor = 1024

// Memory is an in-process Cache. Expired entries are dropped on read and swept when the map
// doubles, so a long-running process does not keep dead counters.
type Memory struct {
	clock clock.Clock

	mu        sync.Mutex
	entries   map[string]entry
	nextSweep int
}

type entry struct {
	value     []byte
	expiresAt time.Time
}

// NewMemory returns an empty in-process cache on clk; nil means the system clock.
func NewMemory(clk clock.Clock) *Memory {
	if clk == nil {
		clk = clock.System{}
	}
	return &Memory{clock: clk, entries: map[string]entry{}, nextSweep: sweepFloor}
}

// Get implements Cache.
func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	if err := ValidateKey(key); err != nil {
		return nil, false, err
	}
	now := m.clock.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return nil, false, nil
	}
	if !now.Before(e.expiresAt) {
		delete(m.entries, key)
		return nil, false, nil
	}
	return clone(e.value), true, nil
}

// Set implements Cache.
func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	now := m.clock.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if ttl <= 0 {
		delete(m.entries, key)
		return nil
	}
	m.entries[key] = entry{value: clone(value), expiresAt: now.Add(ttl)}
	if len(m.entries) >= m.nextSweep {
		m.sweep(now)
	}
	return nil
}

// Add implements Cache; the check and the write happen under one lock.
func (m *Memory) Add(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if err := ValidateKey(key); err != nil {
		return false, err
	}
	if ttl <= 0 {
		return false, nil
	}
	now := m.clock.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[key]; ok && now.Before(e.expiresAt) {
		return false, nil
	}
	m.entries[key] = entry{value: clone(value), expiresAt: now.Add(ttl)}
	if len(m.entries) >= m.nextSweep {
		m.sweep(now)
	}
	return true, nil
}

// Delete implements Cache.
func (m *Memory) Delete(_ context.Context, key string) error {
	if err := ValidateKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.entries, key)
	m.mu.Unlock()
	return nil
}

// sweep drops expired entries; the caller holds mu. Amortised O(1) per Set.
func (m *Memory) sweep(now time.Time) {
	for k, e := range m.entries {
		if !now.Before(e.expiresAt) {
			delete(m.entries, k)
		}
	}
	m.nextSweep = max(sweepFloor, 2*len(m.entries))
}

func (m *Memory) len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries)
}

func clone(b []byte) []byte { return append([]byte{}, b...) }
