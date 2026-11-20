package mcp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

// staleReads is a cache shared by replicas whose reads lag the other replicas' writes: only the
// atomic Add keeps a value single-use there (a get-then-set lets every replica through).
type staleReads struct{ cache.Cache }

func (staleReads) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }

func TestADPoPProofIsAcceptedOnceAcrossConcurrentReplicas(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFrozen(time.Unix(1_800_000_000, 0))
	shared := staleReads{cache.NewMemory(clk)}
	key := newDPoPKey()
	proof := key.proof(t, "POST", testResource, "tok", "j1", clk.Now().Unix())
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		replica := &dpopProofs{cache: shared, clock: clk}
		wg.Go(func() {
			if _, err := replica.thumbprint(ctx, proof, "POST", testResource, "tok"); err == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if n := accepted.Load(); n != 1 {
		t.Fatalf("the proof was accepted %d times; want 1", n)
	}
}
