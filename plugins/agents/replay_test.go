package agents

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

// staleReads is a cache shared by replicas whose reads lag the other replicas' writes: only the
// atomic Add keeps a value single-use there (a get-then-set lets every replica through).
type staleReads struct{ cache.Cache }

func (staleReads) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }

func TestARequestJWTIsAcceptedOnceAcrossConcurrentReplicas(t *testing.T) {
	p, _ := bootUnit(t, Config{})
	ctx := context.Background()
	execute := unitBase + "/agents/execute"
	k := newTestKey(AlgES256)
	a := newAgent(t, p, k)
	jwt := k.jwt(k.request(a.ID, execute, nil), nil)
	shared := staleReads{cache.NewMemory(nil)}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		replica := &requestJWTs{cache: shared, clock: clock.System{}, maxAge: 300}
		wg.Go(func() {
			if _, err := replica.verify(ctx, jwt, a, "POST", execute, nil); err == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	if n := accepted.Load(); n != 1 {
		t.Fatalf("the JWT was accepted %d times; want 1", n)
	}
}
