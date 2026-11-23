package audit_test

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
)

// A name with its own retention leaves gaps anywhere in the chain. Verify accepts each, also once the
// checkpoint that recorded it is itself pruned, and still reports what nobody pruned.
func TestAPrunedChainWithPerNameRetentionVerifies(t *testing.T) {
	p := audit.New(audit.Config{HashChain: true, Retention: audit.Retention{Default: "P90D",
		Names: map[string]string{audit.SessionSignedIn: "P30D", audit.UserSignedUp: "P7Y"}}})
	srv := polaristest.New(t, polaristest.WithPlugins(p))
	ctx := context.Background()
	record := func(name string, ago time.Duration) {
		t.Helper()
		if err := p.Record(ctx, audit.Event{Name: name, ActorID: "u1", ActorType: audit.ActorUser, OccurredAt: time.Now().Add(-ago)}); err != nil {
			t.Fatal(err)
		}
	}
	intact := func(when string, want bool) {
		t.Helper()
		if r, err := p.Verify(ctx); err != nil || r.Intact() != want {
			t.Fatalf("%s: %v %+v", when, err, r)
		}
	}
	prune := func(want int64) {
		t.Helper()
		if n, err := p.Prune(ctx); err != nil || n != want {
			t.Fatalf("pruned %d %v, want %d", n, err, want)
		}
	}
	const day = 24 * time.Hour
	for range 3 {
		record(audit.UserSignedUp, 60*day)
		record(audit.SessionSignedIn, 60*day)
		record(audit.SessionSignedIn, 60*day)
	}
	record(audit.SessionSignedIn, day)
	intact("before", true)
	prune(6)
	intact("after a pruning", true)

	// The checkpoint ages out; the gaps it recorded stay accepted.
	if _, err := srv.Graph().DB().Update(ctx, audit.TableEvents, store.Criteria{"name": audit.AuditPruned}, store.Data{"occurred_at": time.Now().Add(-100 * day)}); err != nil {
		t.Fatal(err)
	}
	prune(1)
	if r, _ := p.Verify(ctx); len(r.Breaks) != 0 {
		t.Fatalf("after the checkpoint was pruned: %v", r.Breaks)
	}

	// A row nobody pruned that is gone is a break, and pruning does not hide it.
	var ids []string
	if err := p.Store().Walk(ctx, 100, func(e audit.Event) error { ids = append(ids, e.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Graph().DB().Delete(ctx, audit.TableEvents, store.Criteria{"id": ids[1]}); err != nil {
		t.Fatal(err)
	}
	intact("a deleted row", false)
	record(audit.SessionSignedIn, 60*day)
	record(audit.UserSignedUp, day)
	prune(1)
	intact("after another pruning", false)
}
