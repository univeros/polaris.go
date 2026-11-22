package admin

import (
	"context"
	"sync"
	"testing"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/store/sqlstore"
	"github.com/univeros/polaris.go/store/storetest"
)

// Two replicas granting one user their first role at once: one grant row, each call answered as a
// sequential upsert answers (the grant, its id kept).
func TestConcurrentFirstGrantsOfOneUserKeepOneRow(t *testing.T) {
	ctx := context.Background()
	for _, b := range storetest.Backends() {
		if b.Dialect == store.SQLite {
			continue // SQLite serializes writers: a second first grant cannot insert beside the first
		}
		t.Run(b.Name, func(t *testing.T) {
			var one, two store.Adapter
			if b.Dialect == store.Memory {
				db := memstore.New(Models()...)
				one, two = db, db
			} else {
				s := storetest.OpenSQL(t, b.Dialect)
				if err := s.CreateSchema(ctx, Models()); err != nil {
					t.Fatal(err)
				}
				one, two = s, sqlstore.New(s.DB(), b.Dialect) // two stores, as two processes
			}
			replicas := []*Grants{{db: one, clock: clock.System{}}, {db: two, clock: clock.System{}}}
			for round := range 20 {
				user := "user-" + string(rune('a'+round))
				var wg sync.WaitGroup
				ids := make([]string, 8)
				for i := range ids {
					wg.Go(func() {
						g, err := replicas[i%2].Grant(ctx, Grant{UserID: user, Role: RoleSupport})
						if err != nil {
							t.Errorf("grant: %v", err)
						}
						ids[i] = g.ID
					})
				}
				wg.Wait()
				if n, err := one.Count(ctx, TableGrants, store.Criteria{"user_id": user}); err != nil || n != 1 {
					t.Fatalf("%s: %d grant rows, %v", user, n, err)
				}
				for _, id := range ids {
					if id != ids[0] {
						t.Fatalf("%s: grants answered ids %v", user, ids)
					}
				}
			}
		})
	}
}
