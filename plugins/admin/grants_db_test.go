package admin

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/store/sqlstore"
	"github.com/univeros/polaris.go/store/storetest"
)

// A v0.4.1 database holding two grants for one user (made by the race above): Migrate refuses to
// add the unique index, naming the table and the column, and keeps the old index; once the extra
// grant is revoked it replaces the index.
func TestAnUpgradeWithDuplicateGrantsIsRefusedWithTheRemedy(t *testing.T) {
	ctx := context.Background()
	for _, b := range storetest.Backends() {
		if b.Dialect == store.Memory {
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			db := storetest.OpenSQL(t, b.Dialect)
			old := Models()
			old[0].Indexes = []schema.Index{{Columns: []string{"user_id"}, Name: "polaris_admin_grant_user_index"}}
			old[0].DroppedIndexes = nil
			if err := db.CreateSchema(ctx, old); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Second)
			for _, id := range []string{"g1", "g2"} {
				if err := db.Insert(ctx, TableGrants, store.Row{"id": id, "user_id": "u1", "role": "support", "scope": ScopeInstance, "created_at": now}); err != nil {
					t.Fatal(err)
				}
			}
			_, err := db.Migrate(ctx, Models())
			if err == nil || !strings.Contains(err.Error(), "polaris_admin_grant holds duplicate (user_id) values") {
				t.Fatalf("migrate over duplicates: %v", err)
			}
			if live, _ := db.Inspect(ctx, TableGrants); !slices.ContainsFunc(live.Indexes, func(i sqlstore.LiveIndex) bool { return i.Name == "polaris_admin_grant_user_index" }) {
				t.Fatalf("the old index is gone after a refused migrate: %+v", live.Indexes)
			}
			if ok, err := (&Grants{db: db, clock: clock.System{}}).Revoke(ctx, "g2"); !ok || err != nil {
				t.Fatal(ok, err)
			}
			changes, err := db.Migrate(ctx, Models())
			if err != nil || !slices.Equal(changes, []string{TableGrants + ": created index polaris_admin_grant_user_unique", TableGrants + ": dropped index polaris_admin_grant_user_index"}) {
				t.Fatalf("migrate: %v %v", changes, err)
			}
			if diffs, err := db.Diff(ctx, Models()); err != nil || len(diffs) != 0 {
				t.Fatalf("diff: %v %v", diffs, err)
			}
		})
	}
}

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
