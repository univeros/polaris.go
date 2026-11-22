package audit

import (
	"context"
	"fmt"
	"path/filepath"
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

// twoProcesses returns two adapters over one database with the audit tables, standing for two
// replicas: on SQLite two connection pools on one file, on PostgreSQL and MySQL two stores sharing a
// pool (every transaction takes its own connection, as another process's would).
func twoProcesses(t *testing.T, d store.Dialect) (store.Adapter, store.Adapter) {
	t.Helper()
	switch d {
	case store.Memory:
		db := memstore.New(Models()...)
		return db, db
	case store.SQLite:
		dsn := "file:" + filepath.Join(t.TempDir(), "audit.db") + "?_pragma=busy_timeout(10000)"
		open := func() *sqlstore.Store {
			s, err := sqlstore.Open(ctx, d, dsn)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = s.DB().Close() })
			return s
		}
		a, b := open(), open()
		if err := a.CreateSchema(ctx, Models()); err != nil {
			t.Fatal(err)
		}
		return a, b
	}
	a := storetest.OpenSQL(t, d)
	if err := a.CreateSchema(ctx, Models()); err != nil {
		t.Fatal(err)
	}
	return a, sqlstore.New(a.DB(), d)
}

func TestTheChainStaysLinearWithWritersInSeparateProcesses(t *testing.T) {
	concurrentWriters(t, "", func(_ store.Adapter, s *Store, e Event) error {
		_, err := s.Write(ctx, e)
		return err
	})
}

// An event recorded inside the host's transaction (sqlstore.WithTx, events dispatched before the
// host commits) appends inside a transaction that has already read: on MySQL's REPEATABLE READ
// its snapshot predates the chain's lock.
func TestTheChainStaysLinearWhenWritersAppendInsideATransactionThatAlreadyRead(t *testing.T) {
	// SQLite is left out: a transaction that already read cannot take the write lock while another
	// writer holds it (SQLITE_BUSY fails the host's transaction), so nothing forks there.
	concurrentWriters(t, store.SQLite, func(db store.Adapter, s *Store, e Event) error {
		return db.Tx(ctx, func(ctx context.Context) error {
			if _, err := db.FindMany(ctx, TableEvents, store.Criteria{}, store.Query{Limit: 1}); err != nil {
				return err
			}
			time.Sleep(time.Millisecond) // let the other writers move the chain past the snapshot
			_, err := s.Write(ctx, e)
			return err
		})
	})
}

func concurrentWriters(t *testing.T, skip store.Dialect, write func(db store.Adapter, s *Store, e Event) error) {
	for _, b := range storetest.Backends() {
		if b.Dialect == skip {
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			one, two := twoProcesses(t, b.Dialect)
			dbs := []store.Adapter{one, two}
			stores := []*Store{NewStore(one, true), NewStore(two, true)}
			const writers, writes = 8, 15
			var wg sync.WaitGroup
			errs := make(chan error, 2*writers*writes)
			for n, s := range stores {
				for w := range writers {
					wg.Go(func() {
						for i := range writes {
							if err := write(dbs[n], s, signedIn(fmt.Sprintf("u%d", w), time.Now(), "")); err != nil {
								errs <- fmt.Errorf("write %d: %w", i, err)
							}
						}
					})
				}
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			c, _ := NewCatalog()
			p := &Plugin{cfg: Config{HashChain: true}, catalog: c, store: stores[0], clock: clock.System{}}
			r, err := p.Verify(ctx)
			if err != nil || r.Rows != 2*writers*writes || !r.Intact() {
				t.Fatalf("verify: %d rows, %d breaks (first %v), %v", r.Rows, len(r.Breaks), first(r.Breaks), err)
			}
		})
	}
}

// A v0.4.1 database has a chain and no polaris_audit_chain table: Migrate creates the table and
// the next write continues the existing chain.
func TestAChainFromBeforeTheLockTableKeepsVerifyingAfterMigrate(t *testing.T) {
	for _, b := range storetest.Backends() {
		if b.Dialect == store.Memory {
			continue
		}
		t.Run(b.Name, func(t *testing.T) {
			db, _ := twoProcesses(t, b.Dialect)
			sql := db.(*sqlstore.Store)
			for i := range 3 {
				if _, err := NewStore(db, true).Write(ctx, signedIn(fmt.Sprintf("u%d", i), time.Now(), "")); err != nil {
					t.Fatal(err)
				}
			}
			if err := sql.Exec(ctx, "DROP TABLE "+TableChain); err != nil {
				t.Fatal(err)
			}
			created, err := sql.CreateMissing(ctx, Models())
			if err != nil || len(created) != 1 || created[0] != TableChain {
				t.Fatalf("migrate created %v, %v", created, err)
			}
			s := NewStore(db, true)
			for range 2 {
				if _, err := s.Write(ctx, signedIn("u9", time.Now(), "")); err != nil {
					t.Fatal(err)
				}
			}
			c, _ := NewCatalog()
			p := &Plugin{cfg: Config{HashChain: true}, catalog: c, store: s, clock: clock.System{}}
			if r, err := p.Verify(ctx); err != nil || r.Rows != 5 || !r.Intact() {
				t.Fatalf("verify %+v %v", r, err)
			}
		})
	}
}

// Without the lock table (Migrate not run after upgrading) a chained write fails and says so.
func TestAChainedWriteWithoutTheLockTableNamesTheFix(t *testing.T) {
	db := storetest.OpenSQL(t, store.SQLite)
	var old []schema.Model
	for _, m := range Models() {
		if m.Table != TableChain {
			old = append(old, m)
		}
	}
	if err := db.CreateSchema(ctx, old); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(db, true).Write(ctx, signedIn("u1", time.Now(), ""))
	if err == nil || !strings.Contains(err.Error(), "run Migrate") {
		t.Fatalf("write: %v", err)
	}
}

func TestAfterSortsRightAfterAUUID(t *testing.T) {
	for id, want := range map[string]string{
		"01a203b4-0ad1-7c38-b1c4-da5e979a0ccb": "01a203b4-0ad1-7c38-b1c4-da5e979a0ccc",
		"01a203b4-0ad1-7c38-80ff-ffffffffffff": "01a203b4-0ad1-7c38-8100-000000000000",
	} {
		if next, err := after(id); err != nil || next != want {
			t.Errorf("after(%s) = %s, %v", id, next, err)
		}
	}
	for _, id := range []string{"ffff", "01a203b4-0ad1-7c38-bfff-ffffffffffff"} {
		if next, err := after(id); err == nil {
			t.Errorf("after(%s) = %s", id, next)
		}
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// The tip lives on the lock row, so pruning the newest event leaves the next row linked to the
// pruned one; the pruning checkpoint names it and Verify accepts the gap.
func TestPruningTheNewestEventKeepsTheChainVerifying(t *testing.T) {
	db := memstore.New(Models()...)
	p := chainPlugin(t, db, Retention{Default: "P7Y", Names: map[string]string{SessionSignedIn: "P1D"}}, at("2026-09-11T10:00:00Z"))
	for _, e := range []Event{
		{Name: UserSignedUp, OccurredAt: at("2026-09-01T00:00:00Z"), ActorType: ActorUser, ActorID: "u1", SubjectID: "u1"},
		signedIn("u1", at("2026-09-02T00:00:00Z"), ""),
	} {
		if _, err := p.store.Write(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := p.Prune(ctx); err != nil || n != 1 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if _, err := p.store.Write(ctx, signedIn("u1", at("2026-09-11T09:00:00Z"), "")); err != nil {
		t.Fatal(err)
	}
	if r, err := p.Verify(ctx); err != nil || r.Rows != 3 || !r.Intact() {
		t.Fatalf("verify %+v %v", r, err)
	}
}
