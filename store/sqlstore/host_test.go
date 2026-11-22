package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/store/sqlstore"
)

// Conn is the transaction ctx carries (a Store.Tx, nested ones included, or WithTx's), else the
// pool: a host's plain database/sql write through it commits or rolls back with Polaris's.
func TestConnJoinsTheTransactionCarriedByCtx(t *testing.T) {
	eachBackend(t, func(t *testing.T, s *sqlstore.Store) {
		ctx := context.Background()
		must(t, s.Exec(ctx, "CREATE TABLE host_notes (id VARCHAR(36) PRIMARY KEY)"))
		insert := func(ctx context.Context, id string) error {
			_, err := s.Conn(ctx).ExecContext(ctx, "INSERT INTO host_notes (id) VALUES ("+ph(s)+")", id)
			return err
		}
		count := func() int {
			var n int
			must(t, s.Conn(ctx).QueryRowContext(ctx, "SELECT COUNT(*) FROM host_notes").Scan(&n))
			return n
		}
		undo := errors.New("undo")
		err := s.Tx(ctx, func(ctx context.Context) error {
			must(t, insert(ctx, "a"))
			must(t, s.Tx(ctx, func(ctx context.Context) error { return insert(ctx, "b") })) // a savepoint
			return undo
		})
		if !errors.Is(err, undo) || count() != 0 {
			t.Fatalf("rolled back: %v, %d rows", err, count())
		}
		must(t, s.Tx(ctx, func(ctx context.Context) error { return insert(ctx, "a") }))
		if count() != 1 {
			t.Fatalf("committed: %d rows", count())
		}

		tx, err := s.DB().BeginTx(ctx, nil)
		must(t, err)
		must(t, insert(sqlstore.WithTx(ctx, tx), "b"))
		must(t, tx.Rollback())
		if count() != 1 {
			t.Fatalf("host rollback: %d rows", count())
		}
		if _, ok := s.Conn(ctx).(*sql.DB); !ok {
			t.Fatal("outside a transaction Conn is the pool")
		}
	})
}

// AfterCommit runs once the outermost Store.Tx commits, in order; a rollback (of the
// transaction, or of the savepoint that queued it) drops it; outside a Store.Tx, under WithTx
// included, it reports false and runs nothing.
func TestAfterCommitWaitsForTheOutermostCommit(t *testing.T) {
	ctx := context.Background()
	s := openSQLite(t)
	var ran []string
	queue := func(ctx context.Context, name string) {
		t.Helper()
		if !s.AfterCommit(ctx, func() { ran = append(ran, name) }) {
			t.Fatalf("%s: AfterCommit refused inside a transaction", name)
		}
	}
	undo := errors.New("undo")

	must(t, s.Tx(ctx, func(ctx context.Context) error {
		queue(ctx, "outer")
		must(t, s.Tx(ctx, func(ctx context.Context) error { queue(ctx, "nested"); return nil }))
		_ = s.Tx(ctx, func(ctx context.Context) error { queue(ctx, "undone savepoint"); return undo })
		if len(ran) != 0 {
			t.Fatal("ran before the commit")
		}
		return nil
	}))
	if !slices.Equal(ran, []string{"outer", "nested"}) {
		t.Fatalf("after the commit: %v", ran)
	}

	ran = nil
	_ = s.Tx(ctx, func(ctx context.Context) error { queue(ctx, "rolled back"); return undo })
	if len(ran) != 0 {
		t.Fatalf("after a rollback: %v", ran)
	}

	// The ctx a queued function captured no longer carries the finished transaction.
	var after sql.Result
	must(t, s.Exec(ctx, "CREATE TABLE host_notes (id VARCHAR(36) PRIMARY KEY)"))
	must(t, s.Tx(ctx, func(ctx context.Context) error {
		s.AfterCommit(ctx, func() {
			var err error
			after, err = s.Conn(ctx).ExecContext(ctx, "INSERT INTO host_notes (id) VALUES (?)", "x")
			must(t, err)
		})
		return nil
	}))
	if after == nil {
		t.Fatal("the queued write did not run")
	}

	if s.AfterCommit(ctx, func() { t.Fatal("ran without a transaction") }) {
		t.Fatal("AfterCommit outside a transaction")
	}
	tx, err := s.DB().BeginTx(ctx, nil)
	must(t, err)
	defer func() { _ = tx.Rollback() }()
	if s.AfterCommit(sqlstore.WithTx(ctx, tx), func() { t.Fatal("ran under WithTx") }) {
		t.Fatal("AfterCommit under WithTx: the host commits that transaction, Polaris never sees it")
	}
}

func TestCloseClosesThePool(t *testing.T) {
	s := openSQLite(t)
	must(t, s.Close())
	if err := s.DB().PingContext(context.Background()); err == nil {
		t.Fatal("the pool is still open")
	}
}

func ph(s *sqlstore.Store) string {
	if s.Dialect() == "postgres" {
		return "$1"
	}
	return "?"
}
