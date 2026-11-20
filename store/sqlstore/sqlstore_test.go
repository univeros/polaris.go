package sqlstore_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
	"github.com/univeros/polaris-go/store/storetest"
)

// openSQLite opens a fresh SQLite database file, foreign keys on, as PHP's test suite does.
func openSQLite(t *testing.T) *sqlstore.Store {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "polaris.db") + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_txlock=immediate"
	return open(t, store.SQLite, dsn)
}

func open(t *testing.T, d store.Dialect, dsn string) *sqlstore.Store {
	t.Helper()
	s, err := sqlstore.Open(context.Background(), d, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DB().Close() })
	return s
}

// backends returns a constructor per available database: SQLite always, PostgreSQL and MySQL
// (a fresh schema / database each, see storetest.OpenSQL) when POLARIS_TEST_PG_DSN /
// POLARIS_TEST_MYSQL_DSN are set.
func backends() map[string]func(t *testing.T) *sqlstore.Store {
	out := map[string]func(t *testing.T) *sqlstore.Store{"sqlite": openSQLite}
	for _, b := range storetest.Backends() {
		if b.Dialect == store.Postgres || b.Dialect == store.MySQL {
			out[b.Name] = func(t *testing.T) *sqlstore.Store { return storetest.OpenSQL(t, b.Dialect) }
		}
	}
	return out
}

func TestConformance(t *testing.T) {
	for _, name := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(name, func(t *testing.T) {
			newStore, ok := backends()[name]
			if !ok {
				t.Skipf("set POLARIS_TEST_%s_DSN to run", map[string]string{"postgres": "PG", "mysql": "MYSQL"}[name])
			}
			storetest.Run(t, func(t *testing.T) store.Adapter { return newStore(t) })
		})
	}
}

func eachBackend(t *testing.T, fn func(t *testing.T, s *sqlstore.Store)) {
	for name, newStore := range backends() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			drop := func() {
				if err := s.DropSchema(ctx, schema.Core()); err != nil {
					t.Fatal(err)
				}
			}
			drop()
			t.Cleanup(drop)
			fn(t, s)
		})
	}
}

func TestSchemaCreatesDiffsCleanAndDrops(t *testing.T) {
	eachBackend(t, func(t *testing.T, s *sqlstore.Store) {
		ctx := context.Background()
		must(t, s.CreateSchema(ctx, schema.Core()))
		assertNoDiff(t, s)

		must(t, s.DropSchema(ctx, schema.Core()))
		for _, m := range schema.Core() {
			if live, err := s.Inspect(ctx, m.Table); err != nil || live != nil {
				t.Errorf("%s after drop: %v, %v", m.Table, live, err)
			}
		}
	})
}

func TestCreateMissingCreatesOnlyMissingTablesInForeignKeyOrder(t *testing.T) {
	eachBackend(t, func(t *testing.T, s *sqlstore.Store) {
		ctx := context.Background()
		must(t, s.CreateSchema(ctx, schema.Core()))
		must(t, s.Exec(ctx, "INSERT INTO auth_users (id, email, created_at, updated_at) VALUES ('u1', 'ada@example.com', '2026-10-13 10:00:00', '2026-10-13 10:00:00')"))
		must(t, s.Exec(ctx, "DROP TABLE auth_membership_roles"))
		must(t, s.Exec(ctx, "DROP TABLE auth_memberships"))

		created, err := s.CreateMissing(ctx, schema.Core())
		must(t, err)
		if !slices.Equal(created, []string{"auth_memberships", "auth_membership_roles"}) {
			t.Errorf("created %v; want only the missing tables, a referenced one first", created)
		}
		if n, _ := s.Count(ctx, "auth_users", nil); n != 1 {
			t.Errorf("auth_users has %d rows, want its row kept", n)
		}
		assertNoDiff(t, s)
		if created, err := s.CreateMissing(ctx, schema.Core()); err != nil || len(created) != 0 {
			t.Errorf("second run created %v, %v; want nothing", created, err)
		}
	})
}

func TestDiffReportsEveryDifference(t *testing.T) {
	s := openSQLite(t)
	ctx := context.Background()
	must(t, s.Exec(ctx, `CREATE TABLE "t" ("id" VARCHAR(10) NOT NULL, "n" INTEGER NULL, "b" INTEGER NOT NULL, "j" TEXT NOT NULL, "x" BLOB, "extra" TEXT NULL)`))
	must(t, s.Exec(ctx, `CREATE INDEX "t_n" ON "t" ("n")`))
	model := schema.Table("t",
		schema.StringField("id", 36).AsPrimary(),
		schema.StringField("n", 10),
		schema.BoolField("b"),
		schema.JSONField("j"),
		schema.TextField("x"),
		schema.DateTimeField("missingCol"),
	).Unique([]string{"n"}).Index([]string{"b"})
	other := schema.Table("absent", schema.StringField("id", 36).AsPrimary())

	diffs, err := s.Diff(ctx, []schema.Model{model, other})
	must(t, err)
	want := []string{
		"t.id: expected string(36), found VARCHAR(10)",
		"t.n: expected string(10), found INTEGER",
		"t.n: expected NOT NULL, found NULL",
		"t.x: expected text, found BLOB",
		"t.x: expected NOT NULL, found NULL",
		"t.missing_col: column is missing",
		"t.extra: extra column (TEXT)",
		"t: expected primary key (id), found ()",
		"t: unique index on (n) is missing",
		"t: plain index on (b) is missing",
		"absent: table is missing",
	}
	if !slices.Equal(diffs, want) {
		t.Errorf("diff:\n%q\nwant\n%q", diffs, want)
	}
}

func TestOpenRejectsUnknownDialectsAndBadConnections(t *testing.T) {
	ctx := context.Background()
	if _, err := sqlstore.Open(ctx, store.Memory, ""); err == nil {
		t.Error("memory dialect accepted")
	}
	if _, err := sqlstore.Open(ctx, store.Postgres, "postgres://invalid host:1/x"); err == nil {
		t.Error("bad postgres DSN accepted")
	}
	if _, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "missing", "x.db")+"?mode=ro"); err == nil {
		t.Error("unreachable sqlite file accepted")
	}
}

func TestErrorsPassThrough(t *testing.T) {
	s := openSQLite(t)
	ctx := context.Background()
	if s.Dialect() != store.SQLite {
		t.Errorf("dialect = %s", s.Dialect())
	}
	if _, err := s.FindMany(ctx, "nope", nil, store.Query{}); err == nil || errors.Is(err, store.ErrDuplicate) {
		t.Errorf("missing table: %v", err)
	}
	if _, err := s.Count(ctx, "nope", nil); err == nil {
		t.Error("count on a missing table succeeded")
	}
	if _, err := s.Update(ctx, "nope", nil, store.Data{"a": 1}); err == nil {
		t.Error("update on a missing table succeeded")
	}
	if err := s.Insert(ctx, "nope", store.Row{}); err == nil {
		t.Error("empty insert succeeded")
	}
	if _, err := s.Update(ctx, "nope", nil, store.Data{}); err == nil {
		t.Error("empty update succeeded")
	}
	if err := s.CreateSchema(ctx, []schema.Model{schema.Table("bad", schema.JSONField("j").WithDefault([]int{}))}); err == nil {
		t.Error("bad default accepted")
	}
	if err := s.Exec(ctx, "NOT SQL"); err == nil {
		t.Error("invalid SQL accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Tx(cancelled, func(context.Context) error { return nil }); err == nil {
		t.Error("Tx on a cancelled context began")
	}
}

func TestTxRollsBackOnPanic(t *testing.T) {
	s := openSQLite(t)
	ctx := context.Background()
	must(t, s.Exec(ctx, `CREATE TABLE "t" ("id" TEXT)`))
	run := func(nested bool) {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		_ = s.Tx(ctx, func(ctx context.Context) error {
			insert := func(ctx context.Context) error {
				_ = s.Insert(ctx, "t", store.Row{"id": "1"})
				panic("boom")
			}
			if nested {
				return s.Tx(ctx, insert)
			}
			return insert(ctx)
		})
	}
	run(false)
	run(true)
	if n, err := s.Count(ctx, "t", nil); err != nil || n != 0 {
		t.Errorf("rows after panics = %d, %v", n, err)
	}
}

func assertNoDiff(t *testing.T, s *sqlstore.Store) {
	t.Helper()
	diffs, err := s.Diff(context.Background(), schema.Core())
	must(t, err)
	if len(diffs) != 0 {
		t.Errorf("diff = %q, want none", diffs)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
