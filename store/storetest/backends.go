package storetest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
)

// Environment variables naming the servers the database matrix runs against. Each DSN must reach a
// user allowed to create and drop schemas (PostgreSQL) or databases (MySQL); every store opened on
// it gets its own, dropped when the test ends. scripts/test-db-matrix.sh sets them.
const (
	EnvPostgresDSN = "POLARIS_TEST_PG_DSN"    // e.g. postgres://polaris:polaris@localhost:55432/polaris?sslmode=disable
	EnvMySQLDSN    = "POLARIS_TEST_MYSQL_DSN" // e.g. root:polaris@tcp(localhost:53306)/polaris
)

// dsnEnv maps each server dialect to the variable holding its DSN.
var dsnEnv = map[store.Dialect]string{store.Postgres: EnvPostgresDSN, store.MySQL: EnvMySQLDSN}

// Backend opens fresh, isolated stores of one kind.
type Backend struct {
	Name    string // "memory", "sqlite", "postgres" or "mysql"
	Dialect store.Dialect
}

// Open returns a store no other test sees, holding models (core's schema when none are given).
// SQL stores are closed and, on PostgreSQL and MySQL, dropped when t ends.
func (b Backend) Open(t testing.TB, models ...schema.Model) store.Adapter {
	t.Helper()
	if len(models) == 0 {
		models = schema.Core()
	}
	if b.Dialect == store.Memory {
		return memstore.New(models...)
	}
	s := OpenSQL(t, b.Dialect)
	if err := s.CreateSchema(context.Background(), models); err != nil {
		t.Fatalf("storetest: create schema on %s: %v", b.Name, err)
	}
	return s
}

// Backends returns memstore and SQLite, plus PostgreSQL and MySQL when POLARIS_TEST_PG_DSN /
// POLARIS_TEST_MYSQL_DSN are set.
func Backends() []Backend {
	out := []Backend{{"memory", store.Memory}, {"sqlite", store.SQLite}}
	for _, d := range []store.Dialect{store.Postgres, store.MySQL} {
		if os.Getenv(dsnEnv[d]) != "" {
			out = append(out, Backend{string(d), d})
		}
	}
	return out
}

// Each runs fn as one subtest per backend (see Backends), each on a fresh store holding models
// (core's schema when none are given).
func Each(t *testing.T, fn func(t *testing.T, db store.Adapter), models ...schema.Model) {
	t.Helper()
	for _, b := range Backends() {
		t.Run(b.Name, func(t *testing.T) { fn(t, b.Open(t, models...)) })
	}
}

// OpenSQL opens an empty database of dialect d that no other test sees: a temp-file SQLite database
// (foreign keys on, 10 s busy timeout), or a new PostgreSQL schema / MySQL database on the server
// named by POLARIS_TEST_PG_DSN / POLARIS_TEST_MYSQL_DSN, dropped when t ends. Without that
// variable the test fails, naming it.
func OpenSQL(t testing.TB, d store.Dialect) *sqlstore.Store {
	t.Helper()
	ctx := context.Background()
	if d == store.SQLite {
		dsn := "file:" + filepath.Join(t.TempDir(), "polaris.db") + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)"
		s, err := sqlstore.Open(ctx, d, dsn)
		if err != nil {
			t.Fatalf("storetest: %v", err)
		}
		t.Cleanup(func() { _ = s.DB().Close() })
		return s
	}
	env, ok := dsnEnv[d]
	if !ok {
		t.Fatalf("storetest: no SQL database for dialect %q", d)
	}
	dsn := os.Getenv(env)
	if dsn == "" {
		t.Fatalf("storetest: set %s to run on %s (scripts/test-db-matrix.sh starts one)", env, d)
	}
	name := "polaris_t_" + strings.ToLower(rand.Text())
	s, drop, err := isolate(ctx, d, dsn, name)
	if err != nil {
		t.Fatalf("storetest: %s: %v", d, err)
	}
	t.Cleanup(func() {
		_ = s.DB().Close()
		if err := drop(); err != nil {
			t.Errorf("storetest: drop %s: %v", name, err)
		}
	})
	return s
}

// isolate creates the schema (PostgreSQL) or database (MySQL) name on the server behind dsn and
// returns a store bound to it and the function that drops it.
func isolate(ctx context.Context, d store.Dialect, dsn, name string) (*sqlstore.Store, func() error, error) {
	driver := map[store.Dialect]string{store.Postgres: "pgx", store.MySQL: "mysql"}[d]
	admin, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, nil, err
	}
	create, dropStmt := "CREATE SCHEMA "+name, "DROP SCHEMA IF EXISTS "+name+" CASCADE"
	if d == store.MySQL {
		// The server's default character set and collation, as a deployment's database gets.
		create, dropStmt = "CREATE DATABASE "+name, "DROP DATABASE IF EXISTS "+name
	}
	if _, err := admin.ExecContext(ctx, create); err != nil {
		_ = admin.Close()
		return nil, nil, err
	}
	drop := func() error {
		defer admin.Close()
		_, err := admin.ExecContext(context.Background(), dropStmt)
		return err
	}
	s, err := bind(ctx, d, dsn, name)
	if err != nil {
		return nil, nil, errors.Join(err, drop())
	}
	return s, drop, nil
}

// bind opens a store whose connections use name: the database on MySQL (through sqlstore.Open, as
// a host does), search_path on PostgreSQL.
func bind(ctx context.Context, d store.Dialect, dsn, name string) (*sqlstore.Store, error) {
	if d == store.MySQL {
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			return nil, err
		}
		cfg.DBName = name
		return sqlstore.Open(ctx, d, cfg.FormatDSN())
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["search_path"] = name
	db := stdlib.OpenDB(*cfg)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return sqlstore.New(db, d), nil
}

// JSONNormalized reports whether d stores JSON columns parsed (PostgreSQL jsonb, MySQL JSON), so a
// read returns an equal value in the database's own form (key order, spacing, escapes) rather than
// the bytes written, as SQLite and memstore do.
func JSONNormalized(d store.Dialect) bool { return d == store.Postgres || d == store.MySQL }
