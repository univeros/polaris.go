// Package sqlstore is the store.Adapter over database/sql for PostgreSQL (pgx), MySQL and SQLite
// (modernc, no cgo), the Go form of PHP polaris/pdo: prepared statements only, nested transactions
// as savepoints, unique-constraint violations as store.ErrDuplicate. It also exports core's schema
// as DDL and installs, inspects and diffs it on a live database.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" driver
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/univeros/polaris-go/store"
)

// Store is a store.Adapter over a *sql.DB. It is safe for concurrent use.
type Store struct {
	db      *sql.DB
	dialect store.Dialect
	found   foundRows // MySQL: whether the pool reports matched rows (see ErrMySQLFoundRows)
}

var _ store.Adapter = (*Store)(nil)

// New returns a Store over db, which speaks dialect d (store.Postgres, store.MySQL or store.SQLite).
// For SQLite, enable foreign keys and a busy timeout on every pooled connection through the DSN,
// e.g. "file:polaris.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)". For MySQL, the DSN
// must set clientFoundRows=true (Open does): Update reports matched rows on every dialect, and
// Polaris's conditional updates read 0 as "another request won". A MySQL pool without it is
// detected on the first write, which fails with ErrMySQLFoundRows.
func New(db *sql.DB, d store.Dialect) *Store {
	return &Store{db: db, dialect: d}
}

// Open opens a database of dialect d with the bundled driver ("pgx", "mysql" or "sqlite") and
// checks the connection.
func Open(ctx context.Context, d store.Dialect, dsn string) (*Store, error) {
	driver, ok := map[store.Dialect]string{store.Postgres: "pgx", store.MySQL: "mysql", store.SQLite: "sqlite"}[d]
	if !ok {
		return nil, fmt.Errorf("sqlstore: unsupported dialect %q; use store.Postgres, store.MySQL or store.SQLite", d)
	}
	if d == store.MySQL {
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			return nil, fmt.Errorf("sqlstore: open %s: %w", d, err)
		}
		cfg.ClientFoundRows = true // Update counts matched rows, as on PostgreSQL and SQLite
		dsn = cfg.FormatDSN()
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: open %s: %w", d, err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlstore: connect to %s: %w", d, err)
	}
	s := New(db, d)
	s.found.checked = true // Open set clientFoundRows on MySQL itself
	return s, nil
}

// DB returns the underlying pool.
func (s *Store) DB() *sql.DB { return s.db }

// Dialect returns the dialect given to New.
func (s *Store) Dialect() store.Dialect { return s.dialect }

// FindOne returns the first matching row, or nil, nil.
func (s *Store) FindOne(ctx context.Context, table string, c store.Criteria) (store.Row, error) {
	rows, err := s.FindMany(ctx, table, c, store.Query{Limit: 1})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// FindMany returns the matching rows with the driver's native values.
func (s *Store) FindMany(ctx context.Context, table string, c store.Criteria, q store.Query) ([]store.Row, error) {
	return s.query(ctx, selectQuery(s.dialect, table, c, q))
}

// Count returns the number of matching rows.
func (s *Store) Count(ctx context.Context, table string, c store.Criteria) (int64, error) {
	q := countQuery(s.dialect, table, c)
	var n int64
	if err := s.conn(ctx).QueryRowContext(ctx, q.sql.String(), q.args...).Scan(&n); err != nil {
		return 0, wrap(err)
	}
	return n, nil
}

// Insert writes one row.
func (s *Store) Insert(ctx context.Context, table string, row store.Row) error {
	q, err := insertQuery(s.dialect, table, row)
	if err != nil {
		return err
	}
	_, err = s.exec(ctx, q)
	return err
}

// Update writes d to the matching rows and returns how many matched, even those it left unchanged
// (on MySQL this needs clientFoundRows=true; see New).
func (s *Store) Update(ctx context.Context, table string, c store.Criteria, d store.Data) (int64, error) {
	q, err := updateQuery(s.dialect, table, c, d)
	if err != nil {
		return 0, err
	}
	if _, inTx := s.txOf(ctx); !inTx {
		if err := s.checkFoundRows(ctx); err != nil {
			return 0, err
		}
	}
	return s.exec(ctx, q)
}

// Delete removes the matching rows and returns how many it removed.
func (s *Store) Delete(ctx context.Context, table string, c store.Criteria) (int64, error) {
	return s.exec(ctx, deleteQuery(s.dialect, table, c))
}

// Exec runs a raw statement (DDL, maintenance) in the transaction carried by ctx, if any.
func (s *Store) Exec(ctx context.Context, statement string, args ...any) error {
	_, err := s.conn(ctx).ExecContext(ctx, statement, args...)
	return wrap(err)
}

// Tx runs fn in a transaction carried by the ctx fn receives: BEGIN at the top level, SAVEPOINT
// polaris_sp_N when nested. fn's error (or panic) rolls back to where this Tx began and is
// returned unchanged; a nil error commits or releases the savepoint.
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if t, ok := s.txOf(ctx); ok {
		return s.savepoint(ctx, t, fn)
	}
	if err := s.checkFoundRows(ctx); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("sqlstore: begin: %w", err)
	}
	inner := context.WithValue(ctx, txKey{s}, &txState{tx: tx, depth: 1})
	return finishGuarded(func() error { return fn(inner) }, tx.Rollback, tx.Commit)
}

func (s *Store) savepoint(ctx context.Context, t *txState, fn func(ctx context.Context) error) error {
	name := fmt.Sprintf("polaris_sp_%d", t.depth)
	if _, err := t.tx.ExecContext(ctx, "SAVEPOINT "+name); err != nil {
		return fmt.Errorf("sqlstore: savepoint: %w", err)
	}
	stmt := func(verb string) func() error {
		return func() error {
			_, err := t.tx.ExecContext(context.WithoutCancel(ctx), verb+name)
			return err
		}
	}
	inner := context.WithValue(ctx, txKey{s}, &txState{tx: t.tx, depth: t.depth + 1})
	return finishGuarded(func() error { return fn(inner) }, stmt("ROLLBACK TO SAVEPOINT "), stmt("RELEASE SAVEPOINT "))
}

// finish rolls back on fnErr (returning it, joined with a rollback failure if any) or commits.
func finish(fnErr error, rollback, commit func() error) error {
	if fnErr != nil {
		if err := rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return errors.Join(fnErr, fmt.Errorf("sqlstore: rollback: %w", err))
		}
		return fnErr
	}
	if err := commit(); err != nil {
		return fmt.Errorf("sqlstore: commit: %w", err)
	}
	return nil
}

// finishGuarded is finish around fn, rolling back before re-raising a panic.
func finishGuarded(fn func() error, rollback, commit func() error) error {
	panicking := true
	defer func() {
		if panicking {
			_ = rollback()
		}
	}()
	err := fn()
	panicking = false
	return finish(err, rollback, commit)
}

// txKey marks a ctx as running inside a transaction of one Store.
type txKey struct{ s *Store }

// hostTxKey marks a ctx carrying a host's transaction (WithTx).
type hostTxKey struct{}

// WithTx returns a ctx under which every Polaris read and write joins tx, the host's own
// transaction: a programmatic call (p.Users().Create(ctx, …)), with its OnUserCreated hook, commits
// or rolls back with the host's other writes. The host alone commits or rolls back tx; Polaris's
// own transactions inside it become savepoints, so a Polaris failure undoes only its own writes
// and returns the error.
//
// tx must come from the same database the Store uses (sqlstore.Store.DB().BeginTx). Events are
// dispatched when Polaris's work is done, before the host commits: a listener with side effects
// outside the database (mail) runs even if the host then rolls back. On PostgreSQL, a failed
// statement aborts the whole transaction; only the savepoint around each Polaris transaction
// recovers from it.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	return context.WithValue(ctx, hostTxKey{}, &txState{tx: tx, depth: 1})
}

// txOf is the transaction ctx runs in: one of this Store's, else the host's (WithTx).
func (s *Store) txOf(ctx context.Context) (*txState, bool) {
	if t, ok := ctx.Value(txKey{s}).(*txState); ok {
		return t, true
	}
	t, ok := ctx.Value(hostTxKey{}).(*txState)
	return t, ok && t.tx != nil
}

type txState struct {
	tx    *sql.Tx
	depth int
}

// conner is what *sql.DB and *sql.Tx share.
type conner interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) conn(ctx context.Context) conner {
	if t, ok := s.txOf(ctx); ok {
		return t.tx
	}
	return s.db
}

func (s *Store) exec(ctx context.Context, q *query) (int64, error) {
	res, err := s.conn(ctx).ExecContext(ctx, q.sql.String(), q.args...)
	if err != nil {
		return 0, wrap(err)
	}
	n, err := res.RowsAffected()
	return n, wrap(err)
}

func (s *Store) query(ctx context.Context, q *query) ([]store.Row, error) {
	rows, err := s.conn(ctx).QueryContext(ctx, q.sql.String(), q.args...)
	if err != nil {
		return nil, wrap(err)
	}
	return scanRows(rows)
}

func scanRows(rows *sql.Rows) ([]store.Row, error) {
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, wrap(err)
	}
	var out []store.Row
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, wrap(err)
		}
		row := make(store.Row, len(cols))
		for i, col := range cols {
			row[col] = values[i]
		}
		out = append(out, row)
	}
	return out, wrap(rows.Err())
}

// wrap marks unique-constraint violations of every bundled driver with store.ErrDuplicate,
// keeping the driver error in the chain.
func wrap(err error) error {
	if err == nil || !isDuplicate(err) {
		return err
	}
	return fmt.Errorf("%w: %w", store.ErrDuplicate, err)
}

func isDuplicate(err error) bool {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505" // unique_violation
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1062 // ER_DUP_ENTRY
	}
	var lite *sqlite.Error
	if errors.As(err, &lite) {
		return lite.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || lite.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
	}
	return false
}
