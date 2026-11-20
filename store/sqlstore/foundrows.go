package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"github.com/univeros/polaris-go/store"
)

// ErrMySQLFoundRows is returned by the writes of a MySQL Store whose pool does not set
// clientFoundRows=true: MySQL would then count changed rows, not matched ones, and Polaris's
// conditional updates would read a no-op (a lock, a timestamp in the same second) as a lost race.
var ErrMySQLFoundRows = errors.New("sqlstore: the MySQL pool given to sqlstore.New counts changed rows, not matched ones; add clientFoundRows=true to its DSN (mysql.Config.ClientFoundRows) or open it with sqlstore.Open")

// foundRows remembers whether a MySQL pool reports matched rows; it is probed once, on the first
// top-level write (never inside a transaction, which may hold the pool's only connection).
type foundRows struct {
	mu      sync.Mutex
	checked bool
}

func (s *Store) checkFoundRows(ctx context.Context) error {
	if s.dialect != store.MySQL {
		return nil
	}
	s.found.mu.Lock()
	defer s.found.mu.Unlock()
	if s.found.checked {
		return nil
	}
	ok, err := probeFoundRows(ctx, s.db)
	if err != nil {
		// ponytail: a probe that cannot run (no CREATE TEMPORARY TABLES grant, connection down) is
		// not a verdict; it runs again on the next write.
		return nil
	}
	if !ok {
		return ErrMySQLFoundRows
	}
	s.found.checked = true
	return nil
}

// probeFoundRows rewrites a row of a temporary table with its own value on one connection: a
// pool that reports matched rows answers 1, one that reports changed rows 0.
func probeFoundRows(ctx context.Context, db *sql.DB) (bool, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	const table = "polaris_found_rows_probe"
	if _, err := conn.ExecContext(ctx, "CREATE TEMPORARY TABLE "+table+" (x INT)"); err != nil {
		return false, err
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "DROP TEMPORARY TABLE IF EXISTS "+table) }()
	if _, err := conn.ExecContext(ctx, "INSERT INTO "+table+" (x) VALUES (1)"); err != nil {
		return false, err
	}
	res, err := conn.ExecContext(ctx, "UPDATE "+table+" SET x = 1")
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
