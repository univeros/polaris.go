// Package store is the persistence port: a row-level adapter over any database, the Go form of
// PHP Polaris\Contract\DatabaseAdapter. Every service and plugin talks to the database through it.
//
// Criteria map a column to:
//   - a scalar (string, int, int64, bool, time.Time): column = value
//   - nil: column IS NULL
//   - a slice ([]any, []string, []int64): column IN (...); an empty slice matches nothing
//   - a Cond (Lt, Lte, Gt, Gte, Ne, NotNull)
//
// Update data maps a column to a value or an Increment.
//
// Values written: nil, string, int/int64, bool, time.Time (stored as "2006-01-02 15:04:05" UTC),
// []byte. Values read come back in the driver's native type; use the Row accessors to read them.
package store

import (
	"context"
	"errors"
)

// Dialect names the SQL flavour behind an adapter.
type Dialect string

const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
	SQLite   Dialect = "sqlite"
	Memory   Dialect = "memory"
)

// TimeLayout is how a time.Time is written to and parsed from the database (UTC, PHP 'Y-m-d H:i:s').
const TimeLayout = "2006-01-02 15:04:05"

// Row is one table row keyed by column name.
type Row map[string]any

// Criteria select rows; see the package comment for the accepted values.
type Criteria map[string]any

// Data is the set of columns an Update writes.
type Data map[string]any

// Order is one ORDER BY term.
type Order struct {
	Column string
	Desc   bool
}

// Query narrows FindMany.
type Query struct {
	OrderBy []Order
	Limit   int // 0 = no limit
	Offset  int
}

// Adapter is the database port. Implementations: store/sqlstore (PostgreSQL, MySQL, SQLite) and
// store/memstore (in memory). Every call joins the transaction carried by ctx, if any.
type Adapter interface {
	FindOne(ctx context.Context, table string, c Criteria) (Row, error) // nil, nil when absent
	FindMany(ctx context.Context, table string, c Criteria, q Query) ([]Row, error)
	Insert(ctx context.Context, table string, row Row) error
	Update(ctx context.Context, table string, c Criteria, d Data) (int64, error)
	Delete(ctx context.Context, table string, c Criteria) (int64, error)
	Count(ctx context.Context, table string, c Criteria) (int64, error)
	// Tx runs fn in a transaction; fn must use the ctx it receives. Nested calls use savepoints.
	// fn's error rolls back and is returned unchanged.
	Tx(ctx context.Context, fn func(ctx context.Context) error) error
	Dialect() Dialect
}

// ErrDuplicate is wrapped by Insert/Update when a unique constraint rejects the write.
var ErrDuplicate = errors.New("store: duplicate key")

// Op is a comparison operator of a Cond.
type Op string

const (
	OpLt      Op = "<"
	OpLte     Op = "<="
	OpGt      Op = ">"
	OpGte     Op = ">="
	OpNe      Op = "!="
	OpNotNull Op = "not null"
)

// Cond is a non-equality criterion.
type Cond struct {
	Op    Op
	Value any
}

func Lt(v any) Cond  { return Cond{OpLt, v} }
func Lte(v any) Cond { return Cond{OpLte, v} }
func Gt(v any) Cond  { return Cond{OpGt, v} }
func Gte(v any) Cond { return Cond{OpGte, v} }
func Ne(v any) Cond  { return Cond{OpNe, v} }
func NotNull() Cond  { return Cond{OpNotNull, nil} }

// Increment adds By to a numeric column in an Update.
type Increment struct{ By int64 }
