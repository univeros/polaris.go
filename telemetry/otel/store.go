package otel

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
)

// AttrRowsAffected is the number of rows an Insert, Update or Delete wrote.
const AttrRowsAffected = "polaris.db.rows_affected"

// Store returns a, tracing every call: one client span named "<operation> <table>" (find_one,
// find_many, count, insert, update, delete; "tx" for a transaction, whose calls are its children)
// with db.system.name, db.collection.name, db.operation.name and the row count
// (db.response.returned_rows for reads, polaris.db.rows_affected for writes). Criteria, rows and
// values are never recorded; a failed call records only error.type ("duplicate" or the error's Go
// type), since driver messages can quote the values that failed.
//
//	db, err := sqlstore.Open(ctx, store.Postgres, dsn)
//	p, err := polaris.New(polaris.Config{DB: polarisotel.Store(db), …})
//
// The returned adapter keeps a's CreateMissing (so Polaris.Migrate works) and exposes a through
// Unwrap.
func Store(a store.Adapter, opts ...Option) store.Adapter {
	c := newConfig(opts)
	s := &tracedStore{next: a, tracer: c.tracer(), system: dbSystem(a.Dialect())}
	if m, ok := a.(migrator); ok {
		return &migratingStore{tracedStore: s, migrator: m}
	}
	return s
}

type migrator interface {
	CreateMissing(ctx context.Context, models []schema.Model) ([]string, error)
}

// migratingStore is a tracedStore over an adapter that can create its tables.
type migratingStore struct {
	*tracedStore
	migrator
}

type tracedStore struct {
	next   store.Adapter
	tracer trace.Tracer
	system attribute.KeyValue
}

// Unwrap returns the adapter Store wrapped.
func (s *tracedStore) Unwrap() store.Adapter { return s.next }

// Dialect implements store.Adapter.
func (s *tracedStore) Dialect() store.Dialect { return s.next.Dialect() }

func (s *tracedStore) start(ctx context.Context, op, table string) (context.Context, trace.Span) {
	name := op
	attrs := []attribute.KeyValue{s.system, semconv.DBOperationName(op)}
	if table != "" {
		name += " " + table
		attrs = append(attrs, semconv.DBCollectionName(table))
	}
	return s.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
}

// end records err (its type only) and ends span.
func end(span trace.Span, err error) {
	if err != nil {
		span.SetAttributes(semconv.ErrorTypeKey.String(errorType(err)))
		span.SetStatus(codes.Error, "")
	}
	span.End()
}

func errorType(err error) string {
	if errors.Is(err, store.ErrDuplicate) {
		return "duplicate"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	return semconv.ErrorTypeOther.Value.AsString()
}

// FindOne implements store.Adapter.
func (s *tracedStore) FindOne(ctx context.Context, table string, c store.Criteria) (store.Row, error) {
	ctx, span := s.start(ctx, "find_one", table)
	row, err := s.next.FindOne(ctx, table, c)
	if err == nil {
		n := 0
		if row != nil {
			n = 1
		}
		span.SetAttributes(semconv.DBResponseReturnedRows(n))
	}
	end(span, err)
	return row, err
}

// FindMany implements store.Adapter.
func (s *tracedStore) FindMany(ctx context.Context, table string, c store.Criteria, q store.Query) ([]store.Row, error) {
	ctx, span := s.start(ctx, "find_many", table)
	rows, err := s.next.FindMany(ctx, table, c, q)
	if err == nil {
		span.SetAttributes(semconv.DBResponseReturnedRows(len(rows)))
	}
	end(span, err)
	return rows, err
}

// Count implements store.Adapter.
func (s *tracedStore) Count(ctx context.Context, table string, c store.Criteria) (int64, error) {
	ctx, span := s.start(ctx, "count", table)
	n, err := s.next.Count(ctx, table, c)
	end(span, err)
	return n, err
}

// Insert implements store.Adapter.
func (s *tracedStore) Insert(ctx context.Context, table string, row store.Row) error {
	ctx, span := s.start(ctx, "insert", table)
	err := s.next.Insert(ctx, table, row)
	if err == nil {
		span.SetAttributes(attribute.Int(AttrRowsAffected, 1))
	}
	end(span, err)
	return err
}

// Update implements store.Adapter.
func (s *tracedStore) Update(ctx context.Context, table string, c store.Criteria, d store.Data) (int64, error) {
	ctx, span := s.start(ctx, "update", table)
	n, err := s.next.Update(ctx, table, c, d)
	if err == nil {
		span.SetAttributes(attribute.Int64(AttrRowsAffected, n))
	}
	end(span, err)
	return n, err
}

// Delete implements store.Adapter.
func (s *tracedStore) Delete(ctx context.Context, table string, c store.Criteria) (int64, error) {
	ctx, span := s.start(ctx, "delete", table)
	n, err := s.next.Delete(ctx, table, c)
	if err == nil {
		span.SetAttributes(attribute.Int64(AttrRowsAffected, n))
	}
	end(span, err)
	return n, err
}

// Tx implements store.Adapter: the transaction is a span, the calls fn makes are its children.
func (s *tracedStore) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	ctx, span := s.start(ctx, "tx", "")
	err := s.next.Tx(ctx, fn)
	end(span, err)
	return err
}

func dbSystem(d store.Dialect) attribute.KeyValue {
	switch d {
	case store.Postgres:
		return semconv.DBSystemNamePostgreSQL
	case store.MySQL:
		return semconv.DBSystemNameMySQL
	case store.SQLite:
		return semconv.DBSystemNameSQLite
	}
	return semconv.DBSystemNameKey.String(string(d))
}
