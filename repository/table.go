// Package repository reads and writes core's records (package model) through a store.Adapter, one
// typed repository per table with explicit row mapping. There is no unit of work and no identity
// map: a read returns a value, a write is one statement, and a caller that needs atomicity runs
// its calls in store.Adapter.Tx with the ctx it receives. Repos bundles every core repository.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/univeros/polaris-go/store"
)

// ErrNotFound is returned by single-row lookups when no row matches.
var ErrNotFound = errors.New("repository: not found")

// NewID returns a new UUIDv7 string, the id format of every core table.
func NewID() string { return uuid.Must(uuid.NewV7()).String() }

// Table is the typed access to one table that every repository embeds: rows are mapped to and
// from T explicitly, criteria are by column.
type Table[T any] struct {
	db      store.Adapter
	name    string
	key     []string // primary-key columns
	toRow   func(T) store.Row
	fromRow func(*reader) T
}

// Insert writes m as a new row; a primary-key or unique-index clash wraps store.ErrDuplicate.
func (t Table[T]) Insert(ctx context.Context, m T) error {
	if err := t.db.Insert(ctx, t.name, t.toRow(m)); err != nil {
		return fmt.Errorf("repository: insert %s: %w", t.name, err)
	}
	return nil
}

// Update writes the columns whose value differs between before (as read) and after (as it
// should be), keyed by before's primary key, as PHP's unit of work does; nothing changed means
// no statement. A clash on a unique index wraps store.ErrDuplicate.
func (t Table[T]) Update(ctx context.Context, before, after T) error {
	old, next := t.toRow(before), t.toRow(after)
	changes := store.Data{}
	for col, v := range next {
		if !same(old[col], v) {
			changes[col] = v
		}
	}
	if len(changes) == 0 {
		return nil
	}
	if _, err := t.db.Update(ctx, t.name, t.keyOf(old), changes); err != nil {
		return fmt.Errorf("repository: update %s: %w", t.name, err)
	}
	return nil
}

// Delete removes m's row by primary key; deleting a missing row is not an error. The database's
// ON DELETE CASCADE removes dependent rows.
func (t Table[T]) Delete(ctx context.Context, m T) error {
	_, err := t.deleteWhere(ctx, t.keyOf(t.toRow(m)))
	return err
}

// Get finds a row by its single-column primary key.
func (t Table[T]) Get(ctx context.Context, id string) (T, error) {
	if len(t.key) != 1 {
		var zero T
		return zero, fmt.Errorf("repository: %s has a composite key", t.name)
	}
	return t.FindOne(ctx, store.Criteria{t.key[0]: id})
}

// FindOne returns the first row matching c, or ErrNotFound.
func (t Table[T]) FindOne(ctx context.Context, c store.Criteria) (T, error) {
	var zero T
	row, err := t.db.FindOne(ctx, t.name, c)
	if err != nil {
		return zero, fmt.Errorf("repository: find %s: %w", t.name, err)
	}
	if row == nil {
		return zero, ErrNotFound
	}
	return t.read(row)
}

// Find returns every row matching c (nil criteria: all rows), ordered and paged by q.
func (t Table[T]) Find(ctx context.Context, c store.Criteria, q store.Query) ([]T, error) {
	rows, err := t.db.FindMany(ctx, t.name, c, q)
	if err != nil {
		return nil, fmt.Errorf("repository: find %s: %w", t.name, err)
	}
	out := make([]T, 0, len(rows))
	for _, row := range rows {
		m, err := t.read(row)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

// Count returns the number of rows matching c.
func (t Table[T]) Count(ctx context.Context, c store.Criteria) (int64, error) {
	n, err := t.db.Count(ctx, t.name, c)
	if err != nil {
		return 0, fmt.Errorf("repository: count %s: %w", t.name, err)
	}
	return n, nil
}

func (t Table[T]) list(ctx context.Context, c store.Criteria) ([]T, error) {
	return t.Find(ctx, c, store.Query{})
}

func (t Table[T]) deleteWhere(ctx context.Context, c store.Criteria) (int64, error) {
	n, err := t.db.Delete(ctx, t.name, c)
	if err != nil {
		return 0, fmt.Errorf("repository: delete %s: %w", t.name, err)
	}
	return n, nil
}

// claim runs a conditional UPDATE and reports whether exactly one row took it: the
// compare-and-swap the services use so that only one concurrent request wins.
func (t Table[T]) claim(ctx context.Context, c store.Criteria, d store.Data) (bool, error) {
	n, err := t.db.Update(ctx, t.name, c, d)
	if err != nil {
		return false, fmt.Errorf("repository: update %s: %w", t.name, err)
	}
	return n == 1, nil
}

func (t Table[T]) keyOf(row store.Row) store.Criteria {
	c := make(store.Criteria, len(t.key))
	for _, col := range t.key {
		c[col] = row[col]
	}
	return c
}

func (t Table[T]) read(row store.Row) (T, error) {
	r := &reader{row: row}
	m := t.fromRow(r)
	if r.err != nil {
		var zero T
		return zero, fmt.Errorf("repository: read %s: %w", t.name, r.err)
	}
	return m, nil
}

// same compares two mapped column values; times by instant.
func same(a, b any) bool {
	if x, ok := a.(time.Time); ok {
		y, ok := b.(time.Time)
		return ok && x.Equal(y)
	}
	return a == b
}

// reader maps one row's columns to Go values, keeping the first error.
type reader struct {
	row store.Row
	err error
}

func (r *reader) str(col string) string     { return r.row.String(col) }
func (r *reader) strPtr(col string) *string { return r.row.StringPtr(col) }
func (r *reader) integer(col string) int    { return int(r.row.Int(col)) }
func (r *reader) boolean(col string) bool   { return r.row.Bool(col) }

func (r *reader) int64Ptr(col string) *int64 {
	if r.row[col] == nil {
		return nil
	}
	v := r.row.Int(col)
	return &v
}

func (r *reader) time(col string) time.Time {
	t, ok := r.row.Time(col)
	if !ok && r.err == nil {
		r.err = fmt.Errorf("column %s: not a datetime: %v", col, r.row[col])
	}
	return t
}

func (r *reader) timePtr(col string) *time.Time {
	if r.row[col] == nil {
		return nil
	}
	t := r.time(col)
	return &t
}

func (r *reader) json(col string, dst any) {
	if err := r.row.JSON(col, dst); err != nil && r.err == nil {
		r.err = fmt.Errorf("column %s: %w", col, err)
	}
}

// ts is how a datetime is written: UTC, to the second, as PHP stores it.
func ts(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }

func tsPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}
