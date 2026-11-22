package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// Migrate brings the database up to models without losing data. It creates the missing tables
// (with their indexes) and, on an existing table, adds the columns and indexes models declare that
// the table lacks and drops the indexes a model lists in DroppedIndexes. It never drops a table or
// a column and never changes a column's type, nullability or default: Diff reports those, and they
// are changed by hand.
//
// It refuses, before changing anything, a column added to an existing table that is NOT NULL
// without a default or part of the primary key, and an index both declared and dropped.
//
// Every step checks the live table first and, when its statement fails, checks again: a step
// another process applied in the meantime counts as done, so replicas booting together can all
// run it. It returns what it changed: each table it created by name, then one "<table>: added
// column <c>", "<table>: created index <i>" or "<table>: dropped index <i>" per change to an
// existing table.
func (s *Store) Migrate(ctx context.Context, models []schema.Model) ([]string, error) {
	plan, err := s.plan(ctx, models)
	if err != nil {
		return nil, err
	}
	var changes []string
	for _, st := range plan {
		applied, err := s.apply(ctx, st)
		if err != nil {
			return changes, err
		}
		if applied && st.change != "" {
			changes = append(changes, st.change)
		}
	}
	return changes, nil
}

// step is one DDL statement of a migration.
type step struct {
	table, statement string
	change           string                // what Migrate reports; "" for a new table's indexes
	done             func(*LiveTable) bool // whether the live table already has the change
	hint             string                // appended to the error when the statement fails
}

// plan inspects every table of models and returns the statements that bring them up to date, or
// the first change it refuses.
func (s *Store) plan(ctx context.Context, models []schema.Model) ([]step, error) {
	ordered, err := Ordered(models)
	if err != nil {
		return nil, err
	}
	var plan []step
	for _, m := range ordered {
		if err := checkDropped(m); err != nil {
			return nil, err
		}
		live, err := s.Inspect(ctx, m.Table)
		if err != nil {
			return nil, err
		}
		steps, err := s.tableSteps(m, live)
		if err != nil {
			return nil, err
		}
		plan = append(plan, steps...)
	}
	return plan, nil
}

func (s *Store) tableSteps(m schema.Model, live *LiveTable) ([]step, error) {
	d := s.dialect
	var steps []step
	if live == nil {
		statements, err := CreateTable(m, d)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step{table: m.Table, statement: statements[0], change: m.Table,
			done: func(t *LiveTable) bool { return t != nil }})
		live = &LiveTable{}
		for _, f := range m.Fields {
			live.Columns = append(live.Columns, LiveColumn{Name: f.Column})
		}
	}
	created := len(steps) > 0
	for _, f := range m.Fields {
		if _, ok := live.Column(f.Column); ok {
			continue
		}
		def, err := addableColumn(m.Table, f, d)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step{table: m.Table,
			statement: "ALTER TABLE " + quote(m.Table, d) + " ADD COLUMN " + quote(f.Column, d) + " " + def,
			change:    m.Table + ": added column " + f.Column,
			done: func(t *LiveTable) bool {
				return t != nil && slices.ContainsFunc(t.Columns, func(c LiveColumn) bool { return c.Name == f.Column })
			}})
	}
	for _, idx := range m.Indexes {
		if live.hasIndex(idx) {
			continue
		}
		st := step{table: m.Table, statement: createIndex(m.Table, idx, d),
			done: func(t *LiveTable) bool { return t.hasIndex(idx) }}
		if !created {
			st.change = m.Table + ": created index " + idx.Name
		}
		if idx.Unique {
			st.hint = fmt.Sprintf("; if %s holds duplicate (%s) values, remove the duplicate rows and migrate again",
				m.Table, strings.Join(idx.Columns, ", "))
		}
		steps = append(steps, st)
	}
	for _, name := range m.DroppedIndexes {
		if !live.hasIndexNamed(name) {
			continue
		}
		steps = append(steps, step{table: m.Table, statement: dropIndex(m.Table, name, d),
			change: m.Table + ": dropped index " + name,
			done:   func(t *LiveTable) bool { return !t.hasIndexNamed(name) }})
	}
	return steps, nil
}

// apply runs st and reports whether it made the change. A failed statement whose change is
// nevertheless in place (another replica applied it) is not an error.
func (s *Store) apply(ctx context.Context, st step) (bool, error) {
	err := s.Exec(ctx, st.statement)
	if err == nil {
		return true, nil
	}
	if live, ierr := s.Inspect(ctx, st.table); ierr == nil && st.done(live) {
		return false, nil
	}
	return false, fmt.Errorf("sqlstore: migrate: %s: %w%s", firstLine(st.statement), err, st.hint)
}

// errRefused marks a change Migrate does not apply on its own.
var errRefused = errors.New("sqlstore: migrate")

func addableColumn(table string, f schema.Field, d store.Dialect) (string, error) {
	switch {
	case f.Primary:
		return "", fmt.Errorf("%w: %s.%s: a column added to an existing table cannot be part of the primary key; create a new table instead",
			errRefused, table, f.Column)
	case !f.Nullable && (!f.HasDefault || f.Default == nil):
		return "", fmt.Errorf("%w: %s.%s: a column added to an existing table must be nullable or have a default; declare it AsNullable() or WithDefault(v)",
			errRefused, table, f.Column)
	}
	def, err := columnDefinition(f, d)
	if err != nil {
		return "", fmt.Errorf("sqlstore: %s.%s: %w", table, f.Column, err)
	}
	return def, nil
}

func checkDropped(m schema.Model) error {
	for _, name := range m.DroppedIndexes {
		if slices.ContainsFunc(m.Indexes, func(i schema.Index) bool { return i.Name == name }) {
			return fmt.Errorf("%w: %s: index %s is both declared and dropped; give the new index another name",
				errRefused, m.Table, name)
		}
	}
	return nil
}

func dropIndex(table, name string, d store.Dialect) string {
	if d == store.MySQL {
		return "DROP INDEX " + quote(name, d) + " ON " + quote(table, d)
	}
	return "DROP INDEX " + quote(name, d)
}

// hasIndex reports whether t has an index on idx's columns, in order, of the same uniqueness
// (whatever its name), as Diff compares them.
func (t *LiveTable) hasIndex(idx schema.Index) bool {
	return t != nil && slices.ContainsFunc(t.Indexes, func(l LiveIndex) bool {
		return l.Unique == idx.Unique && slices.Equal(l.Columns, idx.Columns)
	})
}

func (t *LiveTable) hasIndexNamed(name string) bool {
	return t != nil && slices.ContainsFunc(t.Indexes, func(l LiveIndex) bool { return l.Name == name })
}
