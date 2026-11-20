package sqlstore

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// CreateSchema creates every table and index of models, referenced tables first. It does not seed
// the permission catalog or the system roles; the caller does that next, as `schema:create` does.
func (s *Store) CreateSchema(ctx context.Context, models []schema.Model) error {
	statements, err := CreateAll(models, s.dialect)
	if err != nil {
		return err
	}
	return s.execAll(ctx, statements)
}

// CreateMissing creates, in foreign-key order, only the tables of models that Inspect does not
// find, leaving existing tables (rows and columns alike) untouched; Diff reports what they lack.
// It returns the tables it created, in creation order.
func (s *Store) CreateMissing(ctx context.Context, models []schema.Model) ([]string, error) {
	ordered, err := Ordered(models)
	if err != nil {
		return nil, err
	}
	var created []string
	for _, m := range ordered {
		live, err := s.Inspect(ctx, m.Table)
		if err != nil {
			return created, err
		}
		if live != nil {
			continue
		}
		statements, err := CreateTable(m, s.dialect)
		if err != nil {
			return created, err
		}
		if err := s.execAll(ctx, statements); err != nil {
			return created, err
		}
		created = append(created, m.Table)
	}
	return created, nil
}

// DropSchema drops every table of models that exists, dependants first.
func (s *Store) DropSchema(ctx context.Context, models []schema.Model) error {
	statements, err := DropAll(models, s.dialect)
	if err != nil {
		return err
	}
	return s.execAll(ctx, statements)
}

func (s *Store) execAll(ctx context.Context, statements []string) error {
	for _, statement := range statements {
		if err := s.Exec(ctx, statement); err != nil {
			return fmt.Errorf("sqlstore: %s: %w", firstLine(statement), err)
		}
	}
	return nil
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// Diff compares models with the live database: one line per difference (missing table or column,
// type, nullability, extra column, primary key, missing index); empty when the database matches.
func (s *Store) Diff(ctx context.Context, models []schema.Model) ([]string, error) {
	var diffs []string
	for _, m := range models {
		live, err := s.Inspect(ctx, m.Table)
		if err != nil {
			return nil, err
		}
		if live == nil {
			diffs = append(diffs, m.Table+": table is missing")
			continue
		}
		diffs = append(diffs, diffTable(m, live, s.dialect)...)
	}
	return diffs, nil
}

func diffTable(m schema.Model, live *LiveTable, d store.Dialect) []string {
	var diffs []string
	add := func(format string, args ...any) { diffs = append(diffs, fmt.Sprintf(format, args...)) }
	for _, f := range m.Fields {
		c, ok := live.Column(f.Column)
		if !ok {
			add("%s.%s: column is missing", m.Table, f.Column)
			continue
		}
		if !sameType(f, c, d) {
			add("%s.%s: expected %s, found %s", m.Table, f.Column, describe(f), c.Raw)
		}
		if c.Nullable != f.Nullable {
			add("%s.%s: expected %s, found %s", m.Table, f.Column, nullability(f.Nullable), nullability(c.Nullable))
		}
	}
	for _, c := range live.Columns {
		if _, err := m.FieldByColumn(c.Name); err != nil {
			add("%s.%s: extra column (%s)", m.Table, c.Name, c.Raw)
		}
	}
	if primary := columnsOf(m.PrimaryKey()); !slices.Equal(primary, live.Primary) {
		add("%s: expected primary key (%s), found (%s)", m.Table, strings.Join(primary, ", "), strings.Join(live.Primary, ", "))
	}
	for _, idx := range m.Indexes {
		if !slices.ContainsFunc(live.Indexes, func(l LiveIndex) bool {
			return l.Unique == idx.Unique && slices.Equal(l.Columns, idx.Columns)
		}) {
			kind := "plain"
			if idx.Unique {
				kind = "unique"
			}
			add("%s: %s index on (%s) is missing", m.Table, kind, strings.Join(idx.Columns, ", "))
		}
	}
	return diffs
}

func sameType(f schema.Field, c LiveColumn, d store.Dialect) bool {
	lenient := d == store.SQLite || d == store.Memory
	switch {
	case c.Type == "":
		return false
	case f.Type == schema.String:
		return c.Type == schema.String && (c.Length == 0 || c.Length == f.Length)
	case f.Type == schema.Bool && lenient:
		return c.Type == schema.Bool || c.Type == schema.Int
	case f.Type == schema.JSON && lenient:
		return c.Type == schema.JSON || c.Type == schema.Text
	}
	return c.Type == f.Type
}

func describe(f schema.Field) string {
	if f.Type == schema.String {
		return fmt.Sprintf("string(%d)", f.Length)
	}
	return string(f.Type)
}

func nullability(nullable bool) string {
	if nullable {
		return "NULL"
	}
	return "NOT NULL"
}
