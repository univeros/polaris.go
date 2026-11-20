package sqlstore

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/univeros/polaris-go/store"
)

// mysqlNoLimit is MySQL's documented "no limit" for an OFFSET without LIMIT.
const mysqlNoLimit = "18446744073709551615"

var errNoColumns = errors.New("sqlstore: no columns to write")

// query accumulates one statement and its arguments, numbering placeholders per dialect.
type query struct {
	d    store.Dialect
	sql  strings.Builder
	args []any
}

func (q *query) write(parts ...string) {
	for _, p := range parts {
		q.sql.WriteString(p)
	}
}

// param records v and returns its placeholder: $n on PostgreSQL, ? elsewhere.
func (q *query) param(v any) string {
	q.args = append(q.args, bindValue(v))
	if q.d == store.Postgres {
		return "$" + strconv.Itoa(len(q.args))
	}
	return "?"
}

// bindValue converts a Go value to what is stored: times as UTC store.TimeLayout text, the rest
// as given (bools bind natively).
func bindValue(v any) any {
	if t, ok := v.(time.Time); ok {
		return t.UTC().Format(store.TimeLayout)
	}
	return v
}

// where appends " WHERE ..." for c, columns in sorted order so equal criteria give equal SQL.
func (q *query) where(c store.Criteria) {
	if len(c) == 0 {
		return
	}
	clauses := make([]string, 0, len(c))
	for _, col := range slices.Sorted(maps.Keys(c)) {
		clauses = append(clauses, q.clause(quote(col, q.d), c[col]))
	}
	q.write(" WHERE ", strings.Join(clauses, " AND "))
}

func (q *query) clause(col string, v any) string {
	if v == nil {
		return col + " IS NULL"
	}
	if c, ok := v.(store.Cond); ok {
		switch c.Op {
		case store.OpNotNull:
			return col + " IS NOT NULL"
		case store.OpNe:
			return col + " <> " + q.param(c.Value)
		}
		return fmt.Sprintf("%s %s %s", col, c.Op, q.param(c.Value))
	}
	if list, ok := store.Values(v); ok {
		if len(list) == 0 {
			return "1 = 0"
		}
		marks := make([]string, len(list))
		for i, item := range list {
			marks[i] = q.param(item)
		}
		return fmt.Sprintf("%s IN (%s)", col, strings.Join(marks, ", "))
	}
	return col + " = " + q.param(v)
}

func selectQuery(d store.Dialect, table string, c store.Criteria, opts store.Query) *query {
	q := &query{d: d}
	q.write("SELECT * FROM ", quote(table, d))
	q.where(c)
	if len(opts.OrderBy) > 0 {
		terms := make([]string, len(opts.OrderBy))
		for i, o := range opts.OrderBy {
			dir := " ASC"
			if o.Desc {
				dir = " DESC"
			}
			terms[i] = quote(o.Column, d) + dir
		}
		q.write(" ORDER BY ", strings.Join(terms, ", "))
	}
	if opts.Limit > 0 {
		q.write(" LIMIT ", strconv.Itoa(opts.Limit))
	}
	if opts.Offset > 0 {
		if opts.Limit <= 0 {
			switch d {
			case store.SQLite:
				q.write(" LIMIT -1")
			case store.MySQL:
				q.write(" LIMIT ", mysqlNoLimit)
			}
		}
		q.write(" OFFSET ", strconv.Itoa(opts.Offset))
	}
	return q
}

func countQuery(d store.Dialect, table string, c store.Criteria) *query {
	q := &query{d: d}
	q.write("SELECT COUNT(*) FROM ", quote(table, d))
	q.where(c)
	return q
}

func insertQuery(d store.Dialect, table string, row store.Row) (*query, error) {
	if len(row) == 0 {
		return nil, fmt.Errorf("insert into %s: %w", table, errNoColumns)
	}
	q := &query{d: d}
	cols := slices.Sorted(maps.Keys(row))
	quoted := make([]string, len(cols))
	marks := make([]string, len(cols))
	for i, col := range cols {
		quoted[i] = quote(col, d)
		marks[i] = q.param(row[col])
	}
	q.write("INSERT INTO ", quote(table, d), " (", strings.Join(quoted, ", "), ") VALUES (", strings.Join(marks, ", "), ")")
	return q, nil
}

func updateQuery(d store.Dialect, table string, c store.Criteria, data store.Data) (*query, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("update %s: %w", table, errNoColumns)
	}
	q := &query{d: d}
	cols := slices.Sorted(maps.Keys(data))
	set := make([]string, len(cols))
	for i, col := range cols {
		quoted := quote(col, d)
		if inc, ok := data[col].(store.Increment); ok {
			set[i] = fmt.Sprintf("%[1]s = %[1]s + %[2]d", quoted, inc.By)
		} else {
			set[i] = quoted + " = " + q.param(data[col])
		}
	}
	q.write("UPDATE ", quote(table, d), " SET ", strings.Join(set, ", "))
	q.where(c)
	return q, nil
}

func deleteQuery(d store.Dialect, table string, c store.Criteria) *query {
	q := &query{d: d}
	q.write("DELETE FROM ", quote(table, d))
	q.where(c)
	return q
}

// quote quotes an identifier: backticks on MySQL, double quotes elsewhere; an embedded quote
// character is doubled.
func quote(id string, d store.Dialect) string {
	if d == store.MySQL {
		return "`" + strings.ReplaceAll(id, "`", "``") + "`"
	}
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}
