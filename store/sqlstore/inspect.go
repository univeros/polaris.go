package sqlstore

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// LiveTable is a table as the database reports it, in the schema package's vocabulary.
type LiveTable struct {
	Columns []LiveColumn // in ordinal order
	Primary []string     // primary-key columns in key order
	Indexes []LiveIndex  // every index but the primary key's
}

// LiveColumn is one column of a LiveTable.
type LiveColumn struct {
	Name     string
	Type     schema.FieldType // "" when the database type has no schema equivalent
	Length   int              // VARCHAR length; 0 when unknown or not a string
	Nullable bool
	Raw      string // the database's own type name
}

// LiveIndex is one index of a LiveTable.
type LiveIndex struct {
	Name    string
	Columns []string
	Unique  bool
}

// Column finds a column by name.
func (t *LiveTable) Column(name string) (LiveColumn, bool) {
	i := slices.IndexFunc(t.Columns, func(c LiveColumn) bool { return c.Name == name })
	if i < 0 {
		return LiveColumn{}, false
	}
	return t.Columns[i], true
}

// Inspect reads a table's columns, primary key and indexes; nil, nil when the table does not exist.
func (s *Store) Inspect(ctx context.Context, table string) (*LiveTable, error) {
	var (
		t   *LiveTable
		err error
	)
	switch s.dialect {
	case store.Postgres:
		t, err = s.inspectPostgres(ctx, table)
	case store.MySQL:
		t, err = s.inspectMySQL(ctx, table)
	default:
		t, err = s.inspectSQLite(ctx, table)
	}
	if err != nil {
		return nil, fmt.Errorf("sqlstore: inspect %s: %w", table, err)
	}
	return t, nil
}

func (s *Store) rows(ctx context.Context, statement string, args ...any) ([]store.Row, error) {
	rows, err := s.conn(ctx).QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, err
	}
	return scanRows(rows)
}

func (s *Store) inspectSQLite(ctx context.Context, table string) (*LiveTable, error) {
	cols, err := s.rows(ctx, "PRAGMA table_info("+quote(table, store.SQLite)+")")
	if err != nil || len(cols) == 0 {
		return nil, err
	}
	t := &LiveTable{}
	pk := map[int64]string{}
	for _, c := range cols {
		t.Columns = append(t.Columns, liveColumn(c.String("name"), c.String("type"), 0, c.Int("notnull") == 0))
		if n := c.Int("pk"); n > 0 {
			pk[n] = c.String("name")
		}
	}
	t.Primary = byPosition(pk)
	list, err := s.rows(ctx, "PRAGMA index_list("+quote(table, store.SQLite)+")")
	if err != nil {
		return nil, err
	}
	for _, idx := range list {
		if idx.String("origin") == "pk" {
			continue
		}
		info, err := s.rows(ctx, "PRAGMA index_info("+quote(idx.String("name"), store.SQLite)+")")
		if err != nil {
			return nil, err
		}
		byPos := map[int64]string{}
		for _, c := range info {
			byPos[c.Int("seqno")] = c.String("name")
		}
		t.Indexes = append(t.Indexes, LiveIndex{Name: idx.String("name"), Columns: byPosition(byPos), Unique: idx.Int("unique") == 1})
	}
	return t, nil
}

func (s *Store) inspectPostgres(ctx context.Context, table string) (*LiveTable, error) {
	cols, err := s.rows(ctx, `SELECT column_name AS name, data_type AS type, character_maximum_length AS length, is_nullable AS nullable FROM information_schema.columns WHERE table_name = $1 AND table_schema = current_schema() ORDER BY ordinal_position`, table)
	if err != nil || len(cols) == 0 {
		return nil, err
	}
	t := &LiveTable{}
	for _, c := range cols {
		t.Columns = append(t.Columns, liveColumn(c.String("name"), c.String("type"), int(c.Int("length")), c.String("nullable") == "YES"))
	}
	// The catalog's rows, not pg_indexes: its definition (pg_get_indexdef) is not read in the query's
	// snapshot and fails for an index another process drops meanwhile.
	rows, err := s.rows(ctx, `SELECT ic.relname AS index, i.indisprimary AS is_primary, i.indisunique AS is_unique, a.attname AS name
FROM pg_index i
JOIN pg_class ic ON ic.oid = i.indexrelid
JOIN pg_class tc ON tc.oid = i.indrelid
JOIN pg_namespace n ON n.oid = tc.relnamespace
CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, position)
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
WHERE tc.relname = $1 AND n.nspname = current_schema() AND k.position <= i.indnkeyatts
ORDER BY ic.relname, k.position`, table)
	if err != nil {
		return nil, err
	}
	var indexes []LiveIndex
	for _, r := range rows {
		if r.Bool("is_primary") {
			t.Primary = append(t.Primary, r.String("name"))
			continue
		}
		if n := len(indexes); n == 0 || indexes[n-1].Name != r.String("index") {
			indexes = append(indexes, LiveIndex{Name: r.String("index"), Unique: r.Bool("is_unique")})
		}
		last := &indexes[len(indexes)-1]
		last.Columns = append(last.Columns, r.String("name"))
	}
	for _, idx := range indexes {
		if !slices.Equal(idx.Columns, t.Primary) {
			t.Indexes = append(t.Indexes, idx)
		}
	}
	return t, nil
}

func (s *Store) inspectMySQL(ctx context.Context, table string) (*LiveTable, error) {
	cols, err := s.rows(ctx, "SELECT column_name AS name, column_type AS type, character_maximum_length AS length, is_nullable AS nullable FROM information_schema.columns WHERE table_name = ? AND table_schema = DATABASE() ORDER BY ordinal_position", table)
	if err != nil || len(cols) == 0 {
		return nil, err
	}
	t := &LiveTable{}
	for _, c := range cols {
		t.Columns = append(t.Columns, liveColumn(c.String("name"), c.String("type"), int(c.Int("length")), c.String("nullable") == "YES"))
	}
	keys, err := s.rows(ctx, "SHOW INDEX FROM "+quote(table, store.MySQL))
	if err != nil {
		return nil, err
	}
	primary := map[int64]string{}
	var names []string
	byName := map[string]map[int64]string{}
	unique := map[string]bool{}
	for _, k := range keys {
		name, seq, col := k.String("Key_name"), k.Int("Seq_in_index"), k.String("Column_name")
		if name == "PRIMARY" {
			primary[seq] = col
			continue
		}
		if byName[name] == nil {
			names = append(names, name)
			byName[name] = map[int64]string{}
		}
		byName[name][seq] = col
		unique[name] = k.Int("Non_unique") == 0
	}
	t.Primary = byPosition(primary)
	for _, name := range names {
		t.Indexes = append(t.Indexes, LiveIndex{Name: name, Columns: byPosition(byName[name]), Unique: unique[name]})
	}
	return t, nil
}

func byPosition(m map[int64]string) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(m)) {
		out = append(out, m[k])
	}
	return out
}

var varcharLength = regexp.MustCompile(`^(?:character varying|varchar)\s*\((\d+)\)$`)
var intPrefix = regexp.MustCompile(`^(?:int|integer|bigint|smallint)`)

func liveColumn(name, raw string, length int, nullable bool) LiveColumn {
	c := LiveColumn{Name: name, Raw: raw, Nullable: nullable}
	c.Type, c.Length = liveType(raw, length)
	return c
}

// liveType maps a database type name to a schema type.
func liveType(raw string, length int) (schema.FieldType, int) {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if m := varcharLength.FindStringSubmatch(lower); m != nil {
		n, _ := strconv.Atoi(m[1])
		return schema.String, n
	}
	switch {
	case lower == "character varying" || lower == "varchar":
		return schema.String, length
	case strings.HasPrefix(lower, "tinyint(1)") || lower == "boolean" || lower == "bool":
		return schema.Bool, 0
	case intPrefix.MatchString(lower):
		return schema.Int, 0
	case strings.HasPrefix(lower, "timestamp") || lower == "datetime":
		return schema.DateTime, 0
	case lower == "json" || lower == "jsonb":
		return schema.JSON, 0
	case lower == "text" || strings.HasPrefix(lower, "longtext") || strings.HasPrefix(lower, "mediumtext"):
		return schema.Text, 0
	}
	return "", length
}
