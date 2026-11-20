package sqlstore

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
)

// ErrCircularForeignKeys is returned when tables reference each other so no creation order exists.
var ErrCircularForeignKeys = errors.New("sqlstore: circular foreign keys in the schema")

// DDL returns the CREATE statements for models in d, formatted as `polaris schema:export` prints
// them: statements separated by a blank line, each ending with ";".
func DDL(models []schema.Model, d store.Dialect) (string, error) {
	statements, err := CreateAll(models, d)
	if err != nil {
		return "", err
	}
	return Script(statements), nil
}

// Script formats statements the way `polaris schema:export` prints them.
func Script(statements []string) string {
	return strings.Join(statements, ";\n\n") + ";\n"
}

// CreateAll returns CREATE TABLE and CREATE INDEX statements for every model, a referenced table
// always before the tables that reference it.
func CreateAll(models []schema.Model, d store.Dialect) ([]string, error) {
	ordered, err := Ordered(models)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range ordered {
		statements, err := CreateTable(m, d)
		if err != nil {
			return nil, err
		}
		out = append(out, statements...)
	}
	return out, nil
}

// DropAll returns DROP TABLE IF EXISTS statements, dependants first.
func DropAll(models []schema.Model, d store.Dialect) ([]string, error) {
	ordered, err := Ordered(models)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ordered))
	for _, m := range slices.Backward(ordered) {
		out = append(out, "DROP TABLE IF EXISTS "+quote(m.Table, d))
	}
	return out, nil
}

// Ordered returns models in creation order: each pass takes, in input order, every model whose
// referenced tables are already placed (a self reference never blocks).
func Ordered(models []schema.Model) ([]schema.Model, error) {
	pending := slices.Clone(models)
	ordered := make([]schema.Model, 0, len(models))
	placed := map[string]bool{}
	for len(pending) > 0 {
		var blocked []schema.Model
		for _, m := range pending {
			if slices.ContainsFunc(m.ForeignKeys, func(r schema.Reference) bool {
				return r.ReferencedTable != m.Table && !placed[r.ReferencedTable]
			}) {
				blocked = append(blocked, m)
				continue
			}
			ordered = append(ordered, m)
			placed[m.Table] = true
		}
		if len(blocked) == len(pending) {
			return nil, fmt.Errorf("%w: %d tables cannot be ordered", ErrCircularForeignKeys, len(blocked))
		}
		pending = blocked
	}
	return ordered, nil
}

// CreateTable returns the CREATE TABLE statement for m followed by one CREATE INDEX per index.
func CreateTable(m schema.Model, d store.Dialect) ([]string, error) {
	q := func(id string) string { return quote(id, d) }
	lines := make([]string, 0, len(m.Fields)+1+len(m.ForeignKeys))
	for _, f := range m.Fields {
		def, err := columnDefinition(f, d)
		if err != nil {
			return nil, fmt.Errorf("sqlstore: %s.%s: %w", m.Table, f.Column, err)
		}
		lines = append(lines, "    "+q(f.Column)+" "+def)
	}
	if pk := m.PrimaryKey(); len(pk) > 0 {
		lines = append(lines, "    PRIMARY KEY ("+joinQuoted(columnsOf(pk), d)+")")
	}
	for _, r := range m.ForeignKeys {
		lines = append(lines, fmt.Sprintf("    FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE %s ON UPDATE %s",
			joinQuoted(r.Columns, d), q(r.ReferencedTable), joinQuoted(r.ReferencedColumns, d), r.OnDelete, r.OnUpdate))
	}
	out := []string{"CREATE TABLE " + q(m.Table) + " (\n" + strings.Join(lines, ",\n") + "\n)"}
	for _, idx := range m.Indexes {
		unique := ""
		if idx.Unique {
			unique = "UNIQUE "
		}
		out = append(out, fmt.Sprintf("CREATE %sINDEX %s ON %s (%s)", unique, q(idx.Name), q(m.Table), joinQuoted(idx.Columns, d)))
	}
	return out, nil
}

func columnDefinition(f schema.Field, d store.Dialect) (string, error) {
	def := columnType(f, d)
	if f.Nullable {
		def += " NULL"
	} else {
		def += " NOT NULL"
	}
	if f.HasDefault && f.Default != nil {
		lit, err := literal(f.Default, d)
		if err != nil {
			return "", err
		}
		def += " DEFAULT " + lit
	}
	return def, nil
}

func columnType(f schema.Field, d store.Dialect) string {
	switch f.Type {
	case schema.String:
		length := f.Length
		if length == 0 {
			length = 255
		}
		if f.ASCII && d == store.MySQL {
			return fmt.Sprintf("VARCHAR(%d) CHARACTER SET ascii COLLATE ascii_bin", length)
		}
		return fmt.Sprintf("VARCHAR(%d)", length)
	case schema.Int:
		return "INTEGER"
	case schema.Bool:
		switch d {
		case store.MySQL:
			return "TINYINT(1)"
		case store.SQLite, store.Memory:
			return "INTEGER"
		}
		return "BOOLEAN"
	case schema.DateTime:
		if d == store.Postgres {
			return "TIMESTAMP"
		}
		return "DATETIME"
	case schema.JSON:
		switch d {
		case store.Postgres:
			return "JSONB"
		case store.MySQL:
			return "JSON"
		}
	}
	return "TEXT"
}

func literal(v any, d store.Dialect) (string, error) {
	switch x := v.(type) {
	case bool:
		switch {
		case d == store.Postgres && x:
			return "TRUE", nil
		case d == store.Postgres:
			return "FALSE", nil
		case x:
			return "1", nil
		}
		return "0", nil
	case string:
		return "'" + strings.ReplaceAll(x, "'", "''") + "'", nil
	case int:
		return strconv.Itoa(x), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	}
	return "", fmt.Errorf("unsupported default value %v (%T)", v, v)
}

func columnsOf(fields []schema.Field) []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.Column
	}
	return out
}

func joinQuoted(ids []string, d store.Dialect) string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = quote(id, d)
	}
	return strings.Join(out, ", ")
}
