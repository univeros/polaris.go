// Package schema is the database schema as data. DDL export,
// schema diff, installers and adapters read it; core's tables are in core.go, a plugin declares its
// own through polaris.Plugin.Schema.
package schema

import (
	"fmt"
	"strings"
)

// FieldType is a column's logical type.
type FieldType string

// The column types. Each dialect maps them in the DDL: String is VARCHAR(Length), Text is TEXT,
// Int is INTEGER, Bool is BOOLEAN (TINYINT(1) on MySQL, INTEGER on SQLite), DateTime is TIMESTAMP
// (DATETIME on MySQL and SQLite) and JSON is JSONB on PostgreSQL, JSON on MySQL and TEXT on SQLite.
const (
	String   FieldType = "string"
	Text     FieldType = "text"
	Int      FieldType = "int"
	Bool     FieldType = "bool"
	DateTime FieldType = "datetime"
	JSON     FieldType = "json"
)

// Field is one column.
type Field struct {
	Property   string
	Column     string
	Type       FieldType
	Length     int // String only
	Nullable   bool
	Primary    bool
	HasDefault bool
	Default    any
	// ASCII marks a String column that only ever holds ASCII and compares byte for byte (base64url
	// identifiers): MySQL declares it CHARACTER SET ascii COLLATE ascii_bin, so it is case-sensitive
	// and a unique index on up to 3072 characters fits; the other dialects are unchanged. It changes
	// only the MySQL DDL: the type, length and data stay the same.
	ASCII bool
	// CaseSensitive marks a String column holding an identifier that compares byte for byte but
	// may hold any UTF-8 (an IdP's subject, a client_id URL): MySQL declares it CHARACTER SET
	// utf8mb4 COLLATE utf8mb4_bin instead of its case- and accent-insensitive default; the other
	// dialects already compare bytes. A Go-only MySQL DDL refinement, like ASCII.
	CaseSensitive bool
}

func newField(property string, t FieldType, length int, column ...string) Field {
	col := SnakeCase(property)
	if len(column) > 0 && column[0] != "" {
		col = column[0]
	}
	return Field{Property: property, Column: col, Type: t, Length: length}
}

// StringField declares a NOT NULL VARCHAR(length) column for property; its column name is
// SnakeCase(property) unless column names it.
func StringField(property string, length int, column ...string) Field {
	return newField(property, String, length, column...)
}

// TextField declares a NOT NULL TEXT column (named as StringField's).
func TextField(property string, column ...string) Field {
	return newField(property, Text, 0, column...)
}

// IntField declares a NOT NULL INTEGER column (named as StringField's).
func IntField(property string, column ...string) Field { return newField(property, Int, 0, column...) }

// BoolField declares a NOT NULL boolean column (named as StringField's).
func BoolField(property string, column ...string) Field {
	return newField(property, Bool, 0, column...)
}

// DateTimeField declares a NOT NULL timestamp column, stored in UTC to the second (named as
// StringField's).
func DateTimeField(property string, column ...string) Field {
	return newField(property, DateTime, 0, column...)
}

// JSONField declares a NOT NULL JSON column (named as StringField's).
func JSONField(property string, column ...string) Field {
	return newField(property, JSON, 0, column...)
}

// AsPrimary returns a copy that is part of the primary key.
func (f Field) AsPrimary() Field { f.Primary = true; return f }

// AsNullable returns a copy that accepts NULL.
func (f Field) AsNullable() Field { f.Nullable = true; return f }

// AsASCII returns a copy marked ASCII (see Field.ASCII).
func (f Field) AsASCII() Field { f.ASCII = true; return f }

// AsCaseSensitive returns a copy marked CaseSensitive (see Field.CaseSensitive).
func (f Field) AsCaseSensitive() Field { f.CaseSensitive = true; return f }

// WithDefault returns a copy with a column default.
func (f Field) WithDefault(v any) Field { f.HasDefault = true; f.Default = v; return f }

// SnakeCase maps a camelCase property to its column ("emailVerifiedAt" → "email_verified_at").
func SnakeCase(property string) string {
	var b strings.Builder
	for i, r := range property {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

// Index is a (unique) index.
type Index struct {
	Columns []string
	Unique  bool
	Name    string
}

// Reference is a foreign key.
type Reference struct {
	Columns           []string
	ReferencedTable   string
	ReferencedColumns []string
	OnDelete          string
	OnUpdate          string
}

// Model is one table. It is declared as the latest release wants it: Migrate creates the table
// when it is missing and, on an existing table, adds the fields and indexes it lacks (see
// sqlstore.Store.Migrate). A field added to an existing table must be nullable or have a default.
type Model struct {
	Table       string
	Fields      []Field
	Indexes     []Index
	ForeignKeys []Reference
	// DroppedIndexes names indexes an earlier release created that this one no longer has;
	// Migrate drops each one that exists. A fresh install never creates them.
	DroppedIndexes []string
}

// Table starts a model.
func Table(table string, fields ...Field) Model {
	return Model{Table: table, Fields: fields}
}

// Unique adds a unique index (name defaults to <table>_<cols>_unique).
func (m Model) Unique(columns []string, name ...string) Model {
	return m.withIndex(Index{Columns: columns, Unique: true, Name: m.indexName(columns, "unique", name)})
}

// Index adds a plain index (name defaults to <table>_<cols>_index).
func (m Model) Index(columns []string, name ...string) Model {
	return m.withIndex(Index{Columns: columns, Name: m.indexName(columns, "index", name)})
}

// References adds a foreign key; onDelete/onUpdate default to CASCADE.
func (m Model) References(columns []string, table string, referenced []string, actions ...string) Model {
	ref := Reference{Columns: columns, ReferencedTable: table, ReferencedColumns: referenced, OnDelete: "CASCADE", OnUpdate: "CASCADE"}
	if len(actions) > 0 {
		ref.OnDelete = actions[0]
	}
	if len(actions) > 1 {
		ref.OnUpdate = actions[1]
	}
	out := m
	out.ForeignKeys = append(append([]Reference{}, m.ForeignKeys...), ref)
	return out
}

// DropIndex records that an earlier release created the index name and this one does not: Migrate
// drops it where it exists. Use it to replace an index (a plain one becoming unique, other
// columns): declare the new index under a new name and drop the old name.
func (m Model) DropIndex(name string) Model {
	out := m
	out.DroppedIndexes = append(append([]string{}, m.DroppedIndexes...), name)
	return out
}

// PrimaryKey lists the primary-key fields in declaration order.
func (m Model) PrimaryKey() []Field {
	var pk []Field
	for _, f := range m.Fields {
		if f.Primary {
			pk = append(pk, f)
		}
	}
	return pk
}

// Field finds a field by property.
func (m Model) Field(property string) (Field, error) {
	for _, f := range m.Fields {
		if f.Property == property {
			return f, nil
		}
	}
	return Field{}, fmt.Errorf("schema: %s has no property %q", m.Table, property)
}

// FieldByColumn finds a field by column.
func (m Model) FieldByColumn(column string) (Field, error) {
	for _, f := range m.Fields {
		if f.Column == column {
			return f, nil
		}
	}
	return Field{}, fmt.Errorf("schema: %s has no column %q", m.Table, column)
}

func (m Model) withIndex(i Index) Model {
	out := m
	out.Indexes = append(append([]Index{}, m.Indexes...), i)
	return out
}

func (m Model) indexName(columns []string, suffix string, name []string) string {
	if len(name) > 0 && name[0] != "" {
		return name[0]
	}
	return fmt.Sprintf("%s_%s_%s", m.Table, strings.Join(columns, "_"), suffix)
}
