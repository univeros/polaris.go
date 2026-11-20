package schema_test

import (
	"errors"
	"testing"

	"github.com/univeros/polaris.go/schema"
)

func TestEveryCoreModelIsDefinedOnceWithAPrimaryKeyAndUniqueColumns(t *testing.T) {
	models := schema.Core()
	if len(models) != 15 {
		t.Fatalf("Core() has %d models, want 15", len(models))
	}
	tables := map[string]bool{}
	for _, m := range models {
		if tables[m.Table] {
			t.Errorf("%s defined twice", m.Table)
		}
		tables[m.Table] = true
		if len(m.PrimaryKey()) == 0 {
			t.Errorf("%s needs a primary key", m.Table)
		}
		columns := map[string]bool{}
		for _, f := range m.Fields {
			if columns[f.Column] {
				t.Errorf("%s has duplicate column %s", m.Table, f.Column)
			}
			columns[f.Column] = true
			byColumn, err := m.FieldByColumn(f.Column)
			if err != nil || byColumn.Property != f.Property {
				t.Errorf("%s: column %s does not map back to %s", m.Table, f.Column, f.Property)
			}
		}
		for _, idx := range m.Indexes {
			for _, c := range idx.Columns {
				if !columns[c] {
					t.Errorf("%s: index %s names unknown column %s", m.Table, idx.Name, c)
				}
			}
		}
	}
}

func TestUserSchemaCarriesTypesLengthsAndIndexes(t *testing.T) {
	users := find(t, schema.Core(), "auth_users")

	email := field(t, users, "email")
	if email.Type != schema.String || email.Length != 320 {
		t.Errorf("email = %s(%d), want string(320)", email.Type, email.Length)
	}
	verified := field(t, users, "emailVerifiedAt")
	if verified.Column != "email_verified_at" || !verified.Nullable {
		t.Errorf("emailVerifiedAt = %+v", verified)
	}
	if field(t, users, "createdAt").Type != schema.DateTime {
		t.Error("createdAt is not a datetime")
	}
	if !field(t, users, "id").Primary {
		t.Error("id is not primary")
	}
	if got := users.Indexes[0]; len(got.Columns) != 1 || got.Columns[0] != "email" || !got.Unique {
		t.Errorf("first index = %+v, want unique (email)", got)
	}
	status := field(t, users, "status")
	if !status.HasDefault || status.Default != "active" {
		t.Errorf("status default = %v", status.Default)
	}
	if mfa := field(t, users, "mfaEnforced"); mfa.Default != false || !mfa.HasDefault {
		t.Errorf("mfaEnforced default = %v", mfa.Default)
	}
}

func TestCompositeKeysAndForeignKeysKeepTheirOrder(t *testing.T) {
	links := find(t, schema.Core(), "auth_membership_roles")
	pk := links.PrimaryKey()
	if len(pk) != 2 || pk[0].Column != "membership_id" || pk[1].Column != "role_id" {
		t.Errorf("primary key = %+v", pk)
	}
	if len(links.ForeignKeys) != 2 || links.ForeignKeys[0].ReferencedTable != "auth_memberships" || links.ForeignKeys[1].ReferencedTable != "auth_roles" {
		t.Errorf("foreign keys = %+v", links.ForeignKeys)
	}
}

func TestCoreReturnsAFreshCopy(t *testing.T) {
	first := schema.Core()
	first[0].Table = "changed"
	first[0].Fields[0].Column = "changed"
	second := schema.Core()
	if second[0].Table != "auth_audit_log" || second[0].Fields[0].Column != "id" {
		t.Error("Core() shares state between calls")
	}
}

func TestMergeAppendsPluginModels(t *testing.T) {
	plugin := schema.Table("auth_api_keys", schema.StringField("id", 36).AsPrimary())
	other := schema.Table("auth_sessions", schema.StringField("id", 36).AsPrimary())

	merged, err := schema.Merge(schema.Core(), []schema.Model{plugin}, []schema.Model{other})
	if err != nil {
		t.Fatal(err)
	}
	if len(merged) != 17 || merged[15].Table != "auth_api_keys" || merged[16].Table != "auth_sessions" {
		t.Errorf("merged tables = %d, tail %s %s", len(merged), merged[15].Table, merged[16].Table)
	}
}

func TestMergeRejectsAPluginRedefiningATable(t *testing.T) {
	core := schema.Core()
	_, err := schema.Merge(core, []schema.Model{schema.Table("auth_users")})
	if !errors.Is(err, schema.ErrRedefined) {
		t.Errorf("redefining a core table: err = %v", err)
	}
	dup := schema.Table("auth_api_keys")
	_, err = schema.Merge(core, []schema.Model{dup}, []schema.Model{dup})
	if !errors.Is(err, schema.ErrRedefined) {
		t.Errorf("two plugins defining one table: err = %v", err)
	}
}

func TestFieldFluentMethodsReturnCopies(t *testing.T) {
	f := schema.StringField("displayName", 120)
	nullable := f.AsNullable()
	if f.Nullable || !nullable.Nullable || f.Column != "display_name" {
		t.Errorf("field = %+v, nullable = %+v", f, nullable)
	}
}

func find(t *testing.T, models []schema.Model, table string) schema.Model {
	t.Helper()
	for _, m := range models {
		if m.Table == table {
			return m
		}
	}
	t.Fatalf("no model %s", table)
	return schema.Model{}
}

func field(t *testing.T, m schema.Model, property string) schema.Field {
	t.Helper()
	f, err := m.Field(property)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
