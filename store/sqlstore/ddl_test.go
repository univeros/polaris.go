package sqlstore_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
)

var dialects = []store.Dialect{store.Postgres, store.MySQL, store.SQLite}

// The goldens are `php bin/polaris schema:export --target=sql:<dialect> [--drop]` from polaris-core.
func TestDDLIsByteIdenticalToPHP(t *testing.T) {
	for _, d := range dialects {
		t.Run(string(d), func(t *testing.T) {
			got, err := sqlstore.DDL(schema.Core(), d)
			if err != nil {
				t.Fatal(err)
			}
			assertGolden(t, "core."+string(d)+".sql", got)

			drops, err := sqlstore.DropAll(schema.Core(), d)
			if err != nil {
				t.Fatal(err)
			}
			assertGolden(t, "core."+string(d)+".drop.sql", sqlstore.Script(drops))
		})
	}
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "ddl", name))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		gl, wl := strings.Split(got, "\n"), strings.Split(string(want), "\n")
		for i := range min(len(gl), len(wl)) {
			if gl[i] != wl[i] {
				t.Fatalf("%s differs at line %d:\n got %q\nwant %q", name, i+1, gl[i], wl[i])
			}
		}
		t.Fatalf("%s differs in length: %d lines, want %d", name, len(gl), len(wl))
	}
}

func TestReferencedTablesComeFirstAndKeysAreDeclared(t *testing.T) {
	statements, err := sqlstore.CreateAll(schema.Core(), store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	sql := strings.Join(statements, "\n")
	pos := func(s string) int { return strings.Index(sql, s) }
	if pos(`CREATE TABLE "auth_roles"`) > pos(`CREATE TABLE "auth_role_permissions"`) ||
		pos(`CREATE TABLE "auth_permissions"`) > pos(`CREATE TABLE "auth_role_permissions"`) {
		t.Error("a referenced table comes after the table referencing it")
	}
	for _, want := range []string{
		`PRIMARY KEY ("role_id", "permission_id")`,
		`FOREIGN KEY ("role_id") REFERENCES "auth_roles" ("id") ON DELETE CASCADE ON UPDATE CASCADE`,
		`CREATE UNIQUE INDEX "auth_users_email_unique" ON "auth_users" ("email")`,
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %s", want)
		}
	}
}

func TestTypesFollowTheDialect(t *testing.T) {
	var users schema.Model
	for _, m := range schema.Core() {
		if m.Table == "auth_users" {
			users = m
		}
	}
	ddl := func(d store.Dialect) string {
		s, err := sqlstore.CreateTable(users, d)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(s, "\n")
	}
	cases := map[store.Dialect][]string{
		store.Postgres: {`"email" VARCHAR(320) NOT NULL`, `"mfa_enforced" BOOLEAN NOT NULL DEFAULT FALSE`, `"created_at" TIMESTAMP NOT NULL`},
		store.MySQL:    {"`mfa_enforced` TINYINT(1) NOT NULL DEFAULT 0", "`created_at` DATETIME NOT NULL"},
		store.SQLite:   {`"status" VARCHAR(16) NOT NULL DEFAULT 'active'`, `"email_verified_at" DATETIME NULL`},
		store.Memory:   {`"mfa_enforced" INTEGER NOT NULL DEFAULT 0`},
	}
	for d, wants := range cases {
		got := ddl(d)
		for _, want := range wants {
			if !strings.Contains(got, want) {
				t.Errorf("%s: missing %s", d, want)
			}
		}
	}
}

func TestDefaultsAndLengths(t *testing.T) {
	m := schema.Table("t",
		schema.StringField("s", 0).WithDefault("it's"),
		schema.IntField("i").WithDefault(int64(7)),
		schema.TextField("f").WithDefault(1.5),
		schema.BoolField("b").WithDefault(true),
		schema.JSONField("j").WithDefault(nil),
	)
	got, err := sqlstore.CreateTable(m, store.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	want := "CREATE TABLE \"t\" (\n" +
		"    \"s\" VARCHAR(255) NOT NULL DEFAULT 'it''s',\n" +
		"    \"i\" INTEGER NOT NULL DEFAULT 7,\n" +
		"    \"f\" TEXT NOT NULL DEFAULT 1.5,\n" +
		"    \"b\" BOOLEAN NOT NULL DEFAULT TRUE,\n" +
		"    \"j\" JSONB NOT NULL\n)"
	if got[0] != want {
		t.Errorf("got\n%s\nwant\n%s", got[0], want)
	}
	if s, _ := sqlstore.CreateTable(schema.Table("t", schema.BoolField("b").WithDefault(true)), store.SQLite); !strings.Contains(s[0], "DEFAULT 1") {
		t.Errorf("sqlite true default: %s", s[0])
	}

	bad := schema.Table("t", schema.JSONField("j").WithDefault([]string{}))
	if _, err := sqlstore.DDL([]schema.Model{bad}, store.SQLite); err == nil {
		t.Error("unsupported default accepted")
	}
}

func TestCircularForeignKeysAreRejected(t *testing.T) {
	a := schema.Table("a", schema.StringField("id", 36).AsPrimary()).References([]string{"id"}, "b", []string{"id"})
	b := schema.Table("b", schema.StringField("id", 36).AsPrimary()).References([]string{"id"}, "a", []string{"id"})
	self := schema.Table("c", schema.StringField("id", 36).AsPrimary()).References([]string{"id"}, "c", []string{"id"})
	if _, err := sqlstore.Ordered([]schema.Model{self}); err != nil {
		t.Errorf("a self reference must not block: %v", err)
	}
	if _, err := sqlstore.DDL([]schema.Model{a, b}, store.SQLite); !errors.Is(err, sqlstore.ErrCircularForeignKeys) {
		t.Errorf("DDL: %v", err)
	}
	if _, err := sqlstore.DropAll([]schema.Model{a, b}, store.SQLite); !errors.Is(err, sqlstore.ErrCircularForeignKeys) {
		t.Errorf("DropAll: %v", err)
	}
}
