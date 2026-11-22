package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func golden(t *testing.T, dir, name string) string {
	t.Helper()
	return readFile(t, filepath.Join("..", "testdata", dir, name))
}

// The goldens are the `schema:export` and `manifest` output, byte for byte.
func TestExportsAreByteIdenticalToTheGoldens(t *testing.T) {
	cleanEnv(t)
	cases := []struct {
		args   []string
		golden [2]string
	}{
		{[]string{"schema:export"}, [2]string{"ddl", "core.postgres.sql"}},
		{[]string{"schema:export", "--target=sql:postgres", "--drop"}, [2]string{"ddl", "core.postgres.drop.sql"}},
		{[]string{"schema:export", "--target=sql:mysql"}, [2]string{"ddl", "core.mysql.sql"}},
		{[]string{"schema:export", "--target=sql:mysql", "--drop"}, [2]string{"ddl", "core.mysql.drop.sql"}},
		{[]string{"schema:export", "--target=sql:sqlite"}, [2]string{"ddl", "core.sqlite.sql"}},
		{[]string{"schema:export", "--target=sql:sqlite", "--drop"}, [2]string{"ddl", "core.sqlite.drop.sql"}},
		{[]string{"manifest"}, [2]string{"manifest", "core.json"}},
		{[]string{"manifest", "--format=openapi"}, [2]string{"manifest", "core.openapi.json"}},
	}
	for _, c := range cases {
		t.Run(strings.Join(c.args, " "), func(t *testing.T) {
			r := standalone(t, noEnvFile(t), c.args...)
			r.want(t, exitOK)
			if want := golden(t, c.golden[0], c.golden[1]); r.stdout != want {
				t.Errorf("differs from %s (%d bytes, want %d)", c.golden[1], len(r.stdout), len(want))
			}
		})
	}
}

func TestExportsFollowThePlugins(t *testing.T) {
	cleanEnv(t)
	r := standalone(t, noEnvFile(t), "schema:export", "--target=sql:sqlite", "--plugins=audit,admin", "--json")
	r.want(t, exitOK)
	m := r.json(t)
	if m["target"] != "sql:sqlite" || !strings.Contains(r.stdout, "polaris_admin_key") {
		t.Errorf("plugin tables missing: %v", m["target"])
	}
	t.Setenv("POLARIS_PLUGINS", "oauth")
	if r := standalone(t, noEnvFile(t), "manifest", "--json"); !strings.Contains(r.stdout, "/oauth2/token") {
		t.Error("POLARIS_PLUGINS not honoured by manifest")
	}
}

func TestSchemaLifecycleIsIdempotent(t *testing.T) {
	configuredEnv(t)
	env := noEnvFile(t)
	plugins := "--plugins=audit,admin,apikeys,oauth,agents,anonymous"

	r := standalone(t, env, "schema:diff", plugins, "--json")
	r.want(t, exitFail)
	if diffs := r.json(t)["differences"].([]any); len(diffs) == 0 || !strings.Contains(r.stdout, "auth_users: table is missing") {
		t.Fatalf("diff on an empty database: %v", diffs)
	}

	r = standalone(t, env, "migrate", plugins, "--json")
	r.want(t, exitOK)
	if created := r.json(t)["created"].([]any); len(created) < 20 {
		t.Errorf("created %v", created)
	}
	standalone(t, env, "migrate", plugins).want(t, exitOK, "The Polaris tables exist; seeded")
	standalone(t, env, "schema:create", plugins, "--json").want(t, exitOK, `"created": []`)
	standalone(t, env, "schema:diff", plugins).want(t, exitOK, "matches the Polaris schema")
	standalone(t, env, "doctor", plugins).want(t, exitOK, "Polaris is ready.", "plugins: audit, admin, api-keys, oauth, agents, anonymous")

	standalone(t, env, "schema:drop", "--force", plugins, "--json").want(t, exitOK, `"dropped"`)
	standalone(t, env, "schema:drop", "--force", plugins).want(t, exitOK, "Dropped the Polaris tables")
	standalone(t, env, "schema:diff", plugins).want(t, exitFail, "auth_users: table is missing", "polaris migrate")
}

func TestParseDSN(t *testing.T) {
	cases := []struct{ in, dialect, dsn string }{
		{"postgres://u:p@db:5432/app?sslmode=disable", "postgres", "postgres://u:p@db:5432/app?sslmode=disable"},
		{"postgresql://db/app", "postgres", "postgresql://db/app"},
		{"mysql://u:p%40ss@db:3306/app", "mysql", "u:p@ss@tcp(db:3306)/app"},
		{"mysql://u:p@db:3306/app?parseTime=true", "mysql", "u:p@tcp(db:3306)/app?parseTime=true"},
		{"mysql://u:p@tcp(db:3306)/app", "mysql", "u:p@tcp(db:3306)/app"},
		{"sqlite:data/p.db", "sqlite", "file:data/p.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{"sqlite:///abs/p.db", "sqlite", "file:/abs/p.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"},
		{"file:p.db?mode=ro", "sqlite", "file:p.db?mode=ro"},
	}
	for _, c := range cases {
		d, dsn, err := parseDSN(c.in)
		if err != nil || string(d) != c.dialect || dsn != c.dsn {
			t.Errorf("%s: %s %q %v, want %s %q", c.in, d, dsn, err, c.dialect, c.dsn)
		}
	}
	for _, bad := range []string{"", "oracle://x", "mysql://[::1"} {
		if _, _, err := parseDSN(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
