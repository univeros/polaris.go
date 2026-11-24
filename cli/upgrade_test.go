package cli

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/plugins/passkey"
	"github.com/univeros/polaris.go/plugins/social"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
	"github.com/univeros/polaris.go/store/storetest"
	"github.com/univeros/polaris.go/wiring"
)

var update = flag.Bool("update", false, "rewrite the plugin DDL goldens in testdata/ddl")

// releases are the tags whose schema the upgrade test starts from: testdata/upgrade/<tag>.<dialect>.sql
// is `polaris schema:export --target=sql:<dialect> --plugins=<every plugin>` run at that tag.
// Add the previous tag here when a release changes the schema.
var releases = []string{"v0.4.1", "v0.5.0", "v0.6.0", "v1.0.0"}

var sqlDialects = []store.Dialect{store.Postgres, store.MySQL, store.SQLite}

// pluginModels returns each standard plugin that declares tables, with its tables.
func pluginModels() map[string][]schema.Model {
	out := map[string][]schema.Model{}
	for _, p := range standardPlugins() {
		if sp, ok := p.build(&source{}).(wiring.SchemaProvider); ok {
			out[p.name] = sp.Schema()
		}
	}
	// Not standard plugins (they need a relying party or providers), but their tables are stored
	// data all the same.
	out["passkey"], out["social"] = passkey.Models(), social.Models()
	return out
}

// Each plugin's tables are pinned per dialect, as core's are: testdata/ddl/<plugin>.<dialect>.sql
// holds its CREATE statements in declaration order. A change to a plugin's schema changes its
// golden (go test ./cli -run TestPluginDDLGoldens -update) and needs Migrate to reach it from the
// released schema (TestMigrateUpgradesEveryReleasedSchema).
func TestPluginDDLGoldens(t *testing.T) {
	for name, models := range pluginModels() {
		for _, d := range sqlDialects {
			t.Run(name+"."+string(d), func(t *testing.T) {
				var statements []string
				for _, m := range models {
					s, err := sqlstore.CreateTable(m, d)
					if err != nil {
						t.Fatal(err)
					}
					statements = append(statements, s...)
				}
				got := sqlstore.Script(statements)
				path := filepath.Join("..", "testdata", "ddl", name+"."+string(d)+".sql")
				if *update {
					if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				if want := readFile(t, path); got != want {
					t.Errorf("%s differs from the schema the plugin declares; if the change is deliberate, rerun with -update and make sure Migrate reaches it", path)
				}
			})
		}
	}
}

// A database created by a released version (every plugin enabled) reaches, through Migrate at
// HEAD, exactly what a fresh install creates: same tables, columns, primary keys and indexes.
// It runs on SQLite in `make qa` and on PostgreSQL and MySQL in the database matrix.
func TestMigrateUpgradesEveryReleasedSchema(t *testing.T) {
	cleanEnv(t)
	models, err := (&source{pluginNames: strings.Join(pluginNames(), ",")}).models()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, b := range storetest.Backends() {
		if b.Dialect == store.Memory {
			continue
		}
		for _, release := range releases {
			t.Run(b.Name+"/"+release, func(t *testing.T) {
				old := storetest.OpenSQL(t, b.Dialect)
				script := golden(t, "upgrade", release+"."+string(b.Dialect)+".sql")
				for _, statement := range strings.Split(strings.TrimSuffix(script, ";\n"), ";\n\n") {
					if err := old.Exec(ctx, statement); err != nil {
						t.Fatalf("%s schema: %v\n%s", release, err, statement)
					}
				}
				changes, err := old.Migrate(ctx, models)
				if err != nil {
					t.Fatalf("migrate from %s: %v (after %v)", release, err, changes)
				}
				t.Logf("migrate from %s: %v", release, changes)
				if diffs, err := old.Diff(ctx, models); err != nil || len(diffs) != 0 {
					t.Errorf("diff after migrating from %s: %v %v", release, diffs, err)
				}
				fresh := storetest.OpenSQL(t, b.Dialect)
				if err := fresh.CreateSchema(ctx, models); err != nil {
					t.Fatal(err)
				}
				for _, m := range models {
					if got, want := liveSchema(t, old, m.Table), liveSchema(t, fresh, m.Table); got != want {
						t.Errorf("%s upgraded from %s differs from a fresh install:\n got %s\nwant %s", m.Table, release, got, want)
					}
				}
				if again, err := old.Migrate(ctx, models); err != nil || len(again) != 0 {
					t.Errorf("second migrate: %v %v; want no change", again, err)
				}
			})
		}
	}
}

// liveSchema describes a live table independently of column order.
func liveSchema(t *testing.T, s *sqlstore.Store, table string) string {
	t.Helper()
	live, err := s.Inspect(context.Background(), table)
	if err != nil {
		t.Fatal(err)
	}
	if live == nil {
		return "<missing>"
	}
	cols := slices.Clone(live.Columns)
	slices.SortFunc(cols, func(a, b sqlstore.LiveColumn) int { return cmp.Compare(a.Name, b.Name) })
	idx := slices.Clone(live.Indexes)
	slices.SortFunc(idx, func(a, b sqlstore.LiveIndex) int { return cmp.Compare(a.Name, b.Name) })
	return fmt.Sprintf("columns %v primary %v indexes %v", cols, live.Primary, idx)
}
