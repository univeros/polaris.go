package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

var sqlTargets = map[string]store.Dialect{"sql:postgres": store.Postgres, "sql:mysql": store.MySQL, "sql:sqlite": store.SQLite}

const remedyDiff = "run `polaris migrate` to create the missing tables; it never alters an existing table, so change mismatched columns and indexes by hand"

func schemaExport(a *app, fs *flag.FlagSet) runFunc {
	target := fs.String("target", "sql:postgres", "sql:postgres | sql:mysql | sql:sqlite")
	drop := fs.Bool("drop", false, "print DROP TABLE statements instead")
	return func(context.Context) (report, error) {
		d, ok := sqlTargets[*target]
		if !ok {
			return report{}, usage(fmt.Sprintf("unknown target %q", *target), "use --target=sql:postgres, sql:mysql or sql:sqlite")
		}
		models, err := a.src.models()
		if err != nil {
			return report{}, err
		}
		build := sqlstore.CreateAll
		if *drop {
			build = sqlstore.DropAll
		}
		statements, err := build(models, d)
		if err != nil {
			return report{}, fail(err.Error(), "two tables reference each other: remove the plugin that adds the cycle")
		}
		return report{text: sqlstore.Script(statements), data: map[string]any{"target": *target, "statements": statements}}, nil
	}
}

func migrate(a *app, _ *flag.FlagSet) runFunc {
	return func(ctx context.Context) (report, error) {
		p, err := a.src.instance(ctx)
		if err != nil {
			return report{}, err
		}
		created, err := p.Migrate(ctx)
		if err != nil {
			return report{}, fail(err.Error(), "check that the database user may create tables; `polaris schema:diff` lists what is missing")
		}
		text := "The Polaris tables exist"
		if len(created) > 0 {
			text = fmt.Sprintf("Created %d table(s): %s", len(created), strings.Join(created, ", "))
		}
		text += "; seeded the permission catalog and the system roles.\n"
		return report{text: text, data: map[string]any{"created": nonNil(created)}}, nil
	}
}

func schemaDiff(a *app, _ *flag.FlagSet) runFunc {
	return func(ctx context.Context) (report, error) {
		db, models, err := a.schemaStore(ctx)
		if err != nil {
			return report{}, err
		}
		diffs, err := db.Diff(ctx, models)
		if err != nil {
			return report{}, fail(err.Error(), "check that the database user may read the catalog (information_schema / PRAGMA)")
		}
		data := map[string]any{"differences": nonNil(diffs)}
		if len(diffs) == 0 {
			return report{text: "The database matches the Polaris schema.\n", data: data}, nil
		}
		var b strings.Builder
		for _, d := range diffs {
			fmt.Fprintf(&b, " - %s\n", d)
		}
		return report{text: b.String(), data: data}, fail(fmt.Sprintf("%d difference(s) between the database and the Polaris schema", len(diffs)), remedyDiff)
	}
}

func schemaDrop(a *app, fs *flag.FlagSet) runFunc {
	force := fs.Bool("force", false, "confirm: every Polaris table and its rows are deleted")
	return func(ctx context.Context) (report, error) {
		if !*force {
			return report{}, usage("schema:drop deletes every Polaris table and its rows", "rerun with --force to confirm")
		}
		db, models, err := a.schemaStore(ctx)
		if err != nil {
			return report{}, err
		}
		if err := db.DropSchema(ctx, models); err != nil {
			return report{}, fail(err.Error(), "check that the database user may drop tables")
		}
		tables := make([]string, 0, len(models))
		for _, m := range models {
			tables = append(tables, m.Table)
		}
		return report{text: fmt.Sprintf("Dropped the Polaris tables (%d).\n", len(tables)), data: map[string]any{"dropped": tables}}, nil
	}
}

func (a *app) schemaStore(ctx context.Context) (*sqlstore.Store, []schema.Model, error) {
	db, err := a.src.database(ctx)
	if err != nil {
		return nil, nil, err
	}
	models, err := a.src.models()
	return db, models, err
}

func manifestCommand(a *app, fs *flag.FlagSet) runFunc {
	format := fs.String("format", "json", "json | openapi")
	return func(context.Context) (report, error) {
		if *format != "json" && *format != "openapi" {
			return report{}, usage(fmt.Sprintf("unknown format %q", *format), "use --format=json or --format=openapi")
		}
		m, err := a.src.manifest()
		if err != nil {
			return report{}, err
		}
		doc := m.Export()
		if *format == "openapi" {
			doc = m.OpenAPI(manifest.UpstreamVersion)
		}
		text, err := phpJSON(doc)
		if err != nil {
			return report{}, fail(err.Error(), "a route spec holds a value JSON cannot encode: fix it")
		}
		return report{text: text, data: doc}, nil
	}
}

// phpJSON encodes v as PHP's json_encode(JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) does, so the
// output is byte-identical to upstream's CLI.
func phpJSON(v any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return unescapeHTML(b.String()), nil
}

var htmlEscapes = map[string]byte{`u003c`: '<', `u003e`: '>', `u0026`: '&'}

// unescapeHTML undoes the \u003c, \u003e and \u0026 escapes json.Marshal applies inside custom
// marshalers (manifest.Object), walking escape pairs so an escaped backslash is never misread.
func unescapeHTML(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		if r, ok := htmlEscapes[s[i+1:min(i+6, len(s))]]; ok {
			b.WriteByte(r)
			i += 5
			continue
		}
		b.WriteString(s[i : i+2])
		i++
	}
	return b.String()
}

// nonNil keeps an empty list a JSON [] rather than null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
