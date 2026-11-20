package sqlstore

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/univeros/polaris.go/store"
)

type shape struct {
	name string
	q    *query
	sql  string
	args []any
}

func TestQueryShapes(t *testing.T) {
	at := time.Date(2026, 6, 7, 12, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	c := store.Criteria{
		"a": "x", "b": nil, "c": []string{"p", "q"}, "d": []int64{}, "e": store.Ne(1),
		"f": store.NotNull(), "g": store.Lt(at), "h": true, "i": []byte("raw"),
	}
	cases := []shape{
		{"select sqlite", selectQuery(store.SQLite, "t", c, store.Query{}),
			`SELECT * FROM "t" WHERE "a" = ? AND "b" IS NULL AND "c" IN (?, ?) AND 1 = 0 AND "e" <> ? AND "f" IS NOT NULL AND "g" < ? AND "h" = ? AND "i" = ?`,
			[]any{"x", "p", "q", 1, "2026-06-07 10:00:00", true, []byte("raw")}},
		{"select postgres numbers placeholders", selectQuery(store.Postgres, "t", store.Criteria{"a": 1, "b": []any{2, 3}}, store.Query{}),
			`SELECT * FROM "t" WHERE "a" = $1 AND "b" IN ($2, $3)`, []any{1, 2, 3}},
		{"select mysql quotes with backticks", selectQuery(store.MySQL, "t", store.Criteria{"a": 1}, store.Query{OrderBy: []store.Order{{Column: "a", Desc: true}, {Column: "b"}}, Limit: 5, Offset: 10}),
			"SELECT * FROM `t` WHERE `a` = ? ORDER BY `a` DESC, `b` ASC LIMIT 5 OFFSET 10", []any{1}},
		{"offset without limit sqlite", selectQuery(store.SQLite, "t", nil, store.Query{Offset: 3}),
			`SELECT * FROM "t" LIMIT -1 OFFSET 3`, nil},
		{"offset without limit mysql", selectQuery(store.MySQL, "t", nil, store.Query{Offset: 3}),
			"SELECT * FROM `t` LIMIT 18446744073709551615 OFFSET 3", nil},
		{"offset without limit postgres", selectQuery(store.Postgres, "t", nil, store.Query{Offset: 3}),
			`SELECT * FROM "t" OFFSET 3`, nil},
		{"count", countQuery(store.Postgres, "t", store.Criteria{"a": 1}), `SELECT COUNT(*) FROM "t" WHERE "a" = $1`, []any{1}},
		{"delete", deleteQuery(store.SQLite, "t", nil), `DELETE FROM "t"`, nil},
		{"quote escapes", deleteQuery(store.SQLite, `we"ird`, nil), `DELETE FROM "we""ird"`, nil},
		{"quote escapes mysql", deleteQuery(store.MySQL, "we`ird", nil), "DELETE FROM `we``ird`", nil},
	}
	ins, err := insertQuery(store.Postgres, "t", store.Row{"b": at, "a": "x"})
	if err != nil {
		t.Fatal(err)
	}
	upd, err := updateQuery(store.Postgres, "t", store.Criteria{"id": "1", "n": store.Lte(3)}, store.Data{"n": store.Increment{By: 2}, "m": "v"})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases,
		shape{"insert", ins, `INSERT INTO "t" ("a", "b") VALUES ($1, $2)`, []any{"x", "2026-06-07 10:00:00"}},
		shape{"update with increment", upd, `UPDATE "t" SET "m" = $1, "n" = "n" + 2 WHERE "id" = $2 AND "n" <= $3`, []any{"v", "1", 3}},
	)
	for _, tc := range cases {
		if got := tc.q.sql.String(); got != tc.sql {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, tc.sql)
		}
		if !reflect.DeepEqual(tc.q.args, tc.args) {
			t.Errorf("%s: args %#v, want %#v", tc.name, tc.q.args, tc.args)
		}
	}
}

func TestWritesWithoutColumnsFail(t *testing.T) {
	if _, err := insertQuery(store.SQLite, "t", store.Row{}); !errors.Is(err, errNoColumns) {
		t.Errorf("insert: %v", err)
	}
	if _, err := updateQuery(store.SQLite, "t", nil, store.Data{}); !errors.Is(err, errNoColumns) {
		t.Errorf("update: %v", err)
	}
}
