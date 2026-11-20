package memstore_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Adapter { return memstore.New(schema.Core()...) })
}

func TestWithoutModelsNothingIsUnique(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	for range 2 {
		if err := s.Insert(ctx, "t", store.Row{"id": "1"}); err != nil {
			t.Fatal(err)
		}
	}
	if n, _ := s.Count(ctx, "t", store.Criteria{"id": "1"}); n != 2 {
		t.Errorf("count = %d, want 2", n)
	}
	if s.Dialect() != store.Memory {
		t.Errorf("dialect = %s", s.Dialect())
	}
}

func TestRowsAreCopies(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	in := store.Row{"id": "1", "name": "a"}
	if err := s.Insert(ctx, "t", in); err != nil {
		t.Fatal(err)
	}
	in["name"] = "changed by caller"
	got, _ := s.FindOne(ctx, "t", nil)
	got["name"] = "changed again"
	if rows := s.Rows("t"); len(rows) != 1 || rows[0]["name"] != "a" {
		t.Errorf("stored rows = %v; callers must not reach them", rows)
	}
}

func TestValuesCompareAcrossTypes(t *testing.T) {
	s := memstore.New()
	ctx := context.Background()
	at := time.Date(2026, 6, 7, 10, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	rows := []store.Row{
		{"id": "1", "n": 10, "flag": true, "at": at},
		{"id": "2", "n": int64(9), "flag": false, "at": "2026-06-07 07:00:00"},
		{"id": "3", "n": nil, "flag": nil, "at": nil},
	}
	for _, r := range rows {
		if err := s.Insert(ctx, "t", r); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		c    store.Criteria
		want int64
	}{
		{store.Criteria{"n": store.Gt(9)}, 1},            // numeric, not lexical: "10" > "9"
		{store.Criteria{"n": "10"}, 1},                   // int and string normalise alike
		{store.Criteria{"n": []any{9, "10"}}, 2},         // IN with mixed types
		{store.Criteria{"flag": true}, 1},                // bools
		{store.Criteria{"at": "2026-06-07 08:00:00"}, 1}, // time normalised to UTC TimeLayout
		{store.Criteria{"at": store.Lt(at)}, 1},          // time against a stored string
		{store.Criteria{"n": store.Ne(nil)}, 0},          // NULL never compares
		{store.Criteria{"missing": nil}, 3},              // absent column is NULL
		{store.Criteria{"n": store.Cond{Op: "~", Value: 1}}, 0},
		{store.Criteria{"n": struct{}{}}, 0},
	}
	for _, tc := range cases {
		if n, err := s.Count(ctx, "t", tc.c); err != nil || n != tc.want {
			t.Errorf("%v: count %d, %v; want %d", tc.c, n, err, tc.want)
		}
	}
	asc, _ := s.FindMany(ctx, "t", nil, store.Query{OrderBy: []store.Order{{Column: "n"}}})
	if asc[0]["id"] != "3" || asc[2]["id"] != "1" {
		t.Errorf("NULL sorts first, then numerically: %v", asc)
	}
	if got, _ := s.FindMany(ctx, "t", nil, store.Query{Offset: 5}); len(got) != 0 {
		t.Errorf("offset past the end = %v", got)
	}
}

func TestTxPanicRollsBackAndRepanics(t *testing.T) {
	s := memstore.New()
	defer func() {
		if recover() == nil {
			t.Error("panic swallowed")
		}
		if rows := s.Rows("t"); len(rows) != 0 {
			t.Errorf("rows after panic = %v", rows)
		}
	}()
	_ = s.Tx(context.Background(), func(ctx context.Context) error {
		_ = s.Insert(ctx, "t", store.Row{"id": "1"})
		panic("boom")
	})
}

func TestTxOfAnotherStoreIsNotJoined(t *testing.T) {
	a, b := memstore.New(), memstore.New()
	abort := errors.New("abort")
	err := a.Tx(context.Background(), func(ctx context.Context) error {
		if err := b.Insert(ctx, "t", store.Row{"id": "1"}); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) || len(b.Rows("t")) != 1 {
		t.Errorf("err = %v, b rows = %v", err, b.Rows("t"))
	}
}

func TestDeleteAppliesForeignKeys(t *testing.T) {
	ctx := context.Background()
	id := schema.StringField("id", 36).AsPrimary()
	parent := schema.Table("parent", id)
	child := schema.Table("child", id, schema.StringField("parentId", 36)).References([]string{"parent_id"}, "parent", []string{"id"})
	grandchild := schema.Table("grandchild", id, schema.StringField("childId", 36)).References([]string{"child_id"}, "child", []string{"id"})
	soft := schema.Table("soft", id, schema.StringField("parentId", 36).AsNullable()).References([]string{"parent_id"}, "parent", []string{"id"}, "SET NULL")
	strict := schema.Table("strict", id, schema.StringField("parentId", 36)).References([]string{"parent_id"}, "parent", []string{"id"}, "RESTRICT")
	tree := schema.Table("tree", id, schema.StringField("parentId", 36).AsNullable()).References([]string{"parent_id"}, "tree", []string{"id"})

	newStore := func(t *testing.T) *memstore.Store {
		s := memstore.New(parent, child, grandchild, soft, strict, tree)
		for table, rows := range map[string][]store.Row{
			"parent":     {{"id": "p1"}, {"id": "p2"}},
			"child":      {{"id": "c1", "parent_id": "p1"}, {"id": "c2", "parent_id": "p2"}},
			"grandchild": {{"id": "g1", "child_id": "c1"}, {"id": "g2", "child_id": "c2"}},
			"soft":       {{"id": "s1", "parent_id": "p1"}, {"id": "s2", "parent_id": "p2"}},
			"tree":       {{"id": "t1", "parent_id": nil}, {"id": "t2", "parent_id": "t1"}, {"id": "t3", "parent_id": "t2"}, {"id": "t4", "parent_id": nil}},
		} {
			for _, r := range rows {
				if err := s.Insert(ctx, table, r); err != nil {
					t.Fatal(err)
				}
			}
		}
		return s
	}
	ids := func(s *memstore.Store, table string) []any {
		var out []any
		for _, r := range s.Rows(table) {
			out = append(out, r["id"], r["parent_id"])
		}
		return out
	}

	t.Run("cascade and set null", func(t *testing.T) {
		s := newStore(t)
		n, err := s.Delete(ctx, "parent", store.Criteria{"id": "p1"})
		if err != nil || n != 1 {
			t.Fatalf("Delete = %d, %v; cascaded rows are not counted", n, err)
		}
		if got := s.Rows("child"); len(got) != 1 || got[0]["id"] != "c2" {
			t.Errorf("child = %v", got)
		}
		if got := s.Rows("grandchild"); len(got) != 1 || got[0]["id"] != "g2" {
			t.Errorf("grandchild = %v; cascades chain", got)
		}
		if got := fmt.Sprint(ids(s, "soft")); got != "[s1 <nil> s2 p2]" {
			t.Errorf("soft = %s", got)
		}
	})
	t.Run("self reference", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.Delete(ctx, "tree", store.Criteria{"id": "t1"}); err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprint(ids(s, "tree")); got != "[t4 <nil>]" {
			t.Errorf("tree = %s", got)
		}
	})
	t.Run("restrict fails the whole delete", func(t *testing.T) {
		s := newStore(t)
		if err := s.Insert(ctx, "strict", store.Row{"id": "x", "parent_id": "p2"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Delete(ctx, "parent", nil); err == nil {
			t.Fatal("restricted delete succeeded")
		}
		if len(s.Rows("parent")) != 2 || len(s.Rows("child")) != 2 || fmt.Sprint(ids(s, "soft")) != "[s1 p1 s2 p2]" {
			t.Error("a failed delete changed rows")
		}
	})
	t.Run("rolled back with the transaction", func(t *testing.T) {
		s := newStore(t)
		abort := errors.New("abort")
		err := s.Tx(ctx, func(ctx context.Context) error {
			if _, err := s.Delete(ctx, "parent", nil); err != nil {
				return err
			}
			return abort
		})
		if !errors.Is(err, abort) || len(s.Rows("child")) != 2 || len(s.Rows("grandchild")) != 2 {
			t.Errorf("err = %v, child = %v", err, s.Rows("child"))
		}
	})
}
