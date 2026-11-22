package sqlstore_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// notesV1 is a table as an earlier release declared it; notesV2 is the same table one release
// later: two columns, two indexes added, one index retired.
func notesV1() schema.Model {
	return schema.Table("mig_notes",
		schema.StringField("id", 36).AsPrimary(),
		schema.StringField("body", 100),
	).Index([]string{"body"}, "mig_notes_body_index")
}

func notesV2() schema.Model {
	return schema.Table("mig_notes",
		schema.StringField("id", 36).AsPrimary(),
		schema.StringField("body", 100),
		schema.StringField("title", 80).AsNullable(),
		schema.BoolField("pinned").WithDefault(false),
	).Unique([]string{"title"}, "mig_notes_title_unique").
		Index([]string{"pinned"}).
		DropIndex("mig_notes_body_index")
}

func dropTables(t *testing.T, s *sqlstore.Store, models ...schema.Model) {
	t.Helper()
	drop := func() {
		if err := s.DropSchema(context.Background(), models); err != nil {
			t.Fatal(err)
		}
	}
	drop()
	t.Cleanup(drop)
}

func TestMigrateAddsColumnsAndIndexesAndKeepsRows(t *testing.T) {
	for name, newStore := range backends() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			dropTables(t, s, notesV2())
			must(t, s.CreateSchema(ctx, []schema.Model{notesV1()}))
			must(t, s.Insert(ctx, "mig_notes", store.Row{"id": "n1", "body": "kept"}))

			changes, err := s.Migrate(ctx, []schema.Model{notesV2()})
			must(t, err)
			want := []string{
				"mig_notes: added column title",
				"mig_notes: added column pinned",
				"mig_notes: created index mig_notes_title_unique",
				"mig_notes: created index mig_notes_pinned_index",
				"mig_notes: dropped index mig_notes_body_index",
			}
			if !slices.Equal(changes, want) {
				t.Errorf("changes\n%q\nwant\n%q", changes, want)
			}
			row, err := s.FindOne(ctx, "mig_notes", store.Criteria{"id": "n1"})
			must(t, err)
			if row.String("body") != "kept" || row.Bool("pinned") || row["title"] != nil {
				t.Errorf("row after migrate: %v", row)
			}
			if diffs, err := s.Diff(ctx, []schema.Model{notesV2()}); err != nil || len(diffs) != 0 {
				t.Errorf("diff after migrate: %v %v", diffs, err)
			}
			assertSameAsFresh(t, s, newStore(t), notesV2())

			if again, err := s.Migrate(ctx, []schema.Model{notesV2()}); err != nil || len(again) != 0 {
				t.Errorf("second migrate: %v %v; want no change", again, err)
			}
		})
	}
}

func TestMigrateCreatesMissingTablesByName(t *testing.T) {
	for name, newStore := range backends() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			dropTables(t, s, schema.Core()...)
			must(t, s.CreateSchema(ctx, schema.Core()))
			must(t, s.Exec(ctx, "DROP TABLE auth_membership_roles"))
			must(t, s.Exec(ctx, "DROP TABLE auth_memberships"))

			changes, err := s.Migrate(ctx, schema.Core())
			must(t, err)
			if !slices.Equal(changes, []string{"auth_memberships", "auth_membership_roles"}) {
				t.Errorf("changes %v; want the missing tables only, a referenced one first", changes)
			}
			assertNoDiff(t, s)
			assertSameAsFresh(t, s, newStore(t), schema.Core()...)
		})
	}
}

// Replicas booting at once all run Migrate: every one succeeds and the schema is applied once.
func TestMigrateIsSafeOnConcurrentReplicas(t *testing.T) {
	for name, newStore := range backends() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			dropTables(t, s, notesV2())
			must(t, s.CreateSchema(ctx, []schema.Model{notesV1()}))
			var wg sync.WaitGroup
			errs := make([]error, 4)
			for i := range errs {
				wg.Go(func() { _, errs[i] = s.Migrate(ctx, []schema.Model{notesV2()}) })
			}
			wg.Wait()
			must(t, errors.Join(errs...))
			assertSameAsFresh(t, s, newStore(t), notesV2())
		})
	}
}

func TestMigrateRefusesWhatItCannotApplySafely(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		model schema.Model
		want  string
	}{
		{"required column", schema.Table("mig_notes", schema.StringField("id", 36).AsPrimary(), schema.StringField("body", 100),
			schema.StringField("owner", 36)), "mig_notes.owner: a column added to an existing table must be nullable or have a default"},
		{"primary-key column", schema.Table("mig_notes", schema.StringField("id", 36).AsPrimary(), schema.StringField("body", 100),
			schema.StringField("tenant", 36).AsPrimary().WithDefault("t")), "mig_notes.tenant: a column added to an existing table cannot be part of the primary key"},
		{"index dropped and declared", notesV1().DropIndex("mig_notes_body_index"), "mig_notes: index mig_notes_body_index is both declared and dropped"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openSQLite(t)
			must(t, s.CreateSchema(ctx, []schema.Model{notesV1()}))
			changes, err := s.Migrate(ctx, []schema.Model{c.model})
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v; want %q", err, c.want)
			}
			if len(changes) != 0 {
				t.Errorf("changes %v; want none", changes)
			}
		})
	}
}

func TestMigrateNamesTheFixWhenAUniqueIndexMeetsDuplicates(t *testing.T) {
	for name, newStore := range backends() {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			ctx := context.Background()
			dropTables(t, s, notesV1())
			must(t, s.CreateSchema(ctx, []schema.Model{notesV1()}))
			must(t, s.Insert(ctx, "mig_notes", store.Row{"id": "n1", "body": "same"}))
			must(t, s.Insert(ctx, "mig_notes", store.Row{"id": "n2", "body": "same"}))
			unique := notesV1().Unique([]string{"body"}, "mig_notes_body_unique")
			_, err := s.Migrate(ctx, []schema.Model{unique})
			if err == nil || !strings.Contains(err.Error(), "remove the duplicate rows") {
				t.Fatalf("err = %v; want the duplicate-rows remedy", err)
			}
		})
	}
}

// assertSameAsFresh checks every table of models in s matches a fresh install of models in
// fresh: the same columns, primary key and indexes (names included), column order aside.
func assertSameAsFresh(t *testing.T, s, fresh *sqlstore.Store, models ...schema.Model) {
	t.Helper()
	ctx := context.Background()
	t.Cleanup(func() { _ = fresh.DropSchema(context.Background(), models) })
	must(t, fresh.DropSchema(ctx, models))
	must(t, fresh.CreateSchema(ctx, models))
	for _, m := range models {
		got, err := s.Inspect(ctx, m.Table)
		must(t, err)
		want, err := fresh.Inspect(ctx, m.Table)
		must(t, err)
		if g, w := describeLive(got), describeLive(want); g != w {
			t.Errorf("%s differs from a fresh install:\n got %s\nwant %s", m.Table, g, w)
		}
	}
}

func describeLive(t *sqlstore.LiveTable) string {
	if t == nil {
		return "<missing>"
	}
	cols := slices.Clone(t.Columns)
	slices.SortFunc(cols, func(a, b sqlstore.LiveColumn) int { return cmp.Compare(a.Name, b.Name) })
	idx := slices.Clone(t.Indexes)
	slices.SortFunc(idx, func(a, b sqlstore.LiveIndex) int { return cmp.Compare(a.Name, b.Name) })
	return fmt.Sprintf("columns %v primary %v indexes %v", cols, t.Primary, idx)
}
