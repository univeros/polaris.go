package sqlstore_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

func Example() {
	ctx := context.Background()
	dir, _ := os.MkdirTemp("", "polaris")
	defer os.RemoveAll(dir)

	s, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer s.DB().Close()

	if err := s.CreateSchema(ctx, schema.Core()); err != nil {
		fmt.Println(err)
		return
	}
	diffs, _ := s.Diff(ctx, schema.Core())
	fmt.Println(len(diffs), "differences")

	_ = s.Insert(ctx, "auth_permissions", store.Row{"id": "p1", "key": "org.manage", "description": "Manage"})
	row, _ := s.FindOne(ctx, "auth_permissions", store.Criteria{"key": "org.manage"})
	fmt.Println(row.String("id"))
	// Output:
	// 0 differences
	// p1
}

func ExampleDDL() {
	ddl, _ := sqlstore.DDL([]schema.Model{
		schema.Table("notes", schema.StringField("id", 36).AsPrimary(), schema.TextField("body")),
	}, store.Postgres)
	fmt.Print(ddl)
	// Output:
	// CREATE TABLE "notes" (
	//     "id" VARCHAR(36) NOT NULL,
	//     "body" TEXT NOT NULL,
	//     PRIMARY KEY ("id")
	// );
}
