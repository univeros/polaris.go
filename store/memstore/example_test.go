package memstore_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
)

func Example() {
	ctx := context.Background()
	s := memstore.New(schema.Core()...) // with the schema, unique indexes are enforced

	_ = s.Insert(ctx, "auth_permissions", store.Row{"id": "p1", "key": "org.manage", "description": "Manage"})
	err := s.Insert(ctx, "auth_permissions", store.Row{"id": "p2", "key": "org.manage", "description": "Again"})
	fmt.Println(errors.Is(err, store.ErrDuplicate))

	_ = s.Tx(ctx, func(ctx context.Context) error {
		_ = s.Insert(ctx, "auth_permissions", store.Row{"id": "p3", "key": "org.view", "description": "View"})
		return errors.New("abort") // rolls the insert back
	})
	n, _ := s.Count(ctx, "auth_permissions", nil)
	fmt.Println(n)
	// Output:
	// true
	// 1
}
