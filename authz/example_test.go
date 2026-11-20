package authz_test

import (
	"context"
	"fmt"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// Seed the catalog once after creating the schema, then ask the Gate per request.
func Example() {
	ctx := context.Background()
	db := memstore.New(schema.Core()...)
	if err := authz.Seed(ctx, db, authz.NewCatalog(map[string]string{"invoices.read": "Read invoices"}), nil); err != nil {
		panic(err)
	}
	gate := authz.NewGate(authz.NewResolver(repository.New(db)))
	err := gate.Authorize(ctx, authz.Caller{UserID: repository.NewID(), OrganizationID: repository.NewID()}, "invoices.read")
	fmt.Println(err)
	// Output: You do not have permission to perform this action.
}
