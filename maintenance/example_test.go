package maintenance_test

import (
	"context"
	"fmt"
	"time"

	"github.com/univeros/polaris-go/maintenance"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

func ExamplePruneExpired() {
	db := memstore.New(schema.Core()...)
	// Run it from a scheduler; 0 keeps refresh tokens for maintenance.DefaultRefreshGrace.
	deleted, err := maintenance.PruneExpired(context.Background(), db, time.Now(), 0)
	fmt.Println(deleted["auth_refresh_tokens"], err)
	// Output: 0 <nil>
}
