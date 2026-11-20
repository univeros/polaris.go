package observe_test

import (
	"context"
	"fmt"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/observe"
	"github.com/univeros/polaris-go/metrics"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
)

func Example() {
	ctx := context.Background()
	repos := repository.New(memstore.New(schema.Core()...))

	bus := &event.Bus{}
	bus.Subscribe(
		observe.AuditLog(repos.AuditLog, nil, nil),
		observe.Metrics(metrics.NewLog(nil)),
	)
	bus.Dispatch(ctx, event.RoleCreated{OrganizationID: "org-1", RoleID: "role-1", ActorUserID: "user-1"})

	rows, _ := repos.AuditLog.Find(ctx, nil, store.Query{})
	fmt.Println(rows[0].Event, string(rows[0].Metadata))
	// Output: role.created {"role_id":"role-1"}
}
