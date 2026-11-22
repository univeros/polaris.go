package maintenance

import (
	"context"
	"log/slog"
	"maps"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/store"
)

// UserRows are the rows of Table whose Column names a user; Where narrows them (owner_type,
// kind).
type UserRows struct {
	Table, Column string
	Where         store.Criteria
}

// EraseOnUserDeleted is the listener a plugin subscribes to delete what an erased user leaves in
// its tables: on event.UserDeleted it deletes each UserRows of the user. A failure is logged and
// the next table still runs, as every plugin's erasure does.
func EraseOnUserDeleted(db store.Adapter, log *slog.Logger, rows ...UserRows) event.Listener {
	return func(ctx context.Context, e event.Event) {
		d, ok := e.(event.UserDeleted)
		if !ok {
			return
		}
		for _, r := range rows {
			c := store.Criteria{r.Column: d.UserID}
			maps.Copy(c, r.Where)
			if _, err := db.Delete(ctx, r.Table, c); err != nil {
				log.ErrorContext(ctx, "polaris: an erased user's rows were not deleted", "table", r.Table, "user_id", d.UserID, "error", err)
			}
		}
	}
}
