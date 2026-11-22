package maintenance

import (
	"context"
	"fmt"
	"maps"

	"github.com/univeros/polaris.go/store"
)

// UserRows are the rows of Table whose Column names a user; Where narrows them (owner_type,
// kind).
type UserRows struct {
	Table, Column string
	Where         store.Criteria
}

// EraseUser deletes each UserRows of userID with ctx: what a plugin's wiring.UserEraser does for
// the rows it keeps about a user. It runs inside the transaction that erases the account, so the
// first failure is returned and rolls the erasure back.
func EraseUser(ctx context.Context, db store.Adapter, userID string, rows ...UserRows) error {
	for _, r := range rows {
		c := store.Criteria{r.Column: userID}
		maps.Copy(c, r.Where)
		if _, err := db.Delete(ctx, r.Table, c); err != nil {
			return fmt.Errorf("erase %s: %w", r.Table, err)
		}
	}
	return nil
}
