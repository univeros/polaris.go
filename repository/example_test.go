package repository_test

import (
	"context"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

func Example() {
	ctx := context.Background()
	repos := repository.New(memstore.New(schema.Core()...))
	now := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)

	user := model.User{ID: repository.NewID(), Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	_ = repos.DB.Tx(ctx, func(ctx context.Context) error { return repos.Users.Insert(ctx, user) })

	found, _ := repos.Users.ByEmail(ctx, "ada@example.com")
	locked := found
	locked.Status = model.UserStatusLocked
	_ = repos.Users.Update(ctx, found, locked) // writes only the status column

	again, _ := repos.Users.Get(ctx, user.ID)
	fmt.Println(again.Status)
	// Output: locked
}
