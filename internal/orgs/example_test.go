package orgs_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/internal/orgs"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store/memstore"
)

// noSessions stands in for *session.Service, the production orgs.Sessions.
type noSessions struct{}

func (noSessions) RevokeAllForOrganization(context.Context, string, string, string) error { return nil }

func Example() {
	ctx := context.Background()
	db := memstore.New(schema.Core()...)
	_ = authz.Seed(ctx, db, authz.NewCatalog(), nil) // the catalog the role templates are cloned from
	pepper, _ := security.NewPepper("an-application-key-of-32-bytes!!")

	// The invitation token travels once, on member.invited, for the mailer.
	var token string
	bus := &event.Bus{}
	bus.Subscribe(func(_ context.Context, e event.Event) {
		if inv, ok := e.(event.MemberInvited); ok {
			token = inv.InviteToken
		}
	})
	svc, err := orgs.New(orgs.Config{DB: db, Sessions: noSessions{}, Pepper: pepper, Events: bus})
	if err != nil {
		panic(err)
	}

	repos := repository.New(db)
	now := time.Now()
	ada := model.User{ID: repository.NewID(), Email: "ada@example.com", CreatedAt: now, UpdatedAt: now}
	bob := model.User{ID: repository.NewID(), Email: "bob@example.com", CreatedAt: now, UpdatedAt: now}
	_ = repos.Users.Insert(ctx, ada)
	_ = repos.Users.Insert(ctx, bob)

	org, _ := svc.CreateOrganization(ctx, "Acme Inc", "", ada.ID) // ada is the owner
	_, _ = svc.Invite(ctx, ada.ID, org.ID, "Bob@Example.com", []string{authz.RoleMember})
	joined, _ := svc.AcceptInvitation(ctx, bob.ID, token)
	fmt.Println(org.Slug, joined == org.ID)

	// Refusals are values: the last owner cannot leave.
	err = svc.RemoveMember(ctx, ada.ID, org.ID, ada.ID)
	var refusal *orgs.Error
	fmt.Println(errors.Is(err, orgs.ErrConflict), errors.As(err, &refusal) && refusal.Message == orgs.MsgLastOwner)
	// Output:
	// acme-inc true
	// true true
}
