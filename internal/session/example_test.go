package session_test

import (
	"context"
	"fmt"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/session"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
)

// fakeIssuer stands in for the access-token *token.Codec.
type fakeIssuer struct{}

func (fakeIssuer) Issue(token.Claims) (string, error) { return "access.jwt", nil }

// Open a session at login, then rotate its refresh token.
func Example() {
	ctx := context.Background()
	db := memstore.New(schema.Core()...)
	auth := config.Defaults()
	pepper, _ := security.NewPepper("an-application-key-of-32-bytes-min")
	sessions, err := session.New(session.Config{
		DB: db, Pepper: pepper, Access: fakeIssuer{}, Auth: auth,
		Principals: session.UserPrincipals{Users: repository.New(db).Users},
		Denylist:   session.NewDenylist(cache.NewMemory(nil), nil, auth.AccessToken.TTL),
	})
	if err != nil {
		panic(err)
	}
	ada := model.User{ID: repository.NewID(), Email: "ada@example.com"}
	if err := repository.New(db).Users.Insert(ctx, ada); err != nil {
		panic(err)
	}
	issued, _ := sessions.Issue(ctx, token.SessionPrincipal{UserID: ada.ID}, token.ClientContext{IP: "203.0.113.7"})
	rotated, _ := sessions.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
	_, err = sessions.Refresh(ctx, issued.RefreshToken, token.ClientContext{}) // replayed: the family is revoked
	fmt.Println(rotated.SessionID == issued.SessionID, err)
	// Output: true session: invalid grant: refresh token already used
}
