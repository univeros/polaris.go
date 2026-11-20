package identity_test

import (
	"context"
	"fmt"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/session"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/token"
)

// noMFA stands in for the mfa package's login service and session.MFATickets: nobody has a
// second factor, so no ticket is ever minted.
type noMFA struct{}

func (noMFA) ConfirmedFactors(context.Context, string) ([]model.MFAFactor, error) { return nil, nil }
func (noMFA) Issue(string) (string, error)                                        { return "", nil }

type unsigned struct{}

func (unsigned) Issue(token.Claims) (string, error) { return "<access jwt>", nil }

// Register, verify the email from the token the mailer receives, then sign in.
func Example() {
	ctx := context.Background()
	db := memstore.New(schema.Core()...)
	repos := repository.New(db)
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	pepper, _ := security.NewPepper("an application key of at least 32 bytes")

	sessions, _ := session.New(session.Config{
		DB: db, Pepper: pepper, Access: unsigned{}, Principals: session.UserPrincipals{Users: repos.Users},
		Denylist: session.NewDenylist(cache.NewMemory(nil), nil, auth.AccessToken.TTL), Auth: auth,
	})

	var mailbox string // the notification listener's view of user.registered
	bus := &event.Bus{}
	bus.Subscribe(func(_ context.Context, e event.Event) {
		if r, ok := e.(event.UserRegistered); ok {
			mailbox = r.VerificationToken
		}
	})

	svc, err := identity.New(identity.Config{
		DB: db, Hasher: security.Argon2id{}, Pepper: pepper, Sessions: sessions, MFA: noMFA{},
		Tickets: noMFA{}, Authority: authz.NewResolver(repos), Auth: auth, Clock: clock.System{}, Events: bus,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	client := token.ClientContext{IP: "203.0.113.7"}
	_ = svc.Register(ctx, "Ada@Example.com", "correct horse battery staple", "Ada", client)
	_ = svc.VerifyEmail(ctx, mailbox)
	r, err := svc.Login(ctx, "ada@example.com", "correct horse battery staple", client)
	fmt.Println(err, r.Email, r.EmailVerified, r.Tokens.AccessToken)
	// Output: <nil> ada@example.com true <access jwt>
}
