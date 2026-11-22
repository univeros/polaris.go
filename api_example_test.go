package polaris_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	polaris "github.com/univeros/polaris.go"
)

// An application route behind Protect: no token is 401, a signed-in user passes, and a
// permission the caller does not hold in its active organization is 403.
func ExamplePolaris_Protect() {
	p, accessToken := signedIn()
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	fmt.Println(get(p.Protect(ok), ""))
	fmt.Println(get(p.Protect(ok), accessToken))
	fmt.Println(get(p.Protect(ok, "invoices.read"), accessToken))
	// Output:
	// 401
	// 200
	// 403
}

// A handler behind Protect, Require or Authenticate reads who is calling from the request
// context.
func ExamplePrincipalFrom() {
	p, accessToken := signedIn()
	me := p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, ok := polaris.PrincipalFrom(r.Context())
		fmt.Println(ok, who.Kind, who.UserID != "", who.OrganizationID == "")
	}))
	get(me, accessToken)
	// Output: true user true true
}

// Can answers a question Protect cannot express, here for a principal outside any request: the
// owner of an organization may update its members, a plain member may not.
func ExamplePolaris_Can() {
	ctx := context.Background()
	p, _ := signedIn()
	if _, err := p.Migrate(ctx); err != nil { // seeds the permission catalog and the system roles
		panic(err)
	}
	owner, _ := p.Users().ByEmail(ctx, "ada@example.com")
	member, _ := p.Users().Create(ctx, polaris.NewUser{Email: "grace@example.com", EmailVerified: true})
	org, _ := p.Orgs().Create(ctx, owner.ID, "Acme", "")
	_ = p.Orgs().AddMember(ctx, org.ID, member.ID, "member")

	fmt.Println(p.Can(ctx, polaris.Principal{UserID: owner.ID, OrganizationID: org.ID}, "members.update"))
	fmt.Println(p.Can(ctx, polaris.Principal{UserID: member.ID, OrganizationID: org.ID}, "members.update"))
	// Output:
	// true
	// false
}

// Organizations from Go, with the rules of the HTTP routes: the last owner cannot be demoted.
func ExamplePolaris_Orgs() {
	ctx := context.Background()
	p, _ := signedIn()
	ada, _ := p.Users().ByEmail(ctx, "ada@example.com")
	org, err := p.Orgs().Create(ctx, ada.ID, "Acme Inc", "")
	if err != nil {
		panic(err)
	}
	fmt.Println(org.Name, org.Slug)

	err = p.Orgs().SetRoles(ctx, org.ID, ada.ID, "member")
	fmt.Println(errors.Is(err, polaris.ErrConflict))
	mine, _ := p.Orgs().ListFor(ctx, ada.ID)
	fmt.Println(len(mine))
	// Output:
	// Acme Inc acme-inc
	// true
	// 1
}

// Sessions for a sign-in the host verified itself (its own SSO, say): issue, refresh with
// rotation, and revoke. A rotated refresh token is spent.
func ExamplePolaris_Sessions() {
	ctx := context.Background()
	p, _ := signedIn()
	ada, _ := p.Users().ByEmail(ctx, "ada@example.com")

	tokens, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID, AMR: []string{"pwd"}})
	if err != nil {
		panic(err)
	}
	next, err := p.Sessions().Refresh(ctx, tokens.RefreshToken)
	fmt.Println(err, next.RefreshToken != tokens.RefreshToken)

	fmt.Println(p.Sessions().Revoke(ctx, next.SessionID))
	_, err = p.Sessions().Refresh(ctx, next.RefreshToken)
	fmt.Println(errors.Is(err, polaris.ErrInvalidCredentials))
	// Output:
	// <nil> true
	// <nil>
	// true
}
