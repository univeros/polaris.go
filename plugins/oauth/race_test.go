package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/store"
)

// A client that rotates back to back does not keep a grant that ends meanwhile: the revocation waits for
// the rotation in flight and ends its successor (PostgreSQL's read committed would miss it).
func TestARotationInFlightDoesNotOutliveARevocation(t *testing.T) {
	ctx := context.Background()
	for name, end := range map[string]func(p *Plugin, c Client, userID string, resp TokenResponse) error{
		"taken back": func(p *Plugin, c Client, userID string, _ TokenResponse) error {
			_, _, err := p.takeBack(ctx, userID, c.ClientID)
			return err
		},
		"reused": func(p *Plugin, c Client, _ string, resp TokenResponse) error {
			_, err := p.tokens.refresh(ctx, resp.RefreshToken, c, "", nil)
			var oe *Error
			if !errors.As(err, &oe) || !oe.reused {
				return errors.New("the reuse was not seen")
			}
			return nil
		},
		"erased": func(p *Plugin, _ Client, userID string, _ TokenResponse) error {
			return p.tokens.hold(ctx, userID, func(ctx context.Context) error { return p.EraseAccess(ctx, userID) })
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, srv := boot(t, Config{})
			if d := p.graph.DB().Dialect(); d != store.Postgres && d != store.MySQL {
				t.Skip("one transaction at a time")
			}
			issued, err := p.CreateClient(ctx, ClientFields{"name": "App", "redirect_uris": []any{"https://app.example/cb"},
				"grant_types": []any{GrantAuthorizationCode, GrantRefreshToken}}, "", "", true)
			must(t, err)
			c := issued.Client
			for round := range 15 {
				user := addUser(t, srv, strings.Repeat("a", round+1)+"@example.com")
				first, err := p.IssueTokens(ctx, c, Grant{UserID: user.ID, Scopes: []string{"offline_access"}})
				must(t, err)
				warm, done := make(chan struct{}), make(chan error, 1)
				go func() {
					secret := first.RefreshToken
					for i := 0; ; i++ {
						next, err := p.tokens.refresh(ctx, secret, c, "", nil)
						if i == 2 {
							close(warm)
						}
						if err != nil || i == 1000 {
							done <- err
							return
						}
						secret = next.RefreshToken
					}
				}()
				<-warm
				must(t, end(p, c, user.ID, first))
				var oe *Error
				if err := <-done; !errors.As(err, &oe) {
					t.Fatalf("round %d: the grant outlived its end: %v", round, err)
				}
				live, err := p.graph.DB().Count(ctx, TableTokens, store.Criteria{"user_id": user.ID, "revoked_at": nil})
				if err != nil || live != 0 {
					t.Fatalf("round %d: %d live tokens %v", round, live, err)
				}
			}
		})
	}
}

// What would issue more tokens goes with the grant: a code and an approved request that were not
// redeemed yet.
func TestTakingAGrantBackEndsWhatWasNotRedeemedYet(t *testing.T) {
	ctx := context.Background()
	p, srv := boot(t, Config{})
	user := addUser(t, srv, "ada@example.com")
	issued, err := p.CreateClient(ctx, ClientFields{"name": "App", "redirect_uris": []any{"https://app.example/cb"},
		"grant_types": []any{GrantAuthorizationCode, GrantRefreshToken}}, "", "", true)
	must(t, err)
	c := issued.Client
	verifier := strings.Repeat("v", 43)
	value, err := p.codes.issue(ctx, c, user.ID, "", pendingRequest{Scopes: []string{"openid"}, RedirectURI: "https://app.example/cb", CodeChallenge: sha256b64(verifier)}, nil)
	must(t, err)
	stored, err := p.codes.consume(ctx, value, c, "", verifier) // a redemption in flight: spent, nothing issued yet
	must(t, err)
	if n, found, err := p.takeBack(ctx, user.ID, c.ClientID); n != 0 || !found || err != nil {
		t.Fatalf("taken back: %d %v %v", n, found, err)
	}
	_, err = p.tokens.issueWhile(ctx, c, Grant{UserID: user.ID, Scopes: stored.Scopes, FamilyID: stored.ID}, p.tokens.stands(TableCodes, stored.ID))
	wantCode(t, err, CodeInvalidGrant, "the redemption")
	if _, found, err := p.takeBack(ctx, user.ID, c.ClientID); found || err != nil {
		t.Fatalf("nothing is left: %v %v", found, err)
	}
}
