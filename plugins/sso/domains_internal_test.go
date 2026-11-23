package sso

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
)

// A claim displaces only a claim that is still unverified when it is deleted, whatever was read.
func TestAClaimDoesNotDisplaceADomainVerifiedSinceItWasRead(t *testing.T) {
	storetest.Each(t, func(t *testing.T, db store.Adapter) {
		ctx := context.Background()
		s := &Domains{db: db, clock: clock.NewFrozen(time.Unix(1_800_000_000, 0))}
		row := store.Row{"id": "p1", "organization_id": "o1", "type": "oidc", "name": "IdP", "issuer": "https://idp", "config": "{}", "attributes": "{}",
			"jit": "{}", "redirect_uris": "[]", "enabled": true, "created_at": s.clock.Now().UTC(), "updated_at": s.clock.Now().UTC()}
		if err := db.Insert(ctx, TableProviders, row); err != nil {
			t.Fatal(err)
		}
		read := Domain{ID: "d1", OrganizationID: "o1", ProviderID: "p1", Domain: "globex.example"}
		if err := db.Insert(ctx, TableDomains, store.Row{"id": read.ID, "organization_id": read.OrganizationID, "provider_id": read.ProviderID,
			"domain": read.Domain, "token": "t", "verified_at": nil, "created_at": s.clock.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MarkVerified(ctx, read); err != nil {
			t.Fatal(err)
		}
		if err := s.displace(ctx, read); err != nil {
			t.Fatal(err)
		}
		if d, ok, err := s.Verified(ctx, "globex.example"); err != nil || !ok || d.ID != read.ID {
			t.Fatalf("the verified domain: %+v %v %v", d, ok, err)
		}
	}, (&Plugin{}).Schema()...)
}
