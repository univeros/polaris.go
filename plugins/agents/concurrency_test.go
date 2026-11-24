package agents

import (
	"context"
	"fmt"
	"github.com/univeros/polaris.go/internal/services"
	"sync"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
	"github.com/univeros/polaris.go/wiring"
)

// bootOn is bootUnit on a fresh database of backend b.
func bootOn(t *testing.T, b storetest.Backend, cfg Config) *Plugin {
	t.Helper()
	ctx := context.Background()
	p := New(cfg)
	plugins := []wiring.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{BaseURL: unitBase}), p}
	var extra [][]schema.Model
	for _, pl := range plugins {
		if sp, ok := pl.(wiring.SchemaProvider); ok {
			extra = append(extra, sp.Schema())
		}
	}
	models, err := schema.Merge(schema.Core(), extra...)
	must(t, err)
	db := b.Open(t, models...)
	auth := config.Defaults()
	auth.Issuer, auth.Audience = contracttest.Issuer, contracttest.Audience
	private, public := contracttest.TestRSAKeyPEM()
	pol, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Plugins: plugins,
		Hasher: security.Argon2id{Memory: 1024, Time: 1, Threads: 1},
	})
	must(t, err)
	must(t, authz.Seed(ctx, db, services.Of(pol.Graph()).Catalog, pol.Graph().Clock()))
	return p
}

// race runs every fn at once and returns their errors.
func race(fns ...func() error) []error {
	errs := make([]error, len(fns))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Go(func() {
			<-start
			errs[i] = fn()
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// Concurrent grant requests of one agent never pass the pending-approval cap, and one capability
// asked concurrently gets one grant.
func TestConcurrentGrantRequestsRespectTheApprovalCap(t *testing.T) {
	var caps []Capability
	for i := range 10 {
		caps = append(caps, unitCapability(fmt.Sprintf("c%d", i), RiskHigh, "deploy.staging"))
	}
	for _, b := range storetest.Backends() {
		t.Run(b.Name, func(t *testing.T) {
			p := bootOn(t, b, Config{Capabilities: caps})
			ctx := context.Background()
			a := newAgent(t, p, nil)
			ask := func(capability string) func() error {
				return func() error {
					_, _, err := p.s.requestGrantsAndApproval(ctx, a, []any{capability}, "", "", "", true, client{})
					return err
				}
			}
			for i := range maxPending - 1 {
				must(t, ask(fmt.Sprintf("c%d", i))())
			}
			ok := 0
			for _, err := range race(ask("c5"), ask("c6"), ask("c7"), ask("c8")) {
				if err == nil {
					ok++
				} else {
					_ = wantType(t, err, ErrConflict, "over the cap")
				}
			}
			if pending, _ := p.s.pendingApprovals(ctx, []Agent{a}); ok != 1 || len(pending) != maxPending {
				t.Fatalf("%d requests passed, %d approvals pending; want 1 and %d", ok, len(pending), maxPending)
			}

			b := newAgent(t, p, nil)
			same := func() error {
				_, _, err := p.s.requestGrantsAndApproval(ctx, b, []any{"c9"}, "", "", "", true, client{})
				return err
			}
			for _, err := range race(same, same, same, same) {
				must(t, err)
			}
			if n, err := p.s.db.Count(ctx, TableGrants, store.Criteria{"agent_id": b.ID}); err != nil || n != 1 {
				t.Fatalf("grants of one capability asked concurrently: %d %v", n, err)
			}
		})
	}
}

// A registration racing its host's revocation finds the host revoked, or its agent is revoked with it.
func TestARegistrationDoesNotOutliveItsHost(t *testing.T) {
	for _, b := range storetest.Backends() {
		t.Run(b.Name, func(t *testing.T) {
			p := bootOn(t, b, Config{Capabilities: unitCaps()})
			ctx := context.Background()
			for round := range 8 {
				h, err := p.s.withKey(Host{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}, newTestKey(AlgEdDSA).jwk(), nil)
				must(t, err)
				h, _, err = p.s.createHost(ctx, h, "Host", nil)
				must(t, err)
				register := func() error {
					_, _, _, err := p.s.registerUnder(ctx, h, map[string]any{"name": "Bot", "jwk": newTestKey(AlgEdDSA).jwk()}, asking{}, client{})
					return err
				}
				revoke := func() error { return p.s.revokeHosts(ctx, store.Criteria{"id": h.ID}) }
				for i, err := range race(register, revoke, register, register) {
					if e, refused := asError(err); err != nil && (i == 1 || !refused || e.Type != ErrHostRevoked) {
						t.Fatalf("round %d, %d: %v", round, i, err)
					}
				}
				left, err := p.s.agentsWhere(ctx, store.Criteria{"host_id": h.ID, "status": StatusActive})
				if err != nil || len(left) != 0 {
					t.Fatalf("round %d: %d agents outlived their host, %v", round, len(left), err)
				}
			}
		})
	}
}

// Deciding a registration and pulling its kill switch at once: the agent ends revoked, or it was
// rejected first; neither waits for the other for good.
func TestADecisionRacesTheKillSwitch(t *testing.T) {
	for _, b := range storetest.Backends() {
		t.Run(b.Name, func(t *testing.T) {
			p := bootOn(t, b, Config{Capabilities: unitCaps()})
			ctx := context.Background()
			for round := range 8 {
				h, err := p.s.withKey(Host{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}, newTestKey(AlgEdDSA).jwk(), nil)
				must(t, err)
				h, _, err = p.s.createHost(ctx, h, "Host", nil)
				must(t, err)
				a, _, approval, err := p.s.registerUnder(ctx, h, map[string]any{"name": "Bot", "jwk": newTestKey(AlgEdDSA).jwk()}, asking{capabilities: []any{"refund"}, method: MethodDevice}, client{})
				if err != nil || a.Status != StatusPending {
					t.Fatalf("%+v %v", a, err)
				}
				decide := func() error { _, _, err := p.s.decide(ctx, *approval, round%2 == 0, "user-1", nil); return err }
				kill := func() error { _, _, err := p.s.revoke(ctx, a, "user-1", "owner", client{}); return err }
				for _, err := range race(decide, kill) {
					if e, refused := asError(err); err != nil && (!refused || e.Type != ErrConflict) {
						t.Fatalf("round %d: %v", round, err)
					}
				}
				got, _, err := p.s.agent(ctx, a.ID)
				if err != nil || got.Status != StatusRevoked && (got.Status != StatusRejected || round%2 == 0) {
					t.Fatalf("round %d: %s %v", round, got.Status, err)
				}
				if live, err := p.s.liveGrants(ctx, a); err != nil || len(live) != 0 {
					t.Fatalf("round %d: %d live grants, %v", round, len(live), err)
				}
			}
		})
	}
}
