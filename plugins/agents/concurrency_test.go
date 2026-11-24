package agents

import (
	"context"
	"errors"
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
				decide := func() error { _, _, err := p.s.decide(ctx, *approval, round%2 == 0, "user-1", nil, nil); return err }
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

// waitingRegistration is a registration of the unknown host with key host, and the approval it waits for.
func waitingRegistration(t *testing.T, p *Plugin, host *testKey, capabilities ...any) (registration, Approval) {
	t.Helper()
	r, _, ap, err := p.s.register(context.Background(), unknownRegistration(t, host, newTestKey(AlgEdDSA)), asking{capabilities: capabilities}, client{})
	must(t, err)
	return r, ap
}

func unknownRegistration(t *testing.T, host, agent *testKey) registration {
	t.Helper()
	thumb := func(k *testKey) string {
		s, err := thumbprintOf(k.jwk())
		must(t, err)
		return s
	}
	return registration{HostThumbprint: thumb(host), HostJWK: host.jwk(), HostName: "Laptop", AgentThumbprint: thumb(agent), AgentJWK: agent.jwk(), Name: "Bot", Mode: ModeDelegated}
}

// decidedBy is the registration as the person deciding it would own it.
func decidedBy(r registration, user string) *registration {
	r.becomes = r.agentFor(nil, user, "")
	return &r
}

// One registration of one host and agent key, however often it is asked for at once (§5.3).
func TestConcurrentRegistrationsAreOne(t *testing.T) {
	for _, b := range storetest.Backends() {
		t.Run(b.Name, func(t *testing.T) {
			p := bootOn(t, b, Config{Capabilities: unitCaps(), Discovery: DiscoveryAgentAuth})
			ctx := context.Background()
			for range 4 {
				host, agent := newTestKey(AlgEdDSA), newTestKey(AlgEdDSA)
				ask := func() error {
					_, _, _, err := p.s.register(ctx, unknownRegistration(t, host, agent), asking{capabilities: []any{"refund"}}, client{})
					return err
				}
				stored := 0
				for _, err := range race(ask, ask, ask, ask) {
					if err == nil {
						stored++
					} else if !errors.Is(err, store.ErrDuplicate) {
						t.Fatal(err)
					}
				}
				r, ok, err := p.s.registrationOf(ctx, unknownRegistration(t, host, agent).HostThumbprint, unknownRegistration(t, host, agent).AgentThumbprint)
				if err != nil || !ok || stored != 1 {
					t.Fatalf("%d stored, %v %v", stored, ok, err)
				}
				grants, _, err := p.s.retried(ctx, r, "")
				if err != nil || len(grants) != 1 {
					t.Fatalf("%v %v", grants, err)
				}
				// Nor does an expired approval open twice.
				if _, err := p.s.db.Update(ctx, TableApprovals, store.Criteria{"agent_id": r.ID}, store.Data{"expires_at": p.s.now().Add(-1)}); err != nil {
					t.Fatal(err)
				}
				again := func() error { _, _, err := p.s.retried(ctx, r, ""); return err }
				for _, err := range race(again, again, again) {
					must(t, err)
				}
				if open, err := p.s.pendingApprovals(ctx, []Agent{r.agent()}); err != nil || len(open) != 1 {
					t.Fatalf("%d approvals, %v", len(open), err)
				}
			}
		})
	}
}

// §2.9: two people approving two registrations of one unknown host at once: the host is one's, and the
// other's registration is as it was.
func TestAnUnknownHostIsLinkedOnce(t *testing.T) {
	for _, b := range storetest.Backends() {
		t.Run(b.Name, func(t *testing.T) {
			p := bootOn(t, b, Config{Capabilities: unitCaps(), Discovery: DiscoveryAgentAuth})
			ctx := context.Background()
			for round := range 8 {
				host := newTestKey(AlgEdDSA)
				first, firstAp := waitingRegistration(t, p, host, "refund")
				second, secondAp := waitingRegistration(t, p, host, "deploy")
				if first.HostID != second.HostID {
					t.Fatal("one host, two ids")
				}
				by := func(r registration, ap Approval, user string) func() error {
					return func() error { _, _, err := p.s.decide(ctx, ap, true, user, nil, decidedBy(r, user)); return err }
				}
				approved := 0
				for _, err := range race(by(first, firstAp, "user-1"), by(second, secondAp, "user-2")) {
					if err == nil {
						approved++
					} else if e, refused := asError(err); !refused || e.Type != ErrConflict {
						t.Fatalf("round %d: %v", round, err)
					}
				}
				h, err := p.s.registeredHost(ctx, first)
				if err != nil || h == nil || approved != 1 {
					t.Fatalf("round %d: %d approved, %+v %v", round, approved, h, err)
				}
				agents, err := p.s.agentsWhere(ctx, store.Criteria{"host_id": h.ID})
				if err != nil || len(agents) != 1 || agents[0].OwnerID != h.OwnerID {
					t.Fatalf("round %d: %+v %v", round, agents, err)
				}
				left, err := p.s.db.Count(ctx, TableRegistrations, store.Criteria{"host_thumbprint": first.HostThumbprint, "status": StatusPending})
				if err != nil || left != 1 {
					t.Fatalf("round %d: %d left, %v", round, left, err)
				}
			}
		})
	}
}

// A registration is decided once, and one approved while its host is revoked leaves no agent acting.
func TestARegistrationIsDecidedOnce(t *testing.T) {
	for _, b := range storetest.Backends() {
		t.Run(b.Name, func(t *testing.T) {
			p := bootOn(t, b, Config{Capabilities: unitCaps(), Discovery: DiscoveryAgentAuth})
			ctx := context.Background()
			for round := range 6 {
				host := newTestKey(AlgEdDSA)
				r, ap := waitingRegistration(t, p, host, "refund")
				decide := func(approve bool) func() error {
					return func() error {
						_, _, err := p.s.decide(ctx, ap, approve, "user-1", nil, decidedBy(r, "user-1"))
						return err
					}
				}
				won := 0
				for _, err := range race(decide(true), decide(false), decide(true)) {
					if err == nil {
						won++
					} else if e, refused := asError(err); !refused || e.Type != ErrConflict {
						t.Fatalf("round %d: %v", round, err)
					}
				}
				a, exists, err := p.s.agent(ctx, r.ID)
				left, waits, err2 := p.s.registration(ctx, r.ID)
				if err != nil || err2 != nil || won != 1 || exists == waits || (waits && left.Status != StatusRejected) || (exists && a.Status != StatusActive) {
					t.Fatalf("round %d: %d decided, agent %v, registration %v, %v %v", round, won, exists, waits, err, err2)
				}
				if !exists {
					continue
				}
				h, err := p.s.registeredHost(ctx, r)
				must(t, err)
				second, secondAp := waitingRegistration(t, p, host, "refund")
				second.becomes = second.agentFor(h, "user-1", "")
				for _, err := range race(func() error { _, _, err := p.s.decide(ctx, secondAp, true, "user-1", nil, &second); return err },
					func() error { return p.s.revokeHosts(ctx, store.Criteria{"id": h.ID}) }) {
					if e, refused := asError(err); err != nil && (!refused || e.Type != ErrHostRevoked) {
						t.Fatalf("round %d: %v", round, err)
					}
				}
				if live, err := p.s.agentsWhere(ctx, store.Criteria{"host_id": h.ID, "status": StatusActive}); err != nil || len(live) != 0 {
					t.Fatalf("round %d: %d agents outlived their host, %v", round, len(live), err)
				}
			}
		})
	}
}
