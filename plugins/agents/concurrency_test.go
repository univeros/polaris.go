package agents

import (
	"context"
	"fmt"
	"sync"
	"testing"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/oauth"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/wiring"
)

// bootMemory is bootUnit on memstore instead of SQLite.
func bootMemory(t *testing.T, cfg Config) *Plugin {
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
	db := memstore.New(models...)
	auth := config.Defaults()
	auth.Issuer, auth.Audience = contracttest.Issuer, contracttest.Audience
	private, public := contracttest.TestRSAKeyPEM()
	pol, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Plugins: plugins,
		Hasher: security.Argon2id{Memory: 1024, Time: 1, Threads: 1},
	})
	must(t, err)
	must(t, authz.Seed(ctx, db, pol.Graph().Catalog, pol.Graph().Clock))
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
	backends := map[string]func(t *testing.T) *Plugin{
		"memory": func(t *testing.T) *Plugin { return bootMemory(t, Config{Capabilities: caps}) },
		"sqlite": func(t *testing.T) *Plugin { p, _ := bootUnit(t, Config{Capabilities: caps}); return p },
	}
	for name, boot := range backends {
		t.Run(name, func(t *testing.T) {
			p := boot(t)
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
					wantType(t, err, ErrConflict, "over the cap")
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
