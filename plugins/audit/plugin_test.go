package audit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	ctx := context.Background()
	spy := audit.SinkFunc(func(context.Context, ...audit.Event) error { return nil })
	var seen []string
	recording := audit.SinkFunc(func(_ context.Context, events ...audit.Event) error {
		for _, e := range events {
			seen = append(seen, e.Name)
		}
		return nil
	})
	p := audit.New(audit.Config{
		Retention: audit.Retention{Default: "P30D"}, HashChain: true, Sinks: []audit.Sink{spy, recording},
		Names: map[string]string{"billing.invoice_paid": "An invoice was paid"}, ActivityInterval: time.Minute,
	})
	srv := polaristest.New(t, polaristest.WithPlugins(p))
	g := srv.Graph()

	if audit.Of(g) != p || len(g.Schema()) != len(schema.Core())+3 {
		t.Fatalf("plugin or schema (%d tables)", len(g.Schema()))
	}
	for _, name := range []string{audit.RouteMe, audit.RouteOrganization, audit.RouteTypes} {
		found := false
		for _, r := range g.Manifest().Routes() {
			found = found || (r.Name == name && r.Plugin == audit.ID)
		}
		if !found {
			t.Errorf("route %s missing", name)
		}
	}
	if !p.Catalog().Has("billing.invoice_paid") || len(g.Listeners()) != 6 {
		t.Fatalf("catalog or listeners (%d): core's three, the recorder, the activity tracker, the activity erasure", len(g.Listeners()))
	}

	srv.Events.Dispatch(ctx, event.UserRegistered{UserID: "u1", Email: "ada@example.com", VerificationToken: "tok"})
	srv.Events.Dispatch(ctx, event.UserLoggedIn{UserID: "u1", SessionID: "s1", AMR: []string{"pwd"}})
	if strings.Join(seen, ",") != audit.UserSignedUp+","+audit.SessionSignedIn {
		t.Fatalf("sinks saw %v", seen)
	}
	page, err := p.Store().Read(ctx, audit.Query{})
	if err != nil || len(page.Events) != 2 || page.Events[0].Hash == "" {
		t.Fatalf("stored %+v %v: the chain is on", page, err)
	}
	if _, ok, _ := p.Activity().LastActiveAt(ctx, "u1"); !ok {
		t.Fatal("no activity")
	}
	if err := p.Record(ctx, audit.Event{Name: "billing.invoice_paid", ActorID: "u1", ActorType: audit.ActorUser}); err != nil {
		t.Fatal(err)
	}
	if report, err := p.Verify(ctx); err != nil || report.Rows != 3 || !report.Intact() {
		t.Fatalf("verify %+v %v", report, err)
	}
	if n, err := p.Prune(ctx); err != nil || n != 0 {
		t.Fatalf("nothing is older than 30 days: %d %v", n, err)
	}
	if p.Drains() == nil {
		t.Fatal("no drains service")
	}
}

func TestABadConfigurationFailsAtStartup(t *testing.T) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	for _, cfg := range []audit.Config{
		{Retention: audit.Retention{Default: "ninety days"}},
		{Names: map[string]string{"Bad Name": "x"}},
	} {
		_, err := polaris.New(polaris.Config{
			Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
			Auth:    auth, DB: memstore.New(), Plugins: []polaris.Plugin{audit.New(cfg)},
		})
		if err == nil || !strings.Contains(err.Error(), `plugin "audit"`) {
			t.Errorf("%+v: %v", cfg, err)
		}
	}
}
