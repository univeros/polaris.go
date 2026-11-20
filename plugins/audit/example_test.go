package audit_test

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"strings"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// The audit plugin records every Polaris event; GET /audit/me, /audit/organization/{id} and
// /audit/types read it. An application emits its own events with Record.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"

	trail := audit.New(audit.Config{
		Retention: audit.Retention{Default: "P90D", Names: map[string]string{audit.UserDeleted: "P7Y"}},
		HashChain: true,
		Sinks:     []audit.Sink{audit.LogSink{Logger: slog.New(slog.DiscardHandler)}},
		Names:     map[string]string{"billing.invoice_paid": "An invoice was paid"},
	})
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(append(schema.Core(), audit.Models()...)...), // sqlstore.Open(...) in production
		Plugins: []polaris.Plugin{trail},
	})
	if err != nil {
		log.Fatal(err)
	}
	_ = p.Handler() // mount it: mux.Handle("/", p.Handler())

	ctx := context.Background()
	p.Graph().Events().Dispatch(ctx, event.UserRegistered{UserID: "u1", Email: "ada@example.com"})
	_ = trail.Record(ctx, audit.Event{Name: "billing.invoice_paid", ActorType: audit.ActorUser, ActorID: "u1",
		Data: map[string]any{"invoice": "inv-1", "card_token": "tok_x"}})

	page, _ := trail.Store().Read(ctx, audit.Query{PrincipalID: "u1"})
	for _, e := range page.Events {
		fmt.Println(e.Name, e.Data)
	}
	report, _ := trail.Verify(ctx)
	fmt.Println("chain intact:", report.Intact())
	// Output:
	// billing.invoice_paid map[card_token:[redacted] invoice:inv-1]
	// user.signed_up map[email:ada@example.com]
	// chain intact: true
}
