package messaging_test

import (
	"context"
	"fmt"
	"log"
	"strings"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/messaging"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// Register the plugin with Config.Mailer and Config.SMS left nil: core's verification, reset and
// code messages are rendered from its templates and sent through its channels. In production the
// channels are messaging.SMTP and messaging.Twilio (or Vonage, or any API through HTTPSMS).
func Example() {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	outbox := messaging.NewMemory("mail", messaging.KindEmail) // in production: &messaging.SMTP{...}

	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(append(append(schema.Core(), audit.Models()...), messaging.Models()...)...),
		Plugins: []polaris.Plugin{audit.New(audit.Config{}), messaging.New(messaging.Config{
			Email:     outbox,
			Templates: map[string]map[string]messaging.Template{"en": {"email.verify": {Subject: "Welcome to Acme", Text: "Your token: {token}"}}},
		})},
	})
	if err != nil {
		log.Fatal(err)
	}

	// What core's notification listener does after a sign-up.
	p.Graph().Events().Dispatch(context.Background(), event.UserRegistered{UserID: "u1", Email: "ada@example.com", VerificationToken: "tok-1"})
	sent := outbox.Messages()[0]
	fmt.Println(sent.Template, "|", sent.Subject, "|", sent.Text)
	// Output: email.verify | Welcome to Acme | Your token: tok-1
}
