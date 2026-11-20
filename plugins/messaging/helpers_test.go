package messaging_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/messaging"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

var now = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

// boot is upstream's PluginTest::polaris(): core, audit and the plugin in memory, a frozen clock.
func boot(t *testing.T, cfg messaging.Config, edit ...func(*polaris.Config)) (*polaris.Polaris, *messaging.Plugin) {
	t.Helper()
	p, err := start(t, cfg, edit...)
	if err != nil {
		t.Fatal(err)
	}
	return p, messaging.Of(p.Graph())
}

func start(t *testing.T, cfg messaging.Config, edit ...func(*polaris.Config)) (*polaris.Polaris, error) {
	t.Helper()
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	plugin := messaging.New(cfg)
	c := polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(append(append(schema.Core(), audit.Models()...), messaging.Models()...)...),
		Clock:   clock.NewFrozen(now),
		Plugins: []polaris.Plugin{audit.New(audit.Config{}), plugin},
	}
	for _, e := range edit {
		e(&c)
	}
	return polaris.New(c)
}

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sentTemplates reads the messaging.sent audit records, newest first.
func sentTemplates(t *testing.T, p *polaris.Polaris) []audit.Event {
	t.Helper()
	page, err := audit.Of(p.Graph()).Store().Read(context.Background(), audit.Query{Names: []string{messaging.AuditSent}})
	if err != nil {
		t.Fatal(err)
	}
	return page.Events
}

func want(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}
