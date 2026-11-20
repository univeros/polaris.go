// Command agentserver boots the Go Polaris the way upstream's Slim demo (examples/slim) is set up,
// so the TypeScript agent SDK's walkthrough (packages/agent-ts/e2e/walkthrough.e2e.ts) runs against
// it: SQLite in a temp dir, the contract-test keys, plugins audit, admin, oauth, mcp and agents with
// the demo's one capability (demo.echo, low risk, members.read, auto-approved with a budget of 100),
// and a file mailbox writing one JSON line per email ({"to","template","context"}) as the demo's
// FileMailer does, where the walkthrough reads the verification token.
//
// It prints POLARIS_URL=<base url> and POLARIS_MAIL_LOG=<path> on stdout once listening, then
// serves until killed. scripts/e2e-agent-ts.sh drives it.
//
//	go run ./internal/e2e/agentserver -addr 127.0.0.1:0 -mail /path/to/examples/slim/var/mail.log
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/agents"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/mcp"
	"github.com/univeros/polaris-go/plugins/oauth"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address (port 0 picks a free one)")
	mail := flag.String("mail", "", "mail log file (default: mail.log in the temp dir)")
	flag.Parse()
	if err := run(*addr, *mail); err != nil {
		log.Fatal(err)
	}
}

func run(addr, mailLog string) error {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "polaris-agentserver-")
	if err != nil {
		return err
	}
	if mailLog == "" {
		mailLog = filepath.Join(dir, "mail.log")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	baseURL := "http://" + ln.Addr().String()

	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)")
	if err != nil {
		return err
	}
	auth := config.Defaults()
	auth.Issuer = baseURL
	private, public := contracttest.TestRSAKeyPEM()
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      db,
		Mailer:  &fileMailer{path: mailLog},
		Plugins: []polaris.Plugin{
			audit.New(audit.Config{}),
			admin.New(admin.Config{}),
			oauth.New(oauth.Config{BaseURL: baseURL, Audiences: []string{baseURL + "/mcp"}}),
			mcp.New(mcp.Config{BaseURL: baseURL, ServerName: "Polaris demo"}),
			agents.New(agents.Config{
				BaseURL:      baseURL,
				ProviderName: "Polaris demo",
				Description:  "The Slim demo of Polaris for PHP",
				Capabilities: []agents.Capability{{
					Name:        "demo.echo",
					Description: "Echo the arguments back",
					Input:       map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string"}}, "additionalProperties": false},
					Permission:  "members.read",
					Risk:        agents.RiskLow,
					Handler: func(_ context.Context, call agents.Call) (any, error) {
						return map[string]any{"echo": call.Arguments}, nil
					},
				}},
			}),
		},
	})
	if err != nil {
		return err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return err
	}
	fmt.Printf("POLARIS_URL=%s\nPOLARIS_MAIL_LOG=%s\n", baseURL, mailLog)
	return http.Serve(ln, p.Handler())
}

// fileMailer is the demo's FileMailer: every email is one JSON line appended to path.
type fileMailer struct {
	mu   sync.Mutex
	path string
}

func (m *fileMailer) Send(_ context.Context, to, template string, data map[string]any) error {
	line, err := json.Marshal(map[string]any{"to": to, "template": template, "context": data})
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := os.OpenFile(m.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
