// Command agentauthserver is the server the unmodified @auth/agent client is run against
// (scripts/e2e-agent-auth.sh): Polaris in the Agent Auth Protocol's discovery mode, in memory, on a
// free local port.
//
//	go run ./internal/e2e/agentauthserver                 # serve, for a client by hand
//	go run ./internal/e2e/agentauthserver node client.mjs # run a command with AGENT_AUTH_URL set
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store/memstore"
)

func main() {
	ctx := context.Background()
	if err := os.Setenv("POLARIS_DEV", "1"); err != nil { // the secrets are generated for this run
		log.Fatal(err)
	}
	status, err := run(ctx, os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
	os.Exit(status)
}

// run serves on a free local port: for as long as the command runs, answering its exit status, or
// for good without a command.
func run(ctx context.Context, command []string) (int, error) {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	url := "http://" + ln.Addr().String()
	h, err := newServer(ctx, url)
	if err != nil {
		return 0, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	if len(command) == 0 {
		log.Printf("serving %s", url)
		return 0, srv.Serve(ln)
	}
	go func() { _ = srv.Serve(ln) }() // ends with Close; a failure shows as the command's
	defer func() { _ = srv.Close() }()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = append(os.Environ(), "AGENT_AUTH_URL="+url)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() > 0 {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// newServer is a Polaris host mounted at url, with a low-risk and a high-risk capability.
func newServer(ctx context.Context, url string) (http.Handler, error) {
	if err := polaris.DevEnv(url); err != nil {
		return nil, err
	}
	ag := agents.New(agents.Config{
		Discovery:    agents.DiscoveryAgentAuth,
		BaseURL:      url,
		ProviderName: "polaris-e2e",
		Description:  "The Agent Auth Protocol interop server",
		Capabilities: []agents.Capability{
			{Name: "invoices.list", Description: "List the invoices", Permission: "org.read", Risk: agents.RiskLow,
				Handler: func(context.Context, agents.Call) (any, error) { return []string{"inv_1", "inv_2"}, nil }},
			{Name: "invoices.refund", Description: "Refund an invoice", Permission: "org.update", Risk: agents.RiskHigh,
				Input: map[string]any{"type": "object", "required": []string{"invoice_id"}, "properties": map[string]any{"invoice_id": map[string]any{"type": "string"}}},
				Handler: func(_ context.Context, c agents.Call) (any, error) {
					return map[string]any{"refunded": c.Arguments["invoice_id"]}, nil
				}},
		},
	})
	cfg, err := polaris.FromEnv(memstore.New(), oauth.New(oauth.Config{BaseURL: url}), ag)
	if err != nil {
		return nil, err
	}
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, err
	}
	return p.Handler(), nil
}
