// Command agentauthserver is the server the unmodified @auth/agent client is run against
// (scripts/e2e-agent-auth.sh): Polaris in the Agent Auth Protocol's discovery mode, in memory, on a
// free local port.
//
//	go run ./internal/e2e/agentauthserver                 # serve, for a client by hand
//	go run ./internal/e2e/agentauthserver node client.mjs # run a command with AGENT_AUTH_URL and
//	                                                      # AGENT_AUTH_OWNER (a session) set
package main

import (
	"context"
	"encoding/json"
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
	h, session, err := newServer(ctx, url)
	if err != nil {
		return 0, err
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	if len(command) == 0 {
		log.Printf("serving %s; the owner's access token: %s", url, session)
		return 0, srv.Serve(ln)
	}
	go func() { _ = srv.Serve(ln) }() // ends with Close; a failure shows as the command's
	defer func() { _ = srv.Close() }()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = append(os.Environ(), "AGENT_AUTH_URL="+url, "AGENT_AUTH_OWNER="+session)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	err = cmd.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() > 0 {
		return exit.ExitCode(), nil
	}
	return 0, err
}

// newServer is a Polaris host mounted at url, with a low-risk and a high-risk capability, one at a location of
// the host's own, and the session of a person who owns an organization there.
func newServer(ctx context.Context, url string) (http.Handler, string, error) {
	if err := polaris.DevEnv(url); err != nil {
		return nil, "", err
	}
	ag := agents.New(agents.Config{
		Discovery:    agents.DiscoveryAgentAuth,
		BaseURL:      url,
		ProviderName: "polaris-e2e",
		Description:  "The Agent Auth Protocol interop server",
		Strengths:    map[string]string{agents.RiskHigh: agents.StrengthStepUp}, // the person has no passkey here
		Capabilities: []agents.Capability{
			{Name: "invoices.list", Description: "List the invoices", Permission: "org.read", Risk: agents.RiskLow,
				Handler: func(context.Context, agents.Call) (any, error) { return []string{"inv_1", "inv_2"}, nil }},
			{Name: "invoices.refund", Description: "Refund an invoice", Permission: "org.update", Risk: agents.RiskHigh,
				Input: map[string]any{"type": "object", "required": []string{"invoice_id"}, "properties": map[string]any{"invoice_id": map[string]any{"type": "string"}}},
				Handler: func(_ context.Context, c agents.Call) (any, error) {
					return map[string]any{"refunded": c.Arguments["invoice_id"]}, nil
				}},
			{Name: "invoices.send", Description: "Send an invoice, at the host's own route", Permission: "org.update", Risk: agents.RiskHigh, Location: url + "/api/invoices/send",
				Input: map[string]any{"type": "object", "required": []string{"invoice_id"}, "properties": map[string]any{"invoice_id": map[string]any{"type": "string"}}}},
		},
	})
	cfg, err := polaris.FromEnv(memstore.New(), oauth.New(oauth.Config{BaseURL: url}), ag)
	if err != nil {
		return nil, "", err
	}
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, "", err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, "", err
	}
	owner, err := p.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	if err != nil {
		return nil, "", err
	}
	org, err := p.Orgs().Create(ctx, owner.ID, "Acme", "")
	if err != nil {
		return nil, "", err
	}
	tokens, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: owner.ID, OrganizationID: org.ID})
	if err != nil {
		return nil, "", err
	}
	mux := http.NewServeMux()
	mux.Handle("/", p.Handler())
	mux.Handle("POST /api/invoices/send", ag.Protect("invoices.send", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			InvoiceID string `json:"invoice_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending", "sent": in.InvoiceID}) // a status of its own
	})))
	return mux, tokens.AccessToken, nil
}
