// Command agents is the agent story end to end in one process: a Polaris server that offers two
// capabilities to AI agents, and an agent, written with the Go agent SDK, that uses them.
//
//   - invoices.list: low risk, run in process by a Go handler (POST /agents/execute). The policy
//     approves it without a person.
//   - invoices.refund: high risk, run at the host's own route POST /api/refunds behind ag.Protect.
//     A person approves it.
//
// The agent enrols through a host token its owner minted, asks for both grants (the refund one with
// a per-call cap and a total budget), waits for the owner's approval, executes, is refused once by
// its constraint and once by its budget, verifies the signed receipt chain, and is finally killed
// with the kill switch. The server keeps running afterwards for the curl walkthrough in README.md.
//
//	POLARIS_DEV=1 go run ./examples/agents           # the owner approves from Go
//	POLARIS_DEV=1 go run ./examples/agents -manual   # you approve with curl (README.md, step 5)
//
// SQLite in a temporary directory; with POLARIS_DEV=1, polaris.DevEnv generates APP_KEY,
// AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER when the environment lacks them. ADDR (default
// localhost:8080) is where it listens.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/agent"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// The owner the demo creates; sign in as them to follow the README.
const (
	ownerEmail    = "ada@example.com"
	ownerPassword = "correct horse battery staple"
)

func main() {
	manual := flag.Bool("manual", false, "leave the high-risk approval to a person (README.md, step 5)")
	flag.Parse()
	ctx := context.Background()
	addr := envOr("ADDR", "localhost:8080")
	baseURL := "http://" + addr
	if err := polaris.DevEnv(baseURL); err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "polaris-agents-")
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	h, p, err := newServer(ctx, db, baseURL)
	if err != nil {
		log.Fatal(err)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr) // listen first: the demo calls the server
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	go func() { log.Fatal(srv.Serve(ln)) }()

	if err := runDemo(ctx, p, baseURL, *manual, os.Stdout); err != nil {
		log.Fatal(err)
	}
	log.Printf("demo done; Polaris keeps serving on %s (sign in as %s / %q)", baseURL, ownerEmail, ownerPassword)
	select {}
}

// newServer is the host: Polaris with audit, admin, oauth and agents, the two capabilities, and
// the host route the high-risk one runs at.
func newServer(ctx context.Context, db store.Adapter, baseURL string, tune ...func(*polaris.Config)) (http.Handler, *polaris.Polaris, error) {
	ag := agents.New(agents.Config{Capabilities: []agents.Capability{
		{
			Name: "invoices.list", Description: "List the organization's invoices",
			Permission: "invoices.read", Risk: agents.RiskLow,
			Handler: func(ctx context.Context, call agents.Call) (any, error) {
				return map[string]any{"organization": call.Agent.OrganizationID, "invoices": invoices}, nil
			},
		},
		{
			Name: "invoices.refund", Description: "Refund part of an invoice",
			Permission: "invoices.refund", Risk: agents.RiskHigh,
			Location: baseURL + "/api/refunds", // the host route below; Protect checks the grant first
			Input: map[string]any{
				"type": "object", "required": []string{"invoice_id", "amount"},
				"properties": map[string]any{
					"invoice_id": map[string]any{"type": "string"},
					"amount":     map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
	}})
	cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{}), ag)
	if err != nil {
		return nil, nil, err
	}
	// The host's own permissions, in the catalog with their descriptions; every organization's
	// owner role holds them, so the owner can approve an agent's grants for them.
	cfg.Permissions = map[string]string{"invoices.read": "Read invoices", "invoices.refund": "Refund invoices"}
	cfg.RolePermissions = map[string][]string{"owner": {"invoices.read", "invoices.refund"}}
	// tune is the tests': a cheap hasher (polaristest.Hasher).
	for _, f := range tune {
		f(&cfg)
	}
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // /auth/*, /orgs/*, /oauth2/*, /agents/*, /.well-known/agent-configuration
	// The grant, its constraints and its budget are checked BEFORE this handler runs; the response
	// gets the X-Polaris-Receipt header.
	mux.Handle("POST /api/refunds", ag.Protect("invoices.refund", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call, _ := agents.CallFrom(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"refunded": call.Arguments["amount"], "invoice": call.Arguments["invoice_id"], "agent": call.Agent.ID,
		})
	})))
	return mux, p, nil
}

// invoices are the host's data the low-risk capability reads.
var invoices = []map[string]any{{"id": "inv_1", "total": 120}, {"id": "inv_2", "total": 80}}

// runDemo plays both sides: the owner (a person, here driven from Go) and the agent (the SDK).
// manual leaves the approval to a person.
func runDemo(ctx context.Context, p *polaris.Polaris, baseURL string, manual bool, out io.Writer) error {
	step := func(format string, args ...any) { fmt.Fprintf(out, "==> "+format+"\n", args...) }

	// 1. The owner: an account and an organization, and a session scoped to it. A real owner signs
	// up and in over HTTP (README), then POST /auth/switch-org scopes the session to the organization.
	owner, err := p.Users().Create(ctx, polaris.NewUser{Email: ownerEmail, Password: ownerPassword, EmailVerified: true})
	if err != nil {
		return err
	}
	org, err := p.Orgs().Create(ctx, owner.ID, "Acme", "")
	if err != nil {
		return err
	}
	session, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: owner.ID, AMR: []string{"pwd"}, OrganizationID: org.ID})
	if err != nil {
		return err
	}
	ownerToken := session.AccessToken
	step("owner %s owns organization %s", owner.Email, org.ID)

	// 2. The owner mints a host enrollment token (peh_…) and hands it to the agent's machine.
	var host struct {
		EnrollmentToken string `json:"enrollment_token"`
	}
	if err := call(ctx, "POST", baseURL+"/agents/hosts", ownerToken, map[string]any{"name": "Billing worker", "organization_id": org.ID}, &host); err != nil {
		return err
	}
	step("owner minted a host enrollment token")

	// 3. The agent: its own key pair (persist key.Export() to keep the identity), then enrolment.
	key, err := agent.GenerateKey(agent.EdDSA)
	if err != nil {
		return err
	}
	a, err := agent.New(ctx, baseURL, agent.WithKey(key))
	if err != nil {
		return err
	}
	bot, enrolled, err := a.Enroll(ctx, host.EnrollmentToken, agent.Registration{Name: "Refund bot", Mode: agent.Delegated})
	if err != nil {
		return err
	}
	step("agent %s enrolled (%s, %s)", bot.ID(), enrolled.Mode, enrolled.Auth)

	// 4. The agent asks for both grants. invoices.list is low risk, so the policy approves it at
	// once (budget: 100 calls). invoices.refund is high risk and waits for a person; the agent
	// proposes its own limits: at most 100 per refund, 100 in total.
	asked, err := bot.RequestGrants(ctx, agent.GrantRequest{
		Reason: "Refund the duplicate charges",
		Capabilities: []agent.CapabilityRequest{
			{Name: "invoices.list"},
			{Name: "invoices.refund", Constraints: map[string]any{
				"amount": map[string]any{"max": 100},
				"budget": map[string]any{"amount": 100, "field": "amount"},
			}},
		},
	})
	if err != nil {
		return err
	}
	for _, g := range asked.Grants {
		step("grant %s: %s", g.Capability, g.Status)
	}

	// 5. The owner approves what waits, and the agent waits for it. With -manual a person approves
	// (the curl in README.md, or your page at asked.Approval.VerificationURIComplete); otherwise
	// the owner approves from Go.
	if asked.Approval != nil {
		step("approval %s waits for the owner (strength %s)", asked.Approval.ID, asked.Approval.Strength)
		if manual {
			step("approve it as %s: README.md, step 5", ownerEmail)
		} else if err := call(ctx, "POST", baseURL+"/agents/approvals/"+asked.Approval.ID+"/decide", ownerToken, map[string]any{"decision": "approve"}, nil); err != nil {
			return err
		}
		grants, err := bot.WaitForApproval(ctx, *asked.Approval) // polls GET /agents/session
		if err != nil {
			return err
		}
		for _, g := range grants {
			step("grant %s: %s", g.Capability, g.Status)
		}
	}

	// 6. Execute the in-process capability: a signed request JWT per call, a receipt per execution.
	res, err := bot.Execute(ctx, "invoices.list", nil)
	if err != nil {
		return err
	}
	step("invoices.list -> %s (receipt #%d)", res.Data, res.Receipt.Seq)

	// 7. Call the host route. 60 passes; 500 breaks the per-refund cap (constraint_violated); the
	// second 60 is more than the 40 left in the budget (budget_exhausted). A refusal never reaches
	// the handler and spends nothing.
	for _, amount := range []int{60, 500, 60} {
		status, answer, err := refund(ctx, bot, baseURL, amount)
		if err != nil {
			return err
		}
		step("refund %d -> %d %s", amount, status, answer)
	}

	// 8. The owner exports the receipt chain; the agent checks every link against the server's
	// published keys (hash, signature, link to the previous one).
	var chain []agent.Receipt
	if err := call(ctx, "GET", baseURL+"/agents/"+bot.ID()+"/receipts", ownerToken, nil, &chain); err != nil {
		return err
	}
	for i, r := range chain {
		var prev *agent.Receipt
		if i > 0 {
			prev = &chain[i-1]
		}
		v, err := bot.VerifyReceipt(ctx, r, prev)
		if err != nil {
			return err
		}
		step("receipt #%d %s %s: valid=%t", r.Seq, deref(r.Capability), r.Outcome, v.Valid)
	}

	// 9. The kill switch: the agent, its OAuth client and its tokens are revoked, the chain sealed.
	if err := call(ctx, "POST", baseURL+"/agents/"+bot.ID()+"/revoke", ownerToken, nil, nil); err != nil {
		return err
	}
	_, err = bot.Execute(ctx, "invoices.list", nil)
	step("after the kill switch: %v", err)
	if err == nil {
		return errors.New("the revoked agent still executes")
	}
	return nil
}

// refund is the agent calling the host route: Do signs the request JWT for that exact URL, method
// and body. It answers the status and the result, or the refusal's problem code.
func refund(ctx context.Context, bot *agent.Agent, baseURL string, amount int) (int, string, error) {
	body, err := json.Marshal(map[string]any{"invoice_id": "inv_1", "amount": amount})
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/refunds", bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := bot.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	var answer map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&answer); err != nil {
		return 0, "", err
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Sprint(answer["error"]), nil
	}
	return resp.StatusCode, fmt.Sprintf("%v (receipt %s)", answer, resp.Header.Get(agents.ReceiptHeader)[:8]+"…"), nil
}

// call sends a JSON request with a bearer token and decodes the envelope's "data" into out (nil:
// ignored). A status of 400 or more is an error carrying the body.
func call(ctx context.Context, method, url, bearer string, body, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("%s %s: %d %s", method, url, resp.StatusCode, raw)
	}
	if out == nil {
		return nil
	}
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	return json.Unmarshal(envelope.Data, out)
}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
