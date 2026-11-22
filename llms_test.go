package polaris_test

// llms.txt is what a coding agent copies, README.md what a person reads first. Every ```go block of
// them is repeated below (imports aside) inside a function the compiler checks, and
// TestLLMSSnippetsCompile fails when a block is edited without its copy here: the guides cannot
// drift from the API.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/agent"
	"github.com/univeros/polaris.go/cli"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/anonymous"
	"github.com/univeros/polaris.go/plugins/apikeys"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/mcp"
	"github.com/univeros/polaris.go/plugins/messaging"
	"github.com/univeros/polaris.go/plugins/multisession"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/plugins/passkey"
	"github.com/univeros/polaris.go/plugins/passwordless"
	"github.com/univeros/polaris.go/plugins/sentinel"
	"github.com/univeros/polaris.go/plugins/social"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/plugins/username"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
	"github.com/univeros/polaris.go/verify"
)

func TestLLMSSnippetsCompile(t *testing.T) {
	self, err := os.ReadFile("llms_test.go")
	if err != nil {
		t.Fatal(err)
	}
	imports := regexp.MustCompile(`(?ms)^import (\(.*?^\)|"[^"]*")$`)
	for _, guide := range []string{"llms.txt", "README.md"} {
		text, err := os.ReadFile(guide)
		if err != nil {
			t.Fatal(err)
		}
		blocks := regexp.MustCompile("(?s)```go\n(.*?)```").FindAllSubmatch(text, -1)
		if len(blocks) == 0 {
			t.Fatalf("no go blocks in %s", guide)
		}
		for _, b := range blocks {
			code := normalize(imports.ReplaceAllString(string(b[1]), ""))
			if !strings.Contains(normalize(string(self)), code) {
				t.Errorf("%s block not copied into llms_test.go:\n%s", guide, b[1])
			}
		}
	}
}

// normalize collapses whitespace runs, so gofmt's alignment does not matter.
func normalize(s string) string { return strings.Join(strings.Fields(s), " ") }

// The identifiers the snippets use without declaring them.
var (
	ctx             = context.Background()
	invoicesHandler http.Handler
	refundHandler   http.Handler
	enrollmentToken string
	listInvoices    func(context.Context, agents.Agent) (any, error)
	deleteProfile   func(context.Context, string) error
	planOf          func(string) string
	legacyRows      []struct {
		Email, PasswordHash, Name string
		Verified, Banned          bool
		CreatedAt                 time.Time
	}
	otherUserID   string
	welcome       func(context.Context, string)
	health        http.Handler
	yourVerifier  sso.DomainVerifier
	home, list    http.Handler
	billing, team http.Handler
	rawToken      string
)

func llmsQuickstart() {
	db, err := sqlstore.Open(ctx, store.Postgres, os.Getenv("DATABASE_URL")) // or store.MySQL, store.SQLite
	cfg, err := polaris.FromEnv(db /*, plugins... */)                        // reads the env vars below
	p, err := polaris.New(cfg)                                               // validates everything; errors say how to fix
	_, err = p.Migrate(ctx)                                                  // creates missing tables, seeds permissions; idempotent

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler())                                            // every Polaris route: /auth/register, /auth/login, /auth/token/refresh, /orgs, ...
	mux.Handle("GET /api/invoices", p.Protect(invoicesHandler, "org.read")) // your route, Polaris principals
	// in the handler: who, ok := polaris.PrincipalFrom(r.Context()) — who.UserID, who.OrganizationID,
	// who.Permissions, who.Kind (polaris.KindUser | KindAPIKey | KindOAuthClient | KindAgent), who.Delegated.
	_ = err
	var r *http.Request
	who, ok := polaris.PrincipalFrom(r.Context())
	_, _, _, _, _ = who.UserID, who.OrganizationID, who.Permissions, who.Delegated, ok
	_ = []polaris.Kind{polaris.KindUser, polaris.KindAPIKey, polaris.KindOAuthClient, polaris.KindAgent}
}

func llmsHooks(cfg polaris.Config, db *sqlstore.Store, mux *http.ServeMux) {
	cfg.Hooks = polaris.Hooks{
		OnUserCreated: func(ctx context.Context, u polaris.User) error { // runs in the account's transaction
			_, err := db.Conn(ctx).ExecContext(ctx, "INSERT INTO profiles (user_id) VALUES ($1)", u.ID) // ? on MySQL and SQLite
			return err
		},
		OnUserDeleted: func(ctx context.Context, userID string) error { return deleteProfile(ctx, userID) },
		Claims: func(ctx context.Context, in polaris.ClaimsInput) (map[string]any, error) {
			return map[string]any{"app_plan": planOf(in.UserID)}, nil // reserved names (sub, org, roles, …) are refused
		},
	}
	cfg.Listeners = []event.Listener{func(ctx context.Context, e event.Event) {
		if r, ok := e.(event.UserRegistered); ok {
			welcome(ctx, r.UserID) // inside db.Tx, only after the commit
		}
	}}
	p, err := polaris.New(cfg)

	var ada polaris.User
	err = db.Tx(ctx, func(ctx context.Context) error { // your transaction: Polaris calls and db.Conn(ctx) join it
		var err error
		if ada, err = p.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true}); err != nil {
			return err
		}
		_, err = db.Conn(ctx).ExecContext(ctx, "UPDATE profiles SET plan = $1 WHERE user_id = $2", "pro", ada.ID)
		return err // an error rolls back the account and its rows, and its events never go out (no mail)
	})
	org, err := p.Orgs().Create(ctx, ada.ID, "Acme", "") // ada is its owner
	err = p.Orgs().AddMember(ctx, org.ID, otherUserID, "member")
	_, inviteToken, err := p.Orgs().Invite(ctx, org.ID, ada.ID, "grace@example.com", "admin")      // deliver it; POST /auth/invites/accept takes it
	tokens, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID, OrganizationID: org.ID}) // your own sign-in, in org; works on Protect
	ok := p.Can(ctx, polaris.Principal{UserID: ada.ID, OrganizationID: org.ID}, "org.read")
	mux.Handle("GET /healthz", p.Wrap(health)) // Config.Middleware around a route Protect does not guard
	// errors: errors.Is(err, polaris.ErrNotFound), polaris.ErrConflict, polaris.ErrForbidden, polaris.ErrEmailNotVerified, polaris.ErrInvalidInput, polaris.ErrInvalidCredentials
	_, _, _ = tokens, ok, inviteToken
	_ = errors.Is(err, polaris.ErrNotFound) || errors.Is(err, polaris.ErrConflict) || errors.Is(err, polaris.ErrForbidden) ||
		errors.Is(err, polaris.ErrEmailNotVerified) || errors.Is(err, polaris.ErrInvalidInput) || errors.Is(err, polaris.ErrInvalidCredentials)
	u, o, sess := p.Users(), p.Orgs(), p.Sessions()
	_, _, _, _, _, _, _, _ = u.Get, u.ByEmail, u.Create, u.Import, u.SetPassword, u.Disable, u.Enable, u.Delete
	_, _, _, _, _, _, _ = o.Create, o.Get, o.ListFor, o.AddMember, o.SetRoles, o.RemoveMember, o.Invite
	_, _, _, _ = sess.Issue, sess.Refresh, sess.Revoke, sess.RevokeAll
	_, _ = cfg.Listeners, cfg.Middleware
	_, _, _ = db.AfterCommit, sqlstore.WithTx, db.Close
	_ = polaris.NewUser{}.EmailVerified
	_ = cfg.Auth.Flows.RequireVerifiedEmail
}

func llmsMigrate(p *polaris.Polaris, db *sqlstore.Store) {
	tx, err := db.DB().BeginTx(ctx, nil)
	for _, row := range legacyRows { // your users table, or an Auth0 / Firebase / Django export
		_, err = p.Users().Import(sqlstore.WithTx(ctx, tx), polaris.ImportedUser{
			Email: row.Email, PasswordHash: row.PasswordHash, DisplayName: row.Name,
			EmailVerified: row.Verified, Disabled: row.Banned, CreatedAt: row.CreatedAt,
		}) // ErrInvalidInput (and security.ErrUnsupportedHash): a hash Polaris cannot verify; ErrConflict: email taken
	}
	err = tx.Commit() // all or nothing; OnUserCreated ran for each account, no email was sent
	_ = errors.Is(err, security.ErrUnsupportedHash)
	_ = security.SupportedHashFormats
	var _ security.HashChecker = security.Argon2id{}
	var memCost, rounds int
	var saltSeparator, signerKey, salt, passwordHash string
	_ = fmt.Sprintf("$firebase-scrypt$ln=%d,r=%d,sep=%s,key=%s$%s$%s", memCost, rounds, saltSeparator, signerKey, salt, passwordHash)
}

func llmsAgents(db store.Adapter, mux *http.ServeMux) {
	ag := agents.New(agents.Config{Capabilities: []agents.Capability{
		{Name: "invoices.list", Description: "List invoices", Permission: "org.read", Risk: agents.RiskLow,
			Handler: func(ctx context.Context, call agents.Call) (any, error) { return listInvoices(ctx, call.Agent) }},
		{Name: "refund", Description: "Refund an invoice", Permission: "billing.refund", Risk: agents.RiskHigh,
			Location: "https://app.example.com/api/refunds",
			Input: map[string]any{"type": "object", "required": []string{"invoice_id"},
				"properties": map[string]any{"invoice_id": map[string]any{"type": "string"}}}},
	}})
	cfg, _ := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{}), ag)
	cfg.Permissions = map[string]string{"billing.refund": "Refund an invoice"} // your own permissions; Migrate seeds them
	cfg.RolePermissions = map[string][]string{"owner": {"billing.refund"}}     // owners hold it, so they can approve it
	p, _ := polaris.New(cfg)
	mux.Handle("/", p.Handler())                                         // includes /.well-known/agent-configuration, /agents/*, /oauth2/*
	mux.Handle("POST /api/refunds", ag.Protect("refund", refundHandler)) // grant, constraints, budget checked BEFORE refundHandler
	// in refundHandler: call, _ := agents.CallFrom(r.Context()); the response gets X-Polaris-Receipt.
	var r *http.Request
	call, _ := agents.CallFrom(r.Context())
	_ = call
}

func llmsAgentSide() {
	key, _ := agent.GenerateKey(agent.EdDSA) // persist key.Export(); reload with agent.ImportKey
	a, _ := agent.New(ctx, "https://app.example.com", agent.WithKey(key))
	bot, _, err := a.Enroll(ctx, enrollmentToken, agent.Registration{Name: "Worker", Mode: agent.Delegated})
	asked, _ := bot.RequestGrants(ctx, agent.GrantRequest{Capabilities: []agent.CapabilityRequest{{Name: "refund"}}})
	if asked.Approval != nil {
		_, err = bot.WaitForApproval(ctx, *asked.Approval)
	} // a person approves
	res, err := bot.Execute(ctx, "invoices.list", nil) // signed request JWT per call; res.Receipt
	// errors: errors.Is(err, agent.ErrCapabilityNotGranted), agent.ErrBudgetExhausted, agent.ErrApprovalDenied …
	_, _, _ = res.Receipt, key.Export, agent.ImportKey
	_ = errors.Is(err, agent.ErrCapabilityNotGranted) || errors.Is(err, agent.ErrBudgetExhausted) || errors.Is(err, agent.ErrApprovalDenied)
}

func llmsProtectMCP(mcpServerHandler http.Handler, mux *http.ServeMux) {
	h, err := mcp.Protect(mcpServerHandler, mcp.ProtectConfig{
		Resource: "https://tools.example.com/mcp",
		Issuer:   "https://auth.example.com",
		JWKSURL:  "https://auth.example.com/auth/.well-known/jwks.json",
		Scopes:   []string{"tools.use"},
	})
	mux.Handle("/", h) // also serves /.well-known/oauth-protected-resource/mcp; mcp.Claims(ctx) in the handler
	_, _ = err, mcp.Claims
}

func llmsMiddleware(p *polaris.Polaris, mux *http.ServeMux) {
	mux.Handle("GET /", p.Authenticate(home))                                                    // anonymous or signed in; a bad or revoked token is still 401
	mux.Handle("GET /api/invoices", p.Require("invoices.read")(list))                            // the same as p.Protect(list, "invoices.read")
	mux.Handle("POST /api/billing", p.Require()(polaris.RequireKind(polaris.KindUser)(billing))) // people only: no API keys, OAuth clients, agents
	mux.Handle("GET /api/team", p.Require()(polaris.RequireOrganization(team)))                  // 403 without an active organization
}

func llmsVerify(mux *http.ServeMux) {
	v, err := verify.New(verify.Config{
		Issuer:  "https://auth.example.com",                            // the Polaris host's AUTH_ISSUER
		JWKSURL: "https://auth.example.com/auth/.well-known/jwks.json", // fetched, cached 1 h, refetched for a new kid
	})
	mux.Handle("GET /invoices", v.Require("invoices.read")(invoicesHandler)) // 401 / 403 / 503 (issuer unreachable)
	// in the handler: c, _ := verify.ClaimsFrom(r.Context()) — c.Subject, c.OrganizationID, c.Scopes, c.All
	claims, err := v.Verify(ctx, rawToken) // a token from elsewhere (WebSocket, queue); errors.Is(err, verify.ErrInvalidToken)
	var r *http.Request
	c, _ := verify.ClaimsFrom(r.Context())
	_, _, _, _ = c.Subject, c.OrganizationID, c.Scopes, c.All
	_, _ = claims, errors.Is(err, verify.ErrInvalidToken)
	_ = verify.Config{Audiences: []string{"https://billing.example.com"}, HTTPClient: http.DefaultClient}
}

func llmsTesting(t *testing.T, cfg polaris.Config) {
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}))) // SQLite in a temp dir, test keys, recorders
	// srv.Handler(), srv.Users(), srv.Sessions(), srv.Mailer.Sent() (verification tokens), srv.SMS, srv.Events.Names()
	// polaristest.WithConfig(func(c *polaris.Config) { c.Hooks = … }) for anything else
	cfg.Hasher = polaristest.Hasher() // tests that build their own polaris.Config: cheap Argon2id, fast under -race
	_, _, _, _, _, _ = srv.Handler(), srv.Users(), srv.Sessions(), srv.Mailer.Sent(), srv.SMS, srv.Events.Names()
	_ = polaristest.WithConfig
}

// llmsInline checks the identifiers llms.txt names outside code blocks.
func llmsInline(p *polaris.Polaris, cfg polaris.Config) {
	_, _, _, _, _, _, _ = cfg.Mailer, cfg.SMS, cfg.Cache, cfg.RateStore, cfg.Events, cfg.Logger, cfg.PathPrefix
	_ = []polaris.Plugin{
		apikeys.New(apikeys.Config{}),
		mcp.New(mcp.Config{BaseURL: "https://app.example.com/auth"}),
		passwordless.New(passwordless.Config{RedirectURIs: []string{"https://app.example.com/welcome"}}),
		username.New(username.Config{}),
		anonymous.New(anonymous.Config{OnConvert: func(ctx context.Context, guestID, userID string) error { return nil }}),
		multisession.New(multisession.Config{}),
		social.New(social.Config{Providers: map[string]social.Provider{"google": {ClientID: "id", ClientSecret: "secret"}}}),
		passkey.New(passkey.Config{RPID: "example.com", Origins: []string{"https://example.com"}}),
		messaging.New(messaging.Config{Email: &messaging.SMTP{Addr: "smtp.example.com:587", From: "noreply@example.com"}, SMS: &messaging.Twilio{}}),
		sentinel.New(sentinel.Config{Mode: sentinel.Enforce}),
		sso.New(sso.Config{HTTPClient: http.DefaultClient, Domains: yourVerifier}),
	}
	_ = polaris.DevEnv("http://localhost:8080")
	_ = []any{event.UserRegistered{}, event.MemberInvited{}}
	os.Exit(cli.Run(ctx, p, os.Args[1:], os.Stdout, os.Stderr))
}

// README.md's blocks that llms.txt does not already hold.
func invoices(w http.ResponseWriter, r *http.Request) {
	who, _ := polaris.PrincipalFrom(r.Context())
	fmt.Fprintf(w, "user %s in organization %s (%s)\n", who.UserID, who.OrganizationID, who.Kind)
}

func readmePlugins(db store.Adapter) {
	cfg, err := polaris.FromEnv(db,
		audit.New(audit.Config{}),
		admin.New(admin.Config{}),
		apikeys.New(apikeys.Config{}),
		passkey.New(passkey.Config{RPID: "example.com", Origins: []string{"https://example.com"}}),
	)
	_, _ = cfg, err
}

var _, _ = invoices, readmePlugins

func readmeQuickstart() {
	db, err := sqlstore.Open(ctx, store.Postgres, os.Getenv("DATABASE_URL"))
	cfg, err := polaris.FromEnv(db) // APP_KEY, AUTH_JWT_*, AUTH_ISSUER; plugins go here too
	p, err := polaris.New(cfg)      // validates everything; every error says how to fix it
	_, err = p.Migrate(ctx)         // creates the missing tables; safe to run on every start

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // /auth/register, /auth/login, /auth/token/refresh, /orgs, …
	mux.Handle("GET /api/invoices", p.Protect(invoicesHandler, "org.read"))
	_ = err
}

func readmeAgents(mux *http.ServeMux) {
	ag := agents.New(agents.Config{Capabilities: []agents.Capability{{
		Name:        "invoices.list",
		Description: "List invoices",
		Permission:  "org.read",
		Risk:        agents.RiskLow, // auto-approved, with a budget
		Handler: func(ctx context.Context, call agents.Call) (any, error) {
			return listInvoices(ctx, call.Agent)
		},
	}, {
		Name:        "refund",
		Description: "Refund an invoice",
		Permission:  "billing.refund",
		Risk:        agents.RiskHigh, // a person approves, with step-up
		Location:    "https://app.example.com/api/refunds",
	}}})

	mux.Handle("POST /api/refunds", ag.Protect("refund", refundHandler))
}

func readmeAgentSDK() {
	key, _ := agent.GenerateKey(agent.EdDSA) // persist key.Export()
	a, _ := agent.New(ctx, "https://app.example.com", agent.WithKey(key))
	bot, _, err := a.Enroll(ctx, enrollmentToken, agent.Registration{Name: "Worker", Mode: agent.Delegated})

	asked, _ := bot.RequestGrants(ctx, agent.GrantRequest{
		Capabilities: []agent.CapabilityRequest{{Name: "refund"}},
	})
	if asked.Approval != nil {
		_, err = bot.WaitForApproval(ctx, *asked.Approval) // a person approves
	}
	res, err := bot.Execute(ctx, "invoices.list", nil) // res.Receipt is the signed receipt
	_, _ = res, err
}

// README.md's testing block, run for real.
func TestSignUp(t *testing.T) {
	srv := polaristest.New(t) // SQLite in a temp dir, test keys, recorded mail and SMS
	req := httptest.NewRequest("POST", "/auth/register",
		strings.NewReader(`{"email": "ada@example.com", "password": "correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || len(srv.Mailer.Sent()) != 1 {
		t.Fatalf("register: %d, %d mails", rec.Code, len(srv.Mailer.Sent()))
	}
}

var _, _, _ = readmeQuickstart, readmeAgents, readmeAgentSDK
