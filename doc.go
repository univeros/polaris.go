// Package polaris is embedded authentication for Go services: sign-in (password, MFA, sessions),
// organizations and RBAC, and agent sign-in (API keys, an OAuth 2.1 / OIDC provider, agents, MCP)
// as plugins, self-hosted in the application's database.
//
// An application touches this package only (plus plugin constructors, store/sqlstore and
// polaristest):
//
//	cfg, err := polaris.FromEnv(db, apikeys.New(apikeys.Config{})) // APP_KEY, AUTH_JWT_*, AUTH_ISSUER
//	p, err := polaris.New(cfg)                                     // fails at startup, naming the fix
//	_, err = p.Migrate(ctx)
//	mux.Handle("/", p.Handler())                                   // every Polaris route
//	mux.Handle("GET /api/invoices", p.Protect(h, "invoices.read")) // your routes
//	// in h: who, _ := polaris.PrincipalFrom(r.Context())
//
// Keep your own user data in step with Config.Hooks (OnUserCreated / OnUserDeleted run in the
// account's transaction; Claims adds your claims to access tokens), join your transaction with
// sqlstore.WithTx, and drive accounts, organizations and sessions from Go with Users, Orgs,
// Sessions and Can. Errors match ErrNotFound, ErrConflict, ErrForbidden, ErrInvalidInput and
// ErrInvalidCredentials.
//
// Plugin authors use the plugin SDK: packages wiring (Plugin, the read-only Graph), endpoint,
// manifest, event and token. API.md is the API promise; llms.txt is the one-page
// integration guide.
package polaris
