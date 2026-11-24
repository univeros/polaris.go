// Package agents makes AI agents Polaris principals (plugin id "agents"): agents registered by their owners or enrolled by hosts, each an OAuth client
// of the oauth plugin (client credentials for an autonomous agent, token exchange with act for a
// delegated one; private_key_jwt, a pcs_ secret or the user's token), signed request JWTs
// (typ agent+jwt: aud the exact URL, jti once, exp - iat at most 5 min, htm/htu/body_hash
// binding), capability grants with constraints and budgets approved by a person (device code,
// CIBA push, in-app) with the strength the risk needs or by policy, one execution path with a
// signed receipt hash chain, and a kill switch. Agents speak a subset of the Agent Auth Protocol.
//
// Install it after the oauth plugin; capabilities are plain Go funcs or host routes:
//
//	ag := agents.New(agents.Config{Capabilities: []agents.Capability{
//		{Name: "invoices.read", Description: "Read invoices", Permission: "invoices.read", Risk: agents.RiskLow,
//			Handler: func(ctx context.Context, call agents.Call) (any, error) { return listInvoices(ctx, call.Arguments) }},
//		{Name: "invoices.refund", Description: "Refund an invoice", Permission: "invoices.refund", Risk: agents.RiskHigh,
//			Location: "https://app.example.com/refunds"},
//	}})
//	p, err := polaris.New(polaris.Config{Secrets: s, Auth: a, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{}), ag}})
//	mux.Handle("/", p.Handler())                                         // the 26 agents routes among Polaris's
//	mux.Handle("POST /refunds", ag.Protect("invoices.refund", refunds))  // checked BEFORE refunds runs
//	mux.Handle("GET /.well-known/agent-configuration", ag.DiscoveryHandler()) // when Polaris is not at the root
//
// A guarded host handler reads its execution with CallFrom. On every other Polaris route (and
// behind polaris.Protect), an agent's OAuth token is the agent principal: the owner (or, for an
// organization's agent, the member who registered it) delegated to the agent's live grants, with
// actor_type "agent" and agent_id claims. The audit plugin records every agent.* event; the admin
// plugin authorizes the /admin/agents operator routes. Each capability with a handler is also an
// MCP tool (wiring.ToolProvider) for the mcp plugin.
package agents
