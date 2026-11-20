# plugins/agents

AI agents as Polaris principals. An agent belongs to a user or an organization, is registered by its
owner or enrolled by a host (`peh_…` token), and is an OAuth client of `plugins/oauth` (client
credentials when autonomous, token exchange with `act` when delegated). It signs each request
(`agent+jwt`: `aud` the exact URL, `jti` once, at most 5 min, `htm`/`htu`/`body_hash`), asks for
capability grants with constraints and budgets that a person approves (device code, CIBA, in-app) at
the strength the risk needs, or the policy approves; every execution spends the budget and appends a
signed, hash-chained receipt; a kill switch seals the agent. Port of `polaris/agents`; needs
`plugins/oauth` (`Init` fails without it); records to `plugins/audit` and uses `plugins/admin` for
`/admin/agents` when they are registered.

## Install

```go
import "github.com/univeros/polaris.go/plugins/agents"

ag := agents.New(agents.Config{Capabilities: []agents.Capability{
	{Name: "invoices.list", Description: "List invoices", Permission: "invoices.read", Risk: agents.RiskLow,
		Handler: func(ctx context.Context, call agents.Call) (any, error) { return listInvoices(ctx, call.Arguments) }},
	{Name: "refund", Description: "Refund an invoice", Permission: "billing.refund", Risk: agents.RiskHigh,
		Location: "https://app.example.com/api/refunds"},
}})
cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{}), ag)
p, err := polaris.New(cfg)
_, err = p.Migrate(ctx) // polaris_agent, _host, _grant, _approval, _receipt; seeds capability permissions

mux.Handle("/", p.Handler())                                   // /agents/*, /.well-known/agent-configuration
mux.Handle("POST /api/refunds", ag.Protect("refund", refunds)) // grant, constraints, budget checked BEFORE refunds
// in refunds: call, _ := agents.CallFrom(r.Context()); the response carries X-Polaris-Receipt
```

## Config

Only `Capabilities` matters for most hosts; every other field has upstream's default.

| Field | Default | Purpose |
| --- | --- | --- |
| `Capabilities` | none | `agents.Capability{Name, Description, Input, Permission, Risk, Handler \| Location}` — exactly one of `Handler`, `Location` |
| `BaseURL` | the oauth plugin's | where Polaris is mounted; the discovery document derives from it |
| `ApprovalURL` | none | your page where a person types a user code; empty: approvals are in-app |
| `AutoApprove` | low risk, 100 executions | risk tier → `agents.Budget` granted without a person; empty map turns it off |
| `Strengths` | low, medium `session`; high `step_up` | risk tier → `StrengthSession`, `StrengthStepUp`, `StrengthPasskey` |
| `ApprovalTTL` | 10 min | how long an approval waits |
| `ProviderName`, `Description` | `Polaris`, `Polaris for Go agent provider` | discovery document |
| `RequestJWTMaxAge` | 5 min (also the maximum) | bound on `exp - iat` |
| `Operators` | the admin plugin | authorizes `/admin/agents`; without admin nobody (401) |
| `MaxBodyBytes` | 1 MiB | body `Protect` / `Guard` read; larger is 413 |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/.well-known/agent-configuration` | discovery (`ag.DiscoveryHandler()` when Polaris is not at the root) |
| GET | `/agents/capabilities` | the capabilities (with `grant_status` for an agent) |
| POST | `/agents/register` | the owner registers an agent |
| POST | `/agents/enroll` | a host enrols an agent with its `peh_` token |
| GET, POST | `/agents/hosts` | the owner's hosts / create one |
| DELETE | `/agents/hosts/{id}` | revoke a host |
| GET | `/agents`, `/agents/{id}` | the owner's agents / one agent |
| POST | `/agents/{id}/suspend`, `/agents/{id}/resume` | pause / resume |
| POST | `/agents/{id}/revoke` | kill switch: revoke, disable its client and tokens, seal the receipts |
| GET | `/agents/session` | the agent's grants and remaining budgets |
| POST | `/agents/grants/request` | the agent asks for grants (constraints, budget) |
| DELETE | `/agents/grants/{id}` | revoke a grant |
| GET | `/agents/approvals`, `/agents/approvals/code` | pending approvals / the one behind a `user_code` |
| POST | `/agents/approvals/{id}/decide` | `{decision: approve\|deny}` at the required strength |
| POST | `/agents/execute` | run a `Handler` capability: `{capability, arguments}` |
| GET | `/agents/{id}/receipts` | export the receipt chain (`after`, `limit`) |
| GET | `/agents/receipts/{id}/verify` | recheck hash, signature and chain link |
| GET | `/admin/agents` | operators: every agent |
| POST | `/admin/agents/{id}/revoke` | operators (`own`): kill switch |

## Events and permissions

Emits `agents.Event` with `EventRegistered`, `EventEnrolled`, `EventSuspended`, `EventResumed`,
`EventRevoked`, `EventGrantRequested`, `EventGrantApproved`, `EventGrantDenied`, `EventGrantRevoked`,
`EventGrantExhausted`, `EventExecuted`, `EventExecutionDenied`, `EventReceiptSealed` (`agent.*`);
`Plugin.AuditNames` adds them to the audit catalog. `Plugin.Permissions` contributes each capability's
`Permission` that core's catalog lacks (so it can join roles and be an OAuth scope); declare your own
with `cfg.Permissions` too if you want descriptions of your choosing.

## Problems

`https://polaris.univeros.io/problems/agents/<name>`, the `agents.Err*` names: `unauthorized`,
`invalid_jwt`, `aud_mismatch`, `agent_inactive` (401); `capability_not_granted`,
`constraint_violated` (with `violations`), `budget_exhausted`, `step_up_required`,
`permission_not_held`, `forbidden` (403); `capability_not_found`, `not_found` (404); `conflict`,
`sealed` (409); `invalid_arguments`, `invalid_input` (422); `unknown_constraint_operator` (400);
`payload_too_large` (413). A `Handler` may return `*agents.Error` to refuse with one.

## Host integration

- On every other Polaris route and behind `p.Protect`, an agent's OAuth token is its owner delegated
  to its live grants, with claims `agents.ClaimActorType` (`"agent"`) and `agents.ClaimAgentID`.
- `ag.Guard(mux)` guards every capability `Location` on a whole mux; `Protect` panics for a name
  that is not a configured `Location` capability (use it after `polaris.New`).
- Each `Handler` capability is also an MCP tool `agents.<name>` for `plugins/mcp`.
- To push a CIBA approval, listen to `agents.EventGrantRequested`. `Plugin.Receipts` and
  `Plugin.VerifyReceipt` read and check the chain from code.
- `Input` is checked by a built-in JSON Schema subset: an unsupported keyword fails `polaris.New`, `format`
  is not checked, `pattern` is RE2.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/agents`.
