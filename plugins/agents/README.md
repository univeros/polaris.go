# plugins/agents

AI agents as Polaris principals. An agent belongs to a user or an organization, is registered by its
owner or enrolled by a host (`peh_…` token), and is an OAuth client of `plugins/oauth` (client
credentials when autonomous, token exchange with `act` when delegated). It signs each request
(`agent+jwt`: `aud` the exact URL, `jti` once, at most 5 min, `htm`/`htu`/`body_hash`), asks for
capability grants with constraints and budgets that a person approves (device code, CIBA, in-app) at
the strength the risk needs, or the policy approves; every execution spends the budget and appends a
signed, hash-chained receipt; a kill switch seals the agent. Needs
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

Only `Capabilities` matters for most hosts; every other field has a working default.

| Field | Default | Purpose |
| --- | --- | --- |
| `Capabilities` | none | `agents.Capability{Name, Description, Input, Permission, Risk, Handler \| Location}` — exactly one of `Handler`, `Location` |
| `BaseURL` | the oauth plugin's | where Polaris is mounted; the discovery document derives from it |
| `ApprovalURL` | none | your page where a person types a user code; empty: approvals are in-app |
| `AutoApprove` | low risk, 100 executions | risk tier → `agents.Budget` granted without a person; empty map turns it off. A budget is granted once per window: see Host integration |
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
- `ag.Guard(mux)` guards every capability `Location` on a whole mux: by its URL, or by its path (decoded as a
  router decodes it) when the request's `Host` is no location's. On a path several hosts' locations
  share, another `Host` answers 404 `agents/capability_not_found`. `Protect` binds one handler to one
  capability, whatever the URL; it panics for a name that is not a configured `Location` capability
  (use it after `polaris.New`).
- `Protect` and `Guard` refuse a body (`agents/invalid_arguments`) your handler could read differently from
  the check: two members of one object with the same name, upper and lower case alike, a declared
  argument in another case, or a body that begins as a JSON object and is not exactly one. A body that is
  no JSON object has no arguments.
- A request JWT's `aud` on the plugin's own routes (`/agents/…`) is the path called on
  `Config.BaseURL`'s origin (default: the oauth plugin's base URL); the `Host` header and `r.TLS`
  are not read, so a TLS-terminating proxy needs no setup and another host name is refused
  (`aud_mismatch`). On your routes behind `Protect` / `Guard` the `aud` is the URL as the request
  names it (`Host`, and `r.TLS` for the scheme): serve them only under your own host names.
- The policy (`AutoApprove`) approves a budget with its own window (or none asked) and no larger than its
  own; any other window waits for a person. It does not refill a budget: once an agent has exhausted a grant of a
  capability, its next request for that capability waits for a person (`pending`) until the spent
  grant's window has passed; a budget without a window is granted by the policy once. A person can
  approve the new request as usual.
- The policy decides per agent and capability name: a newly enrolled agent, or a capability the
  host renames, starts with neither an exhausted budget nor a revoked grant. Whoever may enroll
  agents can so ask the policy again; give `AutoApprove` only what that may cost, and an empty map
  where a person should decide every grant.
- An autonomous agent's own token (`client_credentials`) carries the permissions of its live
  grants that its owner holds when the token is issued (`Plugin.ClientPermissions`).
- Each `Handler` capability is also an MCP tool `agents.<name>` for `plugins/mcp`.
- To push a CIBA approval, listen to `agents.EventGrantRequested`. `Plugin.Receipts` and
  `Plugin.VerifyReceipt` read and check the chain from code.
- `Input` is checked by a built-in JSON Schema subset: an unsupported keyword fails `polaris.New`, `format`
  is not checked, `pattern` is RE2. A refusal's `errors` name the JSON Pointer and the rule
  (`/amount: must be at most 100`, `missing required properties: to`).
- Input is read as its JSON type: `arguments` and `constraints` are objects (`[]` is refused),
  `capabilities` is a list, `after` and `limit` are integers. `max` and `min` bound JSON numbers (a
  numeric string violates them); `in` and `not_in` compare numbers by value (`1` is `1.0`).
- Times are RFC 3339 in UTC (`2026-11-22T10:00:00Z`), except a receipt's `created_at`, which its
  hash and signature cover: it keeps the form every receipt was hashed in (`+00:00`), and a verifier
  hashes it as sent.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/agents`.
