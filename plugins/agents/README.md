# plugins/agents

AI agents as Polaris principals. An agent belongs to a user or an organization, is registered by its
owner or enrolled by a host (`peh_…` token), and is an OAuth client of `plugins/oauth` (client
credentials when autonomous, token exchange with `act` when delegated). It signs each request
(`agent+jwt`: `aud` the exact URL, `jti` once, at most 5 min, `htm`/`htu`/`body_hash`), asks for
capability grants with constraints and budgets that a person approves (device code, CIBA, in-app) at
the strength the risk needs, or the policy approves; every execution spends the budget and appends a
signed, hash-chained receipt; a kill switch seals the agent. Needs
`plugins/oauth` (`Init` fails without it); serves the twelve endpoints of the
[Agent Auth Protocol](https://agent-auth-protocol.com/specification) (`v1.0-draft`) to its own clients
(see [Agent Auth Protocol](#agent-auth-protocol)); records to `plugins/audit` and uses `plugins/admin` for
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
_, err = p.Migrate(ctx) // polaris_agent, _host, _grant, _approval, _receipt, _registration; seeds capability permissions

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
| `Strengths` | low, medium `session`; high `step_up`. With `DiscoveryAgentAuth`: low `step_up`; medium, high `passkey` | risk tier → `StrengthSession`, `StrengthStepUp`, `StrengthPasskey` |
| `ApprovalTTL` | 10 min | how long an approval waits |
| `Discovery` | `DiscoveryPolaris` | the document at `/.well-known/agent-configuration`: `DiscoveryPolaris` (the Go agent SDK's) or `DiscoveryAgentAuth` (the Agent Auth Protocol's) |
| `DisableJWKSURLs` | false | refuse hosts that publish their keys at a `jwks_url` (taken with `DiscoveryAgentAuth` only) |
| `DisableDynamicHosts` | false | refuse hosts the server does not know (taken with `DiscoveryAgentAuth` only): only hosts an owner registered sign agents in |
| `RateLimits` | 60 / 300 / 600 a minute | the protocol's routes, per `Agent`, per `Host` and per `Address`; see Agent Auth Protocol |
| `Lifetimes` | unlimited | `Session`, `Max` and `Absolute` of agents hosts' JWTs registered; see Agent Auth Protocol |
| `HTTPClient` | guarded | fetches those key sets; the default connects to public addresses only, and no client follows a redirect |
| `ProviderName`, `Description` | `Polaris`, `Polaris for Go agent provider` | discovery document |
| `RequestJWTMaxAge` | 5 min (also the maximum) | bound on `exp - iat` |
| `Operators` | the admin plugin | authorizes `/admin/agents`; without admin nobody (401) |
| `MaxBodyBytes` | 1 MiB | body `Protect` / `Guard` read; larger is 413 |

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/.well-known/agent-configuration` | discovery, as `Config.Discovery` says (`ag.DiscoveryHandler()` when Polaris is not at the root) |
| GET | `/agents/configuration` | Polaris's discovery document, whatever `Config.Discovery` says |
| GET | `/capability/list` | Agent Auth Protocol: the capabilities (`query`, `cursor`, `limit` ≤ 100), with `grant_status` for an agent |
| GET | `/capability/describe` | Agent Auth Protocol: one capability (`name`) |
| POST | `/agent/register` | Agent Auth Protocol: a host registers an agent; one the server does not know waits for a person with it |
| GET | `/agent/status` | Agent Auth Protocol: an agent of the host (`agent_id`) |
| POST | `/agent/request-capability` | Agent Auth Protocol: the agent asks for capabilities |
| POST | `/capability/execute` | Agent Auth Protocol: run a `Handler` capability |
| GET | `/agents/capabilities` | the capabilities (with `grant_status` for an agent) |
| POST | `/agents/register` | the owner registers an agent |
| POST | `/agents/enroll` | a host enrols an agent with its `peh_` token |
| GET, POST | `/agents/hosts` | the owner's hosts / create one (with an enrolment token, or a `public_key` or `jwks_url` of its own) |
| DELETE | `/agents/hosts/{id}` | revoke a host; one with a key takes its agents with it |
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
`EventGrantExhausted`, `EventExecuted`, `EventExecutionDenied`, `EventReceiptSealed`,
`EventRegistrationRequested`, `EventRegistrationDenied` (`agent.*`);
`Plugin.AuditNames` adds them to the audit catalog. `Plugin.Permissions` contributes each capability's
`Permission` that core's catalog lacks (so it can join roles and be an OAuth scope); declare your own
with `cfg.Permissions` too if you want descriptions of your choosing.

## Problems

`https://polaris.univeros.io/problems/agents/<name>`, the `agents.Err*` names: `unauthorized`,
`invalid_jwt`, `aud_mismatch`, `agent_inactive` (401); `capability_not_granted`,
`constraint_violated` (with `violations`), `budget_exhausted`, `step_up_required`,
`permission_not_held`, `forbidden` (403); `capability_not_found`, `not_found` (404); `conflict`,
`sealed` (409); `invalid_arguments`, `invalid_input` (422); `unknown_constraint_operator` (400);
`payload_too_large` (413). Only on the protocol routes: `invalid_request`,
`invalid_capabilities`, `unsupported_mode`, `unsupported_algorithm` (400); `agent_revoked`,
`agent_suspended`, `agent_pending`, `agent_rejected`, `host_revoked`, `limit_exceeded` (403);
`agent_not_found` (404); `already_granted`, `agent_exists` (409). A `Handler` may return `*agents.Error` to refuse with one.

## Host integration

- On every other Polaris route and behind `p.Protect`, an agent's OAuth token is its owner delegated
  to its live grants, with claims `agents.ClaimActorType` (`"agent"`) and `agents.ClaimAgentID`.
- The arguments checked are the JSON body and nothing else, so behind `Protect` and `Guard` nothing else may carry
  any: a query, and a body that is not one JSON object in UTF-8, or that its `Content-Type` says is something else, are
  refused with 422 `agents/invalid_arguments` (a protocol agent gets 400 `invalid_request`, and its type is not read); a body
  sent without a type reaches the handler as `application/json`. A form parsed before, trailers, `GetBody` and
  `Content-Encoding` do not reach the handler. A request without a body has no arguments. Headers, cookies and what the
  path names (`PathValue`) are the route's, and no constraint covers them: take arguments from the body or `CallFrom`.
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

## Agent Auth Protocol

The protocol's own client (`@auth/agent`) signs in through a host whose key its owner registered
(`POST /agents/hosts` with `public_key` and `proof`), or, with `DiscoveryAgentAuth`, through a host the server does not
know: it registers an agent, waits for a person where one must approve, requests capabilities and executes
them, at their `Location` too. [`examples/agents -protocol`](../../examples/agents/README.md#an-agent-auth-protocol-client)
walks through it; how it is built, and why, is [docs/agent-auth-compat.md](../../docs/agent-auth-compat.md).

- An origin has one `/.well-known/agent-configuration` and the two client families read it differently.
  `Discovery: agents.DiscoveryAgentAuth` gives it to the protocol's clients; the Go agent SDK then reads
  `/agents/configuration` by itself (SDK v1.1.0 or newer: an older one fails with
  `agent.ErrNotConfiguration`). The capability routes are served in both modes.
- The protocol document's `issuer` is `BaseURL`, where Polaris is mounted: its paths resolve against it,
  and it is the exact `aud` of an agent's request JWT on `/capability/*` (`AUTH_ISSUER` plays no part).
  A JWT's `iat` may be at most 30 s ahead there. An agent's OAuth token works too.
- A credential on those routes that is neither an agent's nor a known host's is 401 `invalid_jwt`, never
  read as anonymous; the reference client then asks again without one.
- An agent belongs to its host's owner, organization included. It is `pending` when a person must approve
  everything it asked for at registration, and `rejected` for good when they deny it. Approvals are
  decided as ever (`/agents/approvals`); with `ApprovalURL` the client shows that page and the code.
- A key or URL is registered with `proof`: a JWT (`typ` `host-link+jwt`, EdDSA) signed by that key whose `sub` is
  the id of the account that will own the host, yours or the organization's. `agent.SignHostLink` makes one. The
  reference client cannot: a host that uses it comes in by itself (next), or you sign with its stored key.
- Approving, in `DiscoveryAgentAuth` mode, always needs a sign-in within `StepUpMaxAge`, and proof that a person
  is there for capabilities of medium (the default) or high risk: a passkey sign-in (not a step-up with one)
  whose authenticator verified them. Add the passkey plugin, with `UserVerification: passkey.UVRequired` as the
  protocol asks (§8.11), or set `Strengths`; without either the server does not start. Registering a host or an
  agent by hand takes the strength of the riskiest capability `AutoApprove` gives, and a recent sign-in too. `step_up` for a
  capability that changes data departs from the protocol: an agent that controls the person's browser may sign
  in again with a stored password and approve itself. Declare what only reads `RiskLow`.
- A host the server does not know registers with its key, and nothing exists until a person approves: no
  host, no agent, no OAuth client. The client shows them your `ApprovalURL` and a code; your page reads
  `GET /agents/approvals/code` with their session and posts their decision. Who approves owns the host and
  the agent, in their active organization, and from then on the policy applies to the host's agents; show
  them that, what is asked (`agent`, `grants`) and who asks (`host`, `reason`). `host.name`, the agent's name
  and `reason` are what the host says, proven by nothing: render them as text, and say so. Approving needs at least
  `step_up` (403 `step_up_required` otherwise: send them to sign in again), and the strength of the riskiest
  capability that `AutoApprove` gives without a person, as nobody is asked again for those. Denying rejects that agent for good; the host may ask again with another key.
  Such a host sends its key (`host_public_key`); a `jwks_url` is for hosts an owner registered.
- A person can be sent a code by somebody else and asked to approve it, as with any device code: the page
  should ask whether they started this themselves.
- At a capability's `Location` an agent of a host with a key posts `{capability, arguments}`, as to the execute
  route. Behind `Protect` and `Guard` your handler reads the arguments alone, as any other agent sends them, and its
  JSON answer (2xx) is sent as `{"data": ...}` with status 200; other answers pass as they are. The JWT's `aud` is
  the `Location` exactly as configured. The client always posts: serve such a capability at `POST`.
- Requests an agent or a host signed are limited per agent (60 a minute) and per host (300), at a `Location` too, and
  everything on the protocol's routes per address (600) before it is verified: 429 `rate_limited` with `Retry-After`. `RateLimits` sets others.
  What one capability may be used for is a budget with a window.
- The host's client revokes its agents and itself (`POST /agent/revoke`, `/host/revoke`: the kill switch, as ever) and
  replaces their keys (`/agent/rotate-key`, `/host/rotate-key`, with the host's JWT). A new host key is
  the host's once its holder names one of the host's agents (their client's next status call), or with `proof`, a
  host link JWT of the new key: a public key alone is anybody's to send, and takes nothing from its holder.
- `Lifetimes` bound the agents hosts' JWTs registered: without a request for `Session`, or `Max` after its activation,
  an agent is `expired` until `POST /agent/reactivate` brings it back to its host's default capabilities; `Absolute`
  after its creation it is revoked. A grant the policy gave keeps what is left of its budget; a person's is asked
  again. Schedule `ag.Prune(ctx)`: it also revokes those past `Absolute`. Setting one applies to the agents there are,
  from their activation (or creation): a short `Absolute` revokes the older ones for good.
- A resource server of yours asks `POST /agent/introspect` about an agent's JWT, as an OAuth client you marked trusted
  (or listed in the oauth plugin's `TrustedClients`). Compare the answer's `aud` with your own URL and take each `jti`
  once: introspection does not spend it.
- New registrations of unknown hosts are limited per address at the budget of sign-up
  (`RateLimits.Register`, 5 an hour). The address is the request's `RemoteAddr`: behind a proxy, set it to the
  client's before Polaris, or every client shares one budget.
- Schedule `ag.Prune(ctx)`: a day after its approval expired, it deletes a registration nobody decided and a
  known host's agent nobody decided. Unknown hosts' registrations are also deleted as new ones come.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/agents`.
