# Agent Auth Protocol compatibility

Status: **in progress** (2026-11-24): decisions 83 (parts 0.1, 0.2 and 1), 84 (part 2) and 85 (part 3) in
[`decisions.md`](decisions.md). Target release: `v1.1.0` (additive; nothing in v1 breaks).

Reference: Agent Auth Protocol, published as `v1.0-draft`,
<https://agent-auth-protocol.com/specification> (§ numbers below are the protocol's), read whole on
2026-11-24. The client was read at `@auth/agent` 0.6.2 and `@auth/agent-cli` (npm 0.5.1, which depends
on `@auth/agent` 0.5.1; the repository is at 0.6.2), `better-auth/agent-auth` commit `e89bd03`; the
published 0.6.2 and 0.5.1 packages were checked for every statement about URLs and JWT claims (§1.1).

---

## 0. Why

`plugins/agents` says it speaks "a subset of the Agent Auth Protocol". The subset is the shape of the
discovery document, the `agent+jwt` request JWT, the constraint operators and the approval object.
The registration model, the endpoint set and the lifecycle are Polaris's own, so the protocol's
reference client (`@auth/agent`, `@auth/agent-cli` and its MCP server, maintained by the Better Auth
team) cannot sign in to a Polaris server.

The protocol is where the client side of agent sign-in is converging. A Polaris server that any
protocol client can use, and that still enforces budgets, receipts and the kill switch behind it, is
the position this work package buys.

### Goal

An **unmodified** Agent Auth Protocol v1.0 client discovers a Polaris for Go server, registers an
agent through a host, gets a person's approval, requests a capability and executes it. Everything
Polaris adds (budgets, approval strengths, the receipt chain, the kill switch, audit events) applies
to that agent exactly as it does to one enrolled the Polaris way.

### Non-goals

- Changing or removing any of the 23 existing agents routes, their fixtures, or the behaviour the Go
  agent SDK relies on.
- Async and streaming execution (§5.11). A service operates in one mode; Polaris stays synchronous.
- Unlinked hosts provisioning autonomous agents (§2.8, a MAY) and therefore the `claimed` state.
  Every Polaris agent has an owner.
- Directories (§6.11) and proof-of-possession for agent JWTs beyond what exists (§4.4, optional).
- Polaris for PHP. The same surface is specified there as its own program
  (`univeros/polaris-core`, `docs/agent-auth/spec.md`), implemented separately and proven by the same
  client; decision 53 stands, so neither implementation is a reference for the other.

---

## 1. Where Polaris stands today

Read from the code at `v1.0.0`.

| Area | Protocol v1.0 | Polaris for Go 1.0 | Gap |
|---|---|---|---|
| Discovery path | `/.well-known/agent-configuration` | Same | None |
| Discovery `version` | `1.0-draft` (the published version) | `1.0-draft` | None |
| Discovery `endpoints` | Paths relative to `issuer` (§5.1); 12 named endpoints. The reference client also takes absolute URLs, and the reference server sends them | Absolute URLs; keys `register`, `enroll`, `capabilities`, `execute`, `request_capability`, `status`, `revoke`, `grants`, `approvals`, `receipts`, `token`, `mcp` | Format and set differ; `register` and `status` mean different things |
| Discovery `algorithms` | `Ed25519` | `ES256`, `EdDSA` (JOSE names) | Value |
| Host identity | Key pair; `host+jwt` with `iss` = RFC 7638 thumbprint; inline JWK or JWKS URL | `peh_` enrolment token, stored as a keyed hash; a host always has an owner | Whole mechanism |
| Host establishment | Dynamic (unknown host, `pending` until a person approves) or pre-registered | An owner creates the host first (`POST /agents/hosts`) | Dynamic hosts |
| Agent registration | `POST /agent/register` with a host JWT carrying the agent's key | `POST /agents/enroll` with the `peh_` token and a `jwk` field; or `POST /agents/register` with the owner's session | Route and credential |
| Agent JWT | `typ agent+jwt`; `iss` host thumbprint (§4.3; the reference client sends no `iss`); `sub` agent id; `aud` the issuer, or the location for execution; 60 s recommended | `typ agent+jwt`; `iss` not read; `sub` agent id; `aud` the exact URL called; `exp - iat` at most 5 min; `htm`, `htu`, `body_hash` checked when present; `jti` once | `aud` on non-execution calls; clock rules |
| Clock rules | `iat` at most 30 s in the future (MUST) | 60 s leeway | Tighten on protocol routes |
| Agent states | `pending`, `active`, `expired`, `revoked`, `rejected`, `claimed` | `active`, `suspended`, `revoked` | Mapping; lifetimes |
| Lifetimes | Session TTL, max lifetime, absolute lifetime; reactivation | None; a grant may expire, an agent does not | New, off by default |
| Key rotation | `POST /agent/rotate-key`, `POST /host/rotate-key` | None | New |
| Status | `GET /agent/status?agent_id=` with a host JWT | `GET /agents/session` with the agent's own credential | New route |
| Introspection | `POST /agent/introspect` | None for agent JWTs | New route |
| Capabilities | `GET /capability/list` (`query`, `cursor`, `limit`), `GET /capability/describe` | `GET /agents/capabilities`, wrapped in `data`, no query or paging, no describe | New routes |
| Execute | `POST /capability/execute`; sync body MUST hold `data` and none of `status`, `status_url`, `result`, `error` | `POST /agents/execute`; body `{data, receipt}` | Body on the protocol route |
| Request capability | `POST /agent/request-capability` | `POST /agents/grants/request`; response already `agent_id`, `agent_capability_grants`, `approval` | Route name; error codes |
| Approval object | `method`, `verification_uri`, `verification_uri_complete`, `user_code`, `expires_in`, `interval`, `binding_message` | All of those, plus `id` and `strength` | None |
| Constraints | `max`, `min`, `in`, `not_in`, exact values; `unknown_constraint_operator` | Same, plus the `budget` key | None (budget is an extension) |
| Error body | `error` and `message` | RFC 9457 problem that also carries `error` and `message` | Codes and some statuses |
| Error statuses | Inactive agent is 403 (`agent_revoked`, `agent_expired`, `agent_pending`) | 401 `agent_inactive` (code `agent_revoked` or `agent_suspended`) | Status on protocol routes |

### 1.1 What the reference client does

From its source; the harness (0.2) runs the published package.

- **Discovery.** It tries `{url}/.well-known/agent-configuration`, then
  `{url}/api/auth/agent-configuration`, then `{url}/api/auth/agent/agent-configuration`, and takes the
  first 2xx document that has `version`, `issuer` and `endpoints`. It checks no version, algorithm or
  approval method. It caches the document under its `issuer` for the life of the storage. Built without
  `urls` and without a `directoryUrl` it only looks in `https://agent-auth.directory` and never fetches
  a well-known document: a host's own URL needs `urls` (the CLI's `--url`, `AGENT_AUTH_URLS`) or
  `allowDirectDiscovery`.
- **Endpoints.** A value that starts with `http://` or `https://` is used as it is; any other is
  appended to `issuer` without its trailing slash; a missing one is the protocol's default path.
  Better Auth's own server sends absolute URLs, against §5.1.
- **Calls, in order.** Discovery; `GET capabilities` with a host JWT when it has a host key, else
  without a credential, and once more without it after a 401 (only a 401); `register` (host JWT with
  `host_public_key`, `agent_public_key`, `host_name`, `sub` = `iss` = the thumbprint); while `pending`
  with an `approval`, `status` (host JWT) every `interval` seconds; before an execution whose grant it
  does not know to be active, `status` once; `execute` (agent JWT, `aud` the location, `capabilities`
  the one name); `request_capability` (agent JWT, `aud` the issuer), then `status` while `pending`.
  `reactivate`, `revoke`, `rotate_key` and `rotate_host_key` only when asked to. It also calls paths
  the protocol does not define: `POST /capability/batch-execute` (a 404 or 405 falls back to single
  executions), `POST {issuer}/host/enroll` and `POST /agent/claim`, both only when asked to.
- **Where it executes.** The capability's `location` as `GET capabilities` listed it, then
  `default_location`, then `endpoints.execute`. `describe` is not kept, so a `location` absent from the
  list is never used.
- **Agent status while it waits.** `active` and `claimed` end the wait; `rejected` and `revoked` throw
  `agent_rejected` / `agent_revoked`; `pending`, `expired` and any other status, and any non-2xx answer
  (429 included), keep it polling until the sooner of `expires_in` and 5 minutes, then
  `approval_timeout`. Nothing is retried after that and `reactivate` is never automatic. The wait after
  `request_capability` watches the agent's status, not the grant's, so for an active agent it ends at
  the first poll, with the grants as they are then.
- **`limit_exceeded`** does not appear in it. Every non-2xx answer becomes an error with the body's
  `error` and `message` and the HTTP status; only `invalid_capabilities` is treated apart (a hint is
  added). Nor does it read `Retry-After`, except between polls of an asynchronous execution.
- **It shows an approval only for a `status` of `pending`.** `request_capability`'s answer must hold
  `status` (`granted` or `pending`), which §5.4 does not name, or the person is never asked; `register`'s
  must be `pending`, not `active` with pending grants.
- **At a capability's `location`** it posts the same `{capability, arguments}` body (§2.15).
- **Agent JWTs carry no `iss`** (nor `htm`, `htu`, `body_hash`, unless the caller sets `htm` and `htu`),
  although §4.3 requires it.

### 1.2 What §8.14 to §12 add

- §8.16: an algorithm in use MUST NOT be removed from `algorithms`.
- §8.18: `aud` MUST match this server exactly, as 2.4.
- §9.2: activity MUST NOT be shared with third parties without consent; Polaris shares none.
- §10.1: the status of each capability MUST be tracked; grants are rows already.
- §10.3: the replay cache covers lifetime plus skew, as 2.4.
- §10.5, §10.6: `Cache-Control` on discovery (an hour) and on capabilities (five minutes); capability
  answers depend on the credential. After `capability_not_found` or `invalid_request` from an execution
  a client MUST fetch the list again, so a schema mismatch on `/capability/execute` is 400
  `invalid_request`, not 422 (§5.2.1), and a removed capability there is 403 `capability_not_granted`,
  not 404 (§2.12).
- §10.9: pending registrations are deleted after a threshold, as 2.3.
- §8.14, §10.10 (proof of possession, cross-user grants, push notification, server-defined approval)
  are optional profiles; none is implemented. §8.17, §9 and §11 otherwise ask for what the receipt,
  budget and audit code does.

What Polaris has that the protocol does not define, and keeps: budgets with windows, risk tiers with
approval strengths (`session`, `step_up`, `passkey`), the signed hash-chained receipt per execution,
`suspend` / `resume`, the kill switch that seals the chain, OAuth tokens for agents (client
credentials, token exchange), capabilities as MCP tools.

---

## 2. Design

### 2.1 A second surface, not a rewrite

The protocol routes are **new routes at the protocol's own default paths**, served by the same
plugin and the same service code:

```
POST /agent/register            GET  /capability/list
POST /agent/request-capability  GET  /capability/describe
GET  /agent/status              POST /capability/execute
POST /agent/reactivate          POST /host/revoke
POST /agent/revoke              POST /host/rotate-key
POST /agent/rotate-key          POST /agent/introspect
```

They are singular (`/agent`, `/host`, `/capability`), so none collides with `/agents/*`. Each gets a
spec in `internal/apispec/api/agents/agents/protocol/*.yaml` (the manifest reads the plugin and the
route's name, `polaris.agents.protocol.*`, from its path) and a recorded fixture, like every other route
(AGENT.md rules 3 and 4).

An agent registered through either surface is the same `polaris_agent` row and the same OAuth client.
It can be listed, suspended, revoked and audited through the existing owner and operator routes, and
its executions append to the same receipt chain.

### 2.2 Discovery

One origin has one `/.well-known/agent-configuration`, and the two client families read it
differently: the Go SDK needs `token_endpoint` and an absolute `endpoints.execute` that ends in
`/agents/execute`, from which it derives every other URL; a protocol client needs the twelve protocol
names. Five of those names (`register`, `capabilities`, `request_capability`, `status`, `revoke`) and
`execute` are in today's document with other URLs, another request and another meaning, so one
document cannot serve both without changing what a v1 client reads.

- `agents.Config.Discovery` chooses the document at the well-known path:
  `agents.DiscoveryPolaris` (default: today's document, byte for byte) or
  `agents.DiscoveryAgentAuth` (the strict protocol document: `version: "1.0-draft"`, relative endpoint
  paths, `algorithms: ["Ed25519"]`, `approval_methods: ["device_authorization", "ciba"]`).
- The protocol document's `issuer` is `Config.BaseURL`, where Polaris is mounted, not the access
  tokens' `iss` (`AUTH_ISSUER`, which may be any string and knows no mount prefix): §5 resolves every
  path against it. It is also the `aud` of 2.4. Where the two differ the Polaris document keeps the
  `iss`.
- The document names only the endpoints the server serves (part 1: `capabilities` and
  `describe_capability`; part 2: `register`, `status`, `request_capability`, `execute` and
  `default_location`); each part adds its own, and all twelve are there after part 4. A client falls back to the protocol's
  default path for a name that is missing.
- The Polaris document is also always served at a new route, `GET /agents/configuration`.
- The Go agent SDK (`agent.New`) falls back to `/agents/configuration` when the well-known document
  has no `enroll` endpoint. Released SDKs keep working against a server in the default mode; against
  one in `DiscoveryAgentAuth` mode v1.0.0's SDK answers `ErrNotConfiguration` and must be upgraded.
- The protocol routes are served in both modes. `Discovery` only decides which client family finds
  the server by itself.

Decided (5.1).

### 2.3 Hosts with keys

`polaris_agent_host` gains nullable columns (additive, as decision 63 requires): `publicJwk`,
`jwksUrl` and `keyThumbprint` (each of the two with a unique index). A row without a key is a token
host, as today. No `status` column: a stored host is active or revoked (`revokedAt`), and a pending one
is a registration row.

- **Pre-registered host.** `POST /agents/hosts` accepts an optional `public_key` (JWK) or
  `jwks_url`. The owner pastes the host's public key; the host is `active` at once and linked to that
  owner, and has no enrolment token. A key or URL is one host's for good, revoked hosts included
  (§8.8.1). The owner proves no possession: see §6. This is the path for first-party fleets (Vela's Nightwatch, Venant, Tarazed).
- **Dynamic host.** A host JWT from an unknown thumbprint on `POST /agent/register` creates nothing
  in `polaris_agent_host` or `polaris_agent`. It creates a row in a new table,
  `polaris_agent_registration` (the future agent and host ids, both keys, names, mode, reason, expiry), and
  the pending grants and the approval, as rows that name the future agent: the existing approval routes
  read and decide them. Nothing of it is approved by the policy. The response is the protocol's `pending`
  registration with a device-authorization approval (never CIBA: an unknown host names nobody to push to).
  When a signed-in person approves at the required strength (at least `step_up`, and a sign-in within its max age even without a second factor: §8.11, and the
  host is linked by it), one transaction creates the host owned by that person in their active organization, the
  agent (through the existing `createAgent`, so it is an OAuth client like any other) under the announced id,
  activates the grants, and deletes the registration row. Denied: the row is marked `rejected` and deleted a
  day later. Undecided: deleted a day after the approval expired (§7.1: cleanup deletes, it does not revoke),
  by `Plugin.Prune` and as new registrations come.
- **Which hosts.** With `DiscoveryAgentAuth`, unless `Config.DisableDynamicHosts`. The key is inline: a
  `host_jwks_url` from an unknown host is refused (5.10). There is no stored pending host: an unknown host
  may register several agents, each with its own approval, under one announced host id. The first approval
  makes the host the approver's; from then on only they decide the rest (§2.9). A key an owner registers
  meanwhile makes it theirs the same way. A revoked host's waiting registrations cannot be approved (§2.11).
- **A denial is of that agent, not of the host.** §2.11's `rejected` host is not stored: anyone who signs in
  with the code could otherwise close the server to a device. The host may ask again with another agent key,
  which a person must approve as before.
- **What a pending host may do** (§4.5.1 step 8, read with §7.1, which has it poll): register, and read the
  status of its own registrations. On the capability routes it is unknown (2.4).
- **Idempotency** (§5.3) by host and agent key, for known hosts too (`polaris_agent.key_thumbprint`, unique
  with the host): pending answers the same agent, its approval opened again when that expired; any other
  state is 409 `agent_exists`.
- Nothing is trusted, granted or shown as an agent before that approval (§8.10). The approving
  person is the only link a host has; a host is never linked to two users (§2.9).
- Host JWT verification is a new `hostjwt.go` beside `requestjwt.go`: `typ host+jwt` only; `iss`
  equals the thumbprint of the verifying key; `aud` equals the issuer; `iat`, `exp`, `jti` required;
  `iat` at most 30 s ahead; `jti` once through `cache.Add` (atomic across replicas, as the agent JWT
  does); the key delivery mode (inline or JWKS URL) fixed at registration (§8.7).
- JWKS URLs are fetched with `internal/netguard` (public addresses only), HTTPS only, no redirect
  followed (§8.12 allows up to 3), a response size cap and a timeout, cached five minutes and fetched at
  most once a minute; the document must be a valid JWKS with the expected `kid` and no symmetric or
  private key (§8.12). Only a URL an owner registered is ever fetched in part 2. They are taken with
  `DiscoveryAgentAuth` unless `Config.DisableJWKSURLs`.
- An agent's key is inline (`agent_public_key`); `agent_jwks_url` is refused with `invalid_request`. It is
  a later addition (a column on `polaris_agent`) if a client needs it; the reference client does not.
- Revoking a host with a key (`DELETE /agents/hosts/{id}` today, `/host/revoke` in part 4) revokes its
  agents with the kill switch (§8.5). A token host's agents stay, as in v1.0.0.

### 2.4 Agent JWTs on the protocol routes

The existing verifier is reused with three differences, on the protocol routes only:

- `aud` is the issuer (2.2) on non-execution routes; on `/capability/execute` and on a capability
  `Location` it is the exact URL, as today (§4.3; §4.5 step 3 says the issuer for both, and the client
  follows §4.3).
- `iss`, when present, must be the current thumbprint of the agent's host; the agent is found by `sub`
  and must belong to that host (§4.5 steps 4 and 5). §4.3 requires `iss`, but the reference client
  sends none (1.1), so requiring it would refuse every agent it registers. Without it the host is the
  one the agent is stored under and the agent's own key still verifies the JWT: nothing is widened.
- `iat` at most 30 s ahead; the replay window covers the whole accepted lifetime.

`htm`, `htu` and `body_hash` stay accepted and checked when present. On the capability routes a host
JWT that does not verify, or whose host is unknown or pending, answers 401 `invalid_jwt`: that is the
only status after which the client asks again without a credential (1.1), and it has a host key before
the server knows it. An agent's OAuth token is accepted on
every agent route (§12.1). Only Ed25519 keys register through the protocol routes; ES256 stays available on the Polaris routes.

### 2.5 States and lifetimes

| Polaris | Reported on the protocol routes |
|---|---|
| registration row (unknown host), undecided | `pending` |
| registration row, denied | `rejected` |
| `pending`: a known host's registration in which a person must approve everything asked | `pending` |
| `rejected`: that registration, denied (§7.1) | `rejected` |
| `active`, inside its lifetimes | `active` |
| `active`, past session TTL or max lifetime | `expired` |
| `suspended` | `pending` (5.2) |
| `revoked` (kill switch, or absolute lifetime passed) | `revoked` |

`pending` and `rejected` are new values of `polaris_agent.status`, written only by protocol
registrations. Such an agent acts nowhere: every credential of it is refused by the same check a
suspended one is, and a rejected one's OAuth client is disabled. A registration some of whose
capabilities the policy approved is `active`, with the others pending.

`agents.Config.Lifetimes{Session, Max, Absolute}`: zero means unlimited, the default, so existing
deployments do not change. `polaris_agent` gains nullable `activatedAt` and `lastUsedAt`;
`lastUsedAt` is written at most once a minute per agent, not per request. `expired` is computed from
those and the clock, not stored, so no job has to flip it. `POST /agent/reactivate` follows §5.6:
only an expired agent; existing grants revoked; the host's default capabilities asked again through
the same policy; session and max clocks reset, the absolute clock never.

Revoking through `/agent/revoke` or `/host/revoke` runs the existing kill switch (client and tokens
disabled, receipt chain sealed, in one transaction), so "revocation is permanent" and "cascade to the
host's agents" (§8.5) hold without new code paths.

### 2.6 Responses and errors

- Capability list entries hold `name`, `description`, `grant_status` and, beyond §5.2's text, the
  `location` §2.12 defines: without it the client executes every capability at the default location
  (1.1). Better Auth's server lists it too.
- One grant per capability is shown, the one that counts: a live one, else a pending one, else the latest
  as `denied` with the reason (Polaris's `revoked` and `exhausted` are not protocol values). An exact
  value (§2.13) is stored as `in` with one value. An argument named `budget` cannot be constrained: the
  name is Polaris's extension.
- Protocol routes answer the protocol's body shapes: no `data` wrapper except execute's `data`
  member; `agent_capability_grants` with full detail for active grants, `capability` and `status`
  only for pending ones, plus `reason` for denied ones (§5.3).
- `POST /capability/execute` answers `{"data": …}` only. The receipt goes in the `X-Polaris-Receipt`
  header, as guarded host routes already do.
- Errors stay RFC 9457 problems (they already carry `error` and `message`), with the protocol's
  codes and statuses on these routes: `agent_exists` 409, `agent_not_found` 404, `host_not_found`
  404, `unsupported_mode` 400, `unsupported_algorithm` 400, `invalid_capabilities` 400 (with the
  list), `already_granted` 409, `agent_revoked` / `agent_expired` / `agent_pending` /
  `agent_rejected` / `host_revoked` / `host_pending` 403, `absolute_lifetime_exceeded` 403,
  `rate_limited` 429 with `Retry-After`, `authentication_required` 401 with
  `WWW-Authenticate: AgentAuth`. An exhausted budget answers `limit_exceeded` 403 here and stays
  `budget_exhausted` on the Polaris routes (§5.13: the agent has the capability but the request
  exceeds its limits; nothing from §8.14 on says more). Bad parameters are 400 `invalid_request`.
- New `agents.Err*` names for those codes are additive to the v1 API.

### 2.7 Approval strength

The protocol requires fresh authentication on every approval, and proof of presence (WebAuthn with
user verification, or out-of-band CIBA) for capabilities that change data or act for the user
(§8.11). Polaris's defaults are `session` for low and medium risk and `step_up` for high. In
`DiscoveryAgentAuth` mode the defaults become `step_up` for low and `passkey` for medium and high; a
host may still set `Strengths` itself, and the README says what that departs from. Decision 5.3 adds three rules.

### 2.8 Introspection

`POST /agent/introspect` follows §5.12 and RFC 7662. It is not public: the caller is a trusted OAuth
client (5.4), and the route is rate limited. A valid JWT is not consumed by introspection (its `jti` is not spent).

---

## 3. Work, in order

Each part is one pull request with `make qa`, the database matrix and `make apicheck` green.

| # | Part | Size | Done when |
|---|---|---|---|
| 0.1 | Read §8.14 to §10 of the protocol and the source of `@auth/agent`; amend this document where they contradict it | S | Done: the "not read" note at the top is gone; open questions in §5 are answered or still listed |
| 0.2 | Interop harness: `scripts/e2e-agent-auth.sh` starts a small server (`internal/e2e/agentauthserver`) and runs the unmodified `@auth/agent` client against it. Decision 30 did this for `@polaris-auth/agent`; that script and its server were removed with decision 53, so this one is new. It needs Node in CI: a separate job, not part of `make qa` | S | The script runs and stops at registration, for the expected reason (exit status 3; any other failure is 1) |
| 1 | Discovery modes, `GET /agents/configuration`, SDK fallback; `/capability/list` with `query`, `cursor`, `limit`; `/capability/describe` | M | A protocol client reads the server's configuration and lists capabilities; existing discovery fixture unchanged |
| 2 | `/agent/status` (moved from part 4: the client polls it during every approval and reads it before an execution, 1.1); host keys: schema columns, `hostjwt.go`, guarded JWKS fetch, `public_key` / `jwks_url` on `POST /agents/hosts`; `/agent/register` for pre-registered hosts; agent JWT rules of 2.4; `/agent/request-capability`; `/capability/execute` | L | The harness completes register → request → execute with a pre-registered host; a receipt is appended and verifies |
| 3 | Done. Dynamic hosts: `polaris_agent_registration`, the registration approval, linking, idempotency by host and agent key (§5.3), cleanup of expired registrations (a known host's too: its agent stays `pending` when the approval expires), strict per-IP rate limit for unknown hosts (§8.13) | L | The harness completes the whole flow from an unknown host with a person approving by user code, and the CI job stops accepting exit status 3; a denied registration is `rejected` and is not retried |
| 3b | Decisions 5.3, 5.7, 5.8 and 5.9 (what parts 2 and 3 left open), before part 4; 5.9 first | M | A key is taken only with its owner's proof; the tests that showed 5.3 and 5.9 pass the other way; the harness executes a capability with a `Location` |
| 4 | Lifecycle: `/agent/revoke`, `/host/revoke`, `/agent/rotate-key`, `/host/rotate-key`, lifetimes and `/agent/reactivate`, `/agent/introspect` | L | Every protocol endpoint in discovery answers per its section; rotation invalidates the old key at once; revocation seals the chain |
| 5 | Release: decision 83 with the security review note (AGENT.md rule 6), CHANGELOG, `plugins/agents/README.md`, `llms.txt`, `examples/agents`, `docs/stored-formats.md` | S | `v1.1.0` tagged by the release workflow |
| 6 | Optional, after 1.1: protocol client in the Go SDK (`agent.NewHost`), so a Go agent signs in to any Agent Auth provider, Better Auth servers included | M | The Go SDK completes the flow against Better Auth's `agent-deploy` example |

## 4. Acceptance for the whole package

1. `scripts/e2e-agent-auth.sh` passes (exit status 0, and the CI job stops accepting 3) with the unmodified `@auth/agent` client: discovery, dynamic
   host registration, device-code approval, capability request, execution, status, key rotation,
   revocation.
2. `auth-agent` (the CLI) and its MCP server connect to `examples/agents` in `DiscoveryAgentAuth`
   mode, given its URL (`--url` or `AGENT_AUTH_URLS`; without one they only ask the directory), and run
   a capability.
3. `TestTheGoAgentSDKWalksThrough` and the agents contract fixtures still pass unchanged in the
   default mode; no existing fixture is re-recorded.
4. `make apicheck BASE=v1.0.0` reports additions only.
5. `TestMigrateUpgradesEveryReleasedSchema` includes a `v1.0.0` export and passes on SQLite,
   PostgreSQL and MySQL; the new columns and table have DDL goldens.
6. Fuzz targets for the host JWT parser and the JWKS document validator, in the weekly job.
7. Tests named for each protocol MUST implemented, citing its section, so a later protocol version
   can be diffed against them. At least: thumbprint mismatch, wrong `typ`, `aud` not the issuer,
   replayed `jti`, `iat` 31 s ahead, key delivery mode changed, an agent under another host, an
   unknown constraint operator, a widened constraint, a pending host doing anything but registering,
   a JWKS URL that resolves to a private address.
8. A security review of parts 2 to 4, recorded in decision 83, before the tag.

## 5. Decisions

1. **Discovery. Decided: 2.2.** The question was whether clients tolerate absolute URLs in `endpoints`.
   The reference client does (0.6.2 and 0.5.1), and Better Auth's server sends them, so absolute URLs do
   not rule a merged document out. The names do: six protocol names are in the v1 document with other
   URLs and meanings (2.2), so a merged document changes the default one, which is frozen byte for byte
   (its fixture, rule 4, and any v1 client that reads `endpoints.register`). As a third choice for
   `Config.Discovery` it would only spare a v1.0.0 Go SDK its upgrade, at the price of an `execute` that
   is not the protocol's and of absolute URLs §5.1 does not allow.
2. **`suspended`. Decided: `pending`.** It is the protocol's only state that means "waits for a person" and that a
   host cannot leave by itself: §5.6 answers `reactivate` for a pending agent with 403 `agent_pending`, while for
   an expired one it must reactivate, which would let a host lift its owner's pause (or be refused against the
   section). The client's tool text asks for `reactivate` on `expired` only. A pause outranks the lifetimes: a
   suspended agent past its TTL reads `pending`, one past its absolute lifetime `revoked`. Its own calls stay 403
   `agent_suspended` (§5.13 allows more codes) and it introspects as inactive. Part 4 checks it in the harness.
3. **Approval strength in protocol mode. Decided: 2.7, with three rules it lacked.** Not built. Shown by throwaway tests
   on part 3: in this mode, with the defaults, a 14-minute-old session of a person without a second factor
   approves a high-risk grant; and with `AutoApprove[high]` and `Strengths[high]: passkey`, a `step_up` approval
   that links a host is followed by a high-risk execution nobody approved.
   - Every approval needs a sign-in within `StepUpMaxAge`, whatever `Strengths` says and with or without a second
     factor (§8.11, a MUST): `recent`, which only registrations check today.
   - Linking a host takes the strength of the riskiest tier `AutoApprove` names too: the link is the only time a
     person decides those. This holds wherever dynamic hosts are taken.
   - `passkey` means user verification: the session must have `mfa`, as a passkey session has only with it. With
     the passkey plugin's defaults it always does; with `NoMFAFactor` it may not. §8.11 also asks for
     `userVerification: "required"` in the challenge; the README tells the host to set it.
   - Defaults: `step_up` low, `passkey` medium and high (an undeclared risk is medium, so it fails closed). They
     apply in this mode only, which no release has. A server with them and without the passkey plugin could
     approve nothing, so it does not start: the error says to add the plugin or set `Strengths`.
   CIBA is not a second way to prove presence: nothing shows that it reaches another device.
4. **Who may introspect. Decided: trusted OAuth clients,** the rule `POST /oauth2/introspect` has, not a permission.
   Not built. A resource server is a confidential client an operator marked trusted (or listed in `TrustedClients`),
   authenticated as it is there. A permission would be held in an organization, so its administrators could give
   away reading other organizations' agents, and API keys act as people. Any other caller is 401. The answer adds
   `aud` (RFC 7662), and a JWT whose `aud` is not the issuer, the execute URL or a capability's `Location` is
   inactive, so that one resource server's JWT is not taken by another that reads only `active`.
5. **`budget_exhausted` on the protocol routes. Decided: `limit_exceeded`.** §5.13 defines it as a
   granted capability whose limits the request exceeds; `constraint_violated` is for arguments. The
   client treats neither specially.
6. **Version label. Decided: unchanged.** The protocol's own version is `1.0-draft`, so the Polaris
   document claims nothing the protocol's does not, and it is frozen for v1.
7. **Rate limits (§8.13, a MUST). Decided: by identity, after the JWT verifies, with a wide limit per address
   before it.** Not built. Today these routes share `token_refresh`, 60 a minute per address, with
   `POST /auth/token/refresh`: five agents waiting for approval behind one office address, polling each 5 s,
   use all of it, and then nobody there refreshes a session. So:
   - per agent 60 a minute and per host 300 a minute (§8.13's examples), in `agents.Config.RateLimits`, counted
     only for a verified JWT: a `sub` or `iss` anyone can write spends nobody's budget;
   - per address 600 a minute, its own key, before anything is verified, on these routes and the capability ones;
     discovery is a cached constant and has none. Unknown hosts keep their 5 an hour;
   - per capability is what budgets with a window do already; per user is left out until somebody needs it.
   The Polaris agent routes of v1.0.0 keep `token_refresh`; that they share it with the refresh is a follow-up.
8. **Capabilities with a `Location`. Decided: unwrap, for agents of a host with a key.** Not built. What decides is the
   stored host, never the body's shape: a capability may itself take arguments called `capability` and `arguments`.
   No other kind of agent belongs to such a host, so no v1.0.0 caller changes.
   - The body is `{capability, arguments}` and nothing else; `capability` must be the one of the location. `next`
     reads the bytes of `arguments` as they were sent, with `ContentLength` to match, so what was checked is what
     is read; `body_hash` covers the body as sent.
   - The JWT rules are 2.4's, which `Protect` does not apply today: `aud` exactly the configured `Location` (the
     Host header plays no part), 30 s of skew, the host's `iss` and revocation.
   - A 2xx JSON body is answered as `{"data": …}`, an empty one as `{"data": null}`: §5.11 requires it, and a
     handler's own `{"status": "pending", "status_url": …}` would otherwise read as an asynchronous answer that
     the client polls with its JWT. Other types and statuses pass as they are. Refusals are §5.13's.
   Leaving `location` out of the list was the other choice; a capability nobody can call is worse.
9. **Proof of possession for a pre-registered key. Decided: required, and it must be in before `v1.1.0` is tagged.** Not
   built. Shown by a throwaway test: Eve posts Ada's public key to `POST /agents/hosts`; Ada's client then
   registers and is `active` at once as Eve's agent, executes with nobody asked, and Ada's own registration of her key
   is 409. What Ada's agent writes lands in Eve's account. A public key is known to every server the host uses.
   - `POST /agents/hosts` with `public_key` or `jwks_url` takes `proof`: a JWT signed by that key, `typ`
     `host-link+jwt`, `iss` its thumbprint, `aud` the issuer, `sub` the account that will own the host (the user's
     id, or the organization's), `iat`, `exp` at most five minutes, `jti` once. Without it, 422.
   - Its own `typ` and `sub` matter: a host JWT would do for possession, but a server the client was lured to
     may claim our issuer (§8.9) and hold one; it says nothing of whose account the host joins.
   - The Go SDK signs one (`agent.SignHostLink`). The reference client cannot, and need not: its way in is the
     dynamic registration, where its own signature and a person's approval are the proof. Its `enroll_host` is no
     substitute: it posts a token and a public key, unsigned, so anyone's key could be sent with one's own token.
   Nothing released takes a key here, so nothing breaks.
10. **JWKS URLs of unknown hosts. Decided: refused, for good until a client needs them.** The server would fetch a
   URL an anonymous caller chose; §8.12's protections bound that, they do not make it free. The reference client has
   no way to send one, and a host has one owner (§2.9), so a shared cloud host with one URL could be linked to one
   person only. Such a host is registered by its owner (with 9's proof).
11. **Agent key rotation, for part 4.** The reference client's `rotateAgentKey` sends an agent JWT and no `agent_id`;
   §5.8 and §4.5.1 require a host JWT. Recommended: the host JWT only. Whoever stole an agent's key could otherwise
   replace it and lock the agent out. §4's acceptance then rotates the host's key with the client and the agent's
   with the client's keys, signed as §5.8 says.

## 6. Risks

- **The protocol moves.** It is a 1.0 draft, and §5.1.1 lets drafts break; Better Auth's own plugin
  calls itself unstable. Keeping the protocol surface in its own routes and specs (2.1) means a 1.1 or
  2.0 is a change to that surface only.
- **Two surfaces to secure.** Every check exists twice at the edge (credential, `aud`, replay) and
  once in the service. Part 2 moves the shared checks behind one function so the edges differ only in
  what §2.4 lists; the security review reads both edges.
- **Dynamic registration is an unauthenticated write path.** Anyone can create registration rows. The
  per-IP limit, the expiry and the cleanup (which registering itself runs) bound it; nothing else is
  written until a person approves.
- **Device-code phishing.** Somebody may send a person the code of a host that is not theirs (RFC 8628 §5.4).
  The approval needs a fresh sign-in, shows what is asked and by whom as the host tells it, and the README
  says what the page must say. A wrong code is counted per person, so codes are not found by trying.
- **JWKS fetching is server-side request forgery surface.** It goes through `netguard` only, and a
  host may turn JWKS URLs off (`Config.DisableJWKSURLs`; on in protocol mode only).
- **A pre-registered key is not proven.** Whoever knows a host's public key (any other server it uses,
  §9.1) could register it under their own account first: the host's agents would then act for them, not
  for the host's user, who would also get a 409. It gives no authority over anyone's data, but it
  misdirects an agent and what it writes. The dynamic path (part 3) has no such gap. Closed by 5.9, before the tag.
