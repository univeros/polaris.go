# Agent Auth Protocol compatibility

Status: **draft** (2026-11-24). Not yet a decision; when work starts it is logged as decision 83 in
[`decisions.md`](decisions.md). Target release: `v1.1.0` (additive; nothing in v1 breaks).

Reference: Agent Auth Protocol v1.0, <https://agent-auth-protocol.com/specification> (§ numbers below
are the protocol's). Sections 1 to 8.13 were read for this document. **§8.14 to §10 (the rest of the
security section, privacy, extensions) were not**; item 0.1 closes that before any code.

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
| Discovery `version` | `1.0` | `1.0-draft` | Value |
| Discovery `endpoints` | Paths relative to `issuer`; 12 named endpoints | Absolute URLs; keys `register`, `enroll`, `capabilities`, `execute`, `request_capability`, `status`, `revoke`, `grants`, `approvals`, `receipts`, `token`, `mcp` | Format and set differ; `register` and `status` mean different things |
| Discovery `algorithms` | `Ed25519` | `ES256`, `EdDSA` (JOSE names) | Value |
| Host identity | Key pair; `host+jwt` with `iss` = RFC 7638 thumbprint; inline JWK or JWKS URL | `peh_` enrolment token, stored as a keyed hash; a host always has an owner | Whole mechanism |
| Host establishment | Dynamic (unknown host, `pending` until a person approves) or pre-registered | An owner creates the host first (`POST /agents/hosts`) | Dynamic hosts |
| Agent registration | `POST /agent/register` with a host JWT carrying the agent's key | `POST /agents/enroll` with the `peh_` token and a `jwk` field; or `POST /agents/register` with the owner's session | Route and credential |
| Agent JWT | `typ agent+jwt`; `iss` host thumbprint; `sub` agent id; `aud` the issuer, or the location for execution; 60 s recommended | `typ agent+jwt`; `iss` not read; `sub` agent id; `aud` the exact URL called; `exp - iat` at most 5 min; `htm`, `htu`, `body_hash` checked when present; `jti` once | `aud` on non-execution calls; clock rules |
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
spec in `internal/apispec/api/agents/protocol/*.yaml` and a recorded fixture, like every other route
(AGENT.md rules 3 and 4).

An agent registered through either surface is the same `polaris_agent` row and the same OAuth client.
It can be listed, suspended, revoked and audited through the existing owner and operator routes, and
its executions append to the same receipt chain.

### 2.2 Discovery

One origin has one `/.well-known/agent-configuration`, and the two client families read it
differently: the Go SDK takes `endpoints` as absolute URLs and needs `enroll`;
a protocol client takes them as paths relative to `issuer` and needs the twelve protocol names. One
document cannot satisfy both.

- `agents.Config.Discovery` chooses the document at the well-known path:
  `agents.DiscoveryPolaris` (default: today's document, byte for byte) or
  `agents.DiscoveryAgentAuth` (the strict protocol document: `version: "1.0"`, relative endpoint
  paths, `algorithms: ["Ed25519"]`, `approval_methods: ["device_authorization", "ciba"]`).
- The Polaris document is also always served at a new route, `GET /agents/configuration`.
- The Go agent SDK (`agent.New`) falls back to `/agents/configuration` when the well-known document
  has no `enroll` endpoint. Released SDKs keep working against a server in the default mode.
- The protocol routes are served in both modes. `Discovery` only decides which client family finds
  the server by itself.

This is open decision 5.1.

### 2.3 Hosts with keys

`polaris_agent_host` gains nullable columns (additive, as decision 63 requires): `publicJwk`,
`jwksUrl`, `keyThumbprint` (unique index), `status`. A row without a key is a token host, as today.

- **Pre-registered host.** `POST /agents/hosts` accepts an optional `public_key` (JWK) or
  `jwks_url`. The owner pastes the host's public key; the host is `active` at once and linked to that
  owner. This is the path for first-party fleets (Vela's Nightwatch, Venant, Tarazed).
- **Dynamic host.** A host JWT from an unknown thumbprint on `POST /agent/register` creates nothing
  in `polaris_agent_host` or `polaris_agent`. It creates a row in a new table,
  `polaris_agent_registration` (the future agent id, the host and agent keys or JWKS URLs, names,
  mode, the capabilities asked, the approval id, expiry). The response is the protocol's `pending`
  registration with a device-authorization approval. When a signed-in person approves at the required
  strength, one transaction creates the host owned by that person, the agent (through the existing
  `createAgent`, so it is an OAuth client like any other) and the grants, and deletes the registration
  row. Denied: the row is marked `rejected`. Expired: a maintenance pass deletes it (§7.1: cleanup
  deletes, it does not revoke).
- Nothing is trusted, granted or shown as an agent before that approval (§8.10). The approving
  person is the only link a host has; a host is never linked to two users (§2.9).
- Host JWT verification is a new `hostjwt.go` beside `requestjwt.go`: `typ host+jwt` only; `iss`
  equals the thumbprint of the verifying key; `aud` equals the issuer; `iat`, `exp`, `jti` required;
  `iat` at most 30 s ahead; `jti` once through `cache.Add` (atomic across replicas, as the agent JWT
  does); the key delivery mode (inline or JWKS URL) fixed at registration (§8.7).
- JWKS URLs are fetched with `internal/netguard` (public addresses only), HTTPS only, at most 3
  redirects, a response size cap and a timeout, cached; the document must be a valid JWKS with the
  expected `kid` and no symmetric key (§8.12).

### 2.4 Agent JWTs on the protocol routes

The existing verifier is reused with three differences, on the protocol routes only:

- `aud` is the issuer on non-execution routes; on `/capability/execute` and on a capability
  `Location` it is the exact URL, as today.
- `iss` must be the current thumbprint of the agent's host; the agent is found by `sub` and must
  belong to that host (§4.5 steps 4 and 5).
- `iat` at most 30 s ahead; the replay window covers the whole accepted lifetime.

`htm`, `htu` and `body_hash` stay accepted and checked when present. Only Ed25519 keys register
through the protocol routes; ES256 stays available on the Polaris routes.

### 2.5 States and lifetimes

| Polaris | Reported on the protocol routes |
|---|---|
| registration row, undecided | `pending` |
| registration row, denied | `rejected` |
| `active`, inside its lifetimes | `active` |
| `active`, past session TTL or max lifetime | `expired` |
| `suspended` | open decision 5.2 |
| `revoked` (kill switch, or absolute lifetime passed) | `revoked` |

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
  `budget_exhausted` on the Polaris routes (confirm against §8.14 onward in 0.1).
- New `agents.Err*` names for those codes are additive to the v1 API.

### 2.7 Approval strength

The protocol requires fresh authentication on every approval, and proof of presence (WebAuthn with
user verification, or out-of-band CIBA) for capabilities that change data or act for the user
(§8.11). Polaris's defaults are `session` for low and medium risk and `step_up` for high. In
`DiscoveryAgentAuth` mode the defaults become `step_up` for low and `passkey` for medium and high; a
host may still set `Strengths` itself, and the README says what that departs from. Open decision 5.3.

### 2.8 Introspection

`POST /agent/introspect` follows §5.12 and RFC 7662. It is not public: the caller presents a Polaris
credential (API key or OAuth client) holding a new permission, `agents.introspect`, and the route is
rate limited. A valid JWT is not consumed by introspection (its `jti` is not spent).

---

## 3. Work, in order

Each part is one pull request with `make qa`, the database matrix and `make apicheck` green.

| # | Part | Size | Done when |
|---|---|---|---|
| 0.1 | Read §8.14 to §10 of the protocol and the source of `@auth/agent`; amend this document where they contradict it | S | The "not read" note at the top is gone; open questions in §5 are answered or still listed |
| 0.2 | Interop harness: `scripts/e2e-agent-auth.sh` starts a small server (`internal/e2e/agentauthserver`) and runs the unmodified `@auth/agent` client against it. Decision 30 did this for `@polaris-auth/agent`; that script and its server were removed with decision 53, so this one is new. It needs Node in CI: a separate job, not part of `make qa` | S | The script runs and fails at registration, for the expected reason |
| 1 | Discovery modes, `GET /agents/configuration`, SDK fallback; `/capability/list` with `query`, `cursor`, `limit`; `/capability/describe` | M | A protocol client reads the server's configuration and lists capabilities; existing discovery fixture unchanged |
| 2 | Host keys: schema columns, `hostjwt.go`, guarded JWKS fetch, `public_key` / `jwks_url` on `POST /agents/hosts`; `/agent/register` for pre-registered hosts; agent JWT rules of 2.4; `/agent/request-capability`; `/capability/execute` | L | The harness completes register → request → execute with a pre-registered host; a receipt is appended and verifies |
| 3 | Dynamic hosts: `polaris_agent_registration`, the registration approval, linking, idempotency by host and agent key (§5.3), cleanup of expired registrations, strict per-IP rate limit for unknown hosts (§8.13) | L | The harness completes the whole flow from an unknown host with a person approving by user code; a denied registration is `rejected` and is not retried |
| 4 | Lifecycle: `/agent/status`, `/agent/revoke`, `/host/revoke`, `/agent/rotate-key`, `/host/rotate-key`, lifetimes and `/agent/reactivate`, `/agent/introspect` | L | Every protocol endpoint in discovery answers per its section; rotation invalidates the old key at once; revocation seals the chain |
| 5 | Release: decision 83 with the security review note (AGENT.md rule 6), CHANGELOG, `plugins/agents/README.md`, `llms.txt`, `examples/agents`, `docs/stored-formats.md` | S | `v1.1.0` tagged by the release workflow |
| 6 | Optional, after 1.1: protocol client in the Go SDK (`agent.NewHost`), so a Go agent signs in to any Agent Auth provider, Better Auth servers included | M | The Go SDK completes the flow against Better Auth's `agent-deploy` example |

## 4. Acceptance for the whole package

1. `scripts/e2e-agent-auth.sh` passes with the unmodified `@auth/agent` client: discovery, dynamic
   host registration, device-code approval, capability request, execution, status, key rotation,
   revocation.
2. `auth-agent` (the CLI) and its MCP server connect to `examples/agents` in `DiscoveryAgentAuth`
   mode and run a capability.
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

## 5. Open decisions

1. **Discovery.** As 2.2 (a host-chosen document, the other one at `/agents/configuration`), or one
   merged document. Merged is only possible if the protocol's clients tolerate absolute URLs in
   `endpoints`; 0.1 answers that from the client source. Recommended: 2.2.
2. **`suspended`.** The protocol has no paused state. Options: report `expired` (the client will try
   `reactivate`, which then answers 403 with a message saying the owner paused the agent), or report
   `pending` (the client polls until the owner resumes). Recommended: decide with the harness in
   part 4, by which of the two the reference client handles without looping.
3. **Approval strength defaults in protocol mode.** As 2.7, or keep today's defaults and document the
   departure from §8.11. Recommended: 2.7.
4. **Who may introspect.** A permission (2.8), or operators only.
5. **`budget_exhausted` on the protocol routes.** `limit_exceeded`, or `constraint_violated` with a
   `violations` entry for the budget. Depends on what §8.14 onward and the client make of
   `limit_exceeded`.
6. **Version label.** Whether the default Polaris document keeps saying `1.0-draft` (a fixture
   freezes it) or is re-recorded to a Polaris-specific value so nobody mistakes it for the protocol's.

## 6. Risks

- **The protocol moves.** It reached 1.0 this year and Better Auth's own plugin calls itself
  unstable. Keeping the protocol surface in its own routes and specs (2.1) means a 1.1 or 2.0 is a
  change to that surface only.
- **Two surfaces to secure.** Every check exists twice at the edge (credential, `aud`, replay) and
  once in the service. Part 2 moves the shared checks behind one function so the edges differ only in
  what §2.4 lists; the security review reads both edges.
- **Dynamic registration is an unauthenticated write path.** Anyone can create registration rows. The
  per-IP limit, the expiry and the cleanup pass bound it; nothing else is written until a person
  approves.
- **JWKS fetching is server-side request forgery surface.** It goes through `netguard` only, and a
  host may turn JWKS URLs off (`Config.AllowJWKSURLs`, default on in protocol mode only).
