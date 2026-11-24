# examples/agents

This example runs the whole agent story in one process ([`main.go`](main.go)). A Polaris server
offers two capabilities to AI agents. An agent, written with the Go agent SDK (package `agent`),
signs in and uses them, within the grants its owner approved.

| Capability | Risk | Runs | Approval |
|---|---|---|---|
| `invoices.list` | low | in process: a Go `Handler`, called with `POST /agents/execute` | the policy approves it at once, with a budget of 100 calls |
| `invoices.refund` | high | at the host's own route `POST /api/refunds`, behind `ag.Protect` | a person approves it (strength `step_up`) |

Both capabilities need permissions of the host's own (`cfg.Permissions`): `invoices.read` and
`invoices.refund`. An agent acts for its owner. Polaris checks that the owner still holds the
permission, and that the agent's grant, constraints and budget cover the call, before the handler
runs. Every execution appends a signed, hash-chained receipt.

## Run it

```sh
POLARIS_DEV=1 go run ./examples/agents           # the owner approves from Go
POLARIS_DEV=1 go run ./examples/agents -manual   # you approve with curl (step 5 below)
POLARIS_DEV=1 go run ./examples/agents -protocol # Agent Auth Protocol clients sign in too (below)
```

The example needs no setup:

- The database is SQLite in a temporary directory.
- With `POLARIS_DEV=1`, `polaris.DevEnv` generates `APP_KEY` and the JWT key pair at start when
  the environment lacks them (without it the example refuses to start). Set
  `APP_KEY`, `AUTH_JWT_PRIVATE_KEY`, `AUTH_JWT_PUBLIC_KEY` and `AUTH_ISSUER` (see
  [`examples/minimal`](../minimal/main.go)) to keep tokens across restarts.
- `ADDR` changes the listen address. The default is `localhost:8080`.

The program plays the story once, then keeps serving so you can inspect it with curl:

```
==> owner ada@example.com owns organization 01a20241-0982-…
==> owner minted a host enrollment token
==> agent 01a20241-0991-… enrolled (delegated, private_key_jwt)
==> grant invoices.list: active
==> grant invoices.refund: pending
==> approval 01a20241-0994-… waits for the owner (strength step_up)
==> grant invoices.refund: active
==> invoices.list -> {"invoices":[{"id":"inv_1","total":120},{"id":"inv_2","total":80}],"organization":"01a20241-0982-…"} (receipt #1)
==> refund 60 -> 200 map[agent:01a20241-0991-… invoice:inv_1 refunded:60] (receipt 01a20241…)
==> refund 500 -> 403 constraint_violated
==> refund 60 -> 403 budget_exhausted
==> receipt #1 invoices.list success: valid=true
==> receipt #2 invoices.refund success: valid=true
==> after the kill switch: agent: POST http://localhost:8080/agents/execute answered 401: The agent is revoked.
demo done; Polaris keeps serving on http://localhost:8080 (sign in as ada@example.com / "correct horse battery staple")
```

## The steps

Each step below is a numbered comment in `runDemo`.

1. **The owner.** `p.Users().Create` creates the owner, `p.Orgs().Create` creates the organization,
   and `p.Sessions().Issue` signs the owner in, scoped to the organization (`SignIn.OrganizationID`).
   A real owner signs up and in over HTTP instead (`/auth/register`, `/auth/login`, then
   `/auth/switch-org`).
2. **The host token.** The owner calls `POST /agents/hosts` and gets an enrollment token (`peh_…`)
   for the machine the agent runs on.
3. **Enrolment.** The agent creates its own key pair with `agent.GenerateKey`. Persist
   `key.Export()` to keep the identity. It then enrols with `Enroll(ctx, peh, Registration{…})` and
   becomes an OAuth client with `private_key_jwt`.
4. **Grants.** The agent asks for both grants with `RequestGrants`. It proposes limits for the
   refund grant: at most 100 per call, and 100 in total
   (`{"amount": {"max": 100}, "budget": {"amount": 100, "field": "amount"}}`). The policy approves
   the low-risk grant at once. The high-risk grant waits, and the answer carries an `Approval`
   with a user code.
5. **Approval.** A person approves at the strength the risk needs. `step_up` means the owner
   re-authenticated recently, or has no second factor to re-authenticate with. Meanwhile
   `WaitForApproval` polls `GET /agents/session`.
6. **Execute in process.** `Execute(ctx, "invoices.list", nil)` sends a request JWT signed for the
   exact URL, method and body. The answer holds the handler's result and the receipt.
7. **Execute at the host.** `bot.Do(req)` signs the request JWT for `POST /api/refunds`.
   `ag.Protect("invoices.refund", h)` checks the grant, the input schema, the constraints and the
   budget before `h` runs. In `h`, `agents.CallFrom(r.Context())` tells you the agent, the grant
   and the arguments, and the response gets `X-Polaris-Receipt`. The three calls show each outcome:
   - 60 passes.
   - 500 breaks the per-call cap and gets `constraint_violated`.
   - The second 60 is more than the 40 left and gets `budget_exhausted`.

   A refusal spends nothing and never reaches the handler.
8. **Receipts.** The owner exports the chain with `GET /agents/{id}/receipts`.
   `bot.VerifyReceipt(ctx, r, prev)` checks each receipt's hash, its signature (against the
   server's JWKS) and its link to the previous receipt.
9. **Kill switch.** The owner calls `POST /agents/{id}/revoke`. The agent, its OAuth client and its
   tokens are revoked, and the receipt chain is sealed. The agent's next call is a 401.

## Walk through it with curl

Start the server with `-manual`. It stops at step 5 until you approve. The output below is real,
with ids shortened.

```sh
POLARIS_DEV=1 go run ./examples/agents -manual
B=http://localhost:8080
J='Content-Type: application/json'
```

### What the server offers (no token needed)

```sh
curl -s $B/.well-known/agent-configuration | jq -c '{provider_name, issuer, modes, approval_methods, approval_strengths}'
```

```json
{"provider_name":"Polaris","issuer":"http://localhost:8080","modes":["delegated","autonomous"],"approval_methods":["device_authorization","ciba","in_app"],"approval_strengths":{"high":"step_up","low":"session","medium":"session"}}
```

```sh
curl -s $B/agents/capabilities | jq -c '.data.capabilities[] | {name, risk, permission, location}'
```

```json
{"name":"invoices.list","risk":"low","permission":"invoices.read","location":null}
{"name":"invoices.refund","risk":"high","permission":"invoices.refund","location":"http://localhost:8080/api/refunds"}
```

### Sign in as the owner

```sh
SESSION=$(curl -s $B/auth/login -H "$J" \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}' | jq -r .data.access_token)
ORG=$(curl -s $B/orgs -H "Authorization: Bearer $SESSION" | jq -r '.data[0].id')
OWNER=$(curl -s $B/auth/switch-org -H "Authorization: Bearer $SESSION" -H "$J" \
  -d "{\"organization_id\":\"$ORG\"}" | jq -r .data.access_token)
```

### Step 5: approve the refund grant

```sh
curl -s $B/agents/approvals -H "Authorization: Bearer $OWNER" \
  | jq -c '.data[] | {id, strength, status, user_code, agent: .agent.name, grants: [.grants[] | {capability, constraints, status}]}'
```

```json
{"id":"01a20241-0994-…","strength":"step_up","status":"pending","user_code":"ZKSP-XXCP","agent":"Refund bot","grants":[{"capability":"invoices.refund","constraints":{"amount":{"max":100}},"status":"pending"}]}
```

```sh
APPROVAL=$(curl -s $B/agents/approvals -H "Authorization: Bearer $OWNER" | jq -r '.data[0].id')
curl -s $B/agents/approvals/$APPROVAL/decide -H "Authorization: Bearer $OWNER" -H "$J" \
  -d '{"decision":"approve"}' | jq -c '.data | {status, grants: [.grants[] | {capability, status, budget}]}'
```

```json
{"status":"approved","grants":[{"capability":"invoices.refund","status":"active","budget":{"field":"amount","kind":"amount","remaining":100,"total":100}}]}
```

`{"decision":"deny"}` refuses the grant instead, and `WaitForApproval` returns
`agent.ErrApprovalDenied`. The demo goes on from step 6 within a few seconds, the next poll.

### After the run: the agent, its receipts, the audit trail

```sh
curl -s $B/agents -H "Authorization: Bearer $OWNER" | jq -c '.data[] | {id, name, mode, status, sealed_at}'
```

```json
{"id":"01a20241-0991-…","name":"Refund bot","mode":"delegated","status":"revoked","sealed_at":"2026-11-22T07:56:16+00:00"}
```

```sh
AGENT=$(curl -s $B/agents -H "Authorization: Bearer $OWNER" | jq -r '.data[0].id')
curl -s $B/agents/$AGENT/receipts -H "Authorization: Bearer $OWNER" \
  | jq -c '.data[] | {seq, capability, outcome, budget_before, budget_after, prev_hash: (.prev_hash // "" | .[0:12]), hash: .hash[0:12]}'
```

```json
{"seq":1,"capability":"invoices.list","outcome":"success","budget_before":100,"budget_after":99,"prev_hash":"","hash":"6dd2805eb8fb"}
{"seq":2,"capability":"invoices.refund","outcome":"success","budget_before":100,"budget_after":40,"prev_hash":"6dd2805eb8fb","hash":"eff819f40459"}
{"seq":3,"capability":null,"outcome":"sealed","budget_before":null,"budget_after":null,"prev_hash":"eff819f40459","hash":"bdcedee0568c"}
```

The kill switch appended the `sealed` receipt, so nothing can be added after it. The server
rechecks any receipt:

```sh
RECEIPT=$(curl -s $B/agents/$AGENT/receipts -H "Authorization: Bearer $OWNER" | jq -r '.data[-1].id')
curl -s $B/agents/receipts/$RECEIPT/verify -H "Authorization: Bearer $OWNER" | jq -c '.data.checks'
```

```json
{"chain":true,"hash":true,"signature":true}
```

Every step is in the organization's audit log (`plugins/audit`), newest first:

```sh
curl -s $B/audit/organization/$ORG -H "Authorization: Bearer $OWNER" \
  | jq -c '[.data[] | .name] | map(select(startswith("agent")))'
```

```json
["agent.receipt.sealed","agent.revoked","agent.execution_denied","agent.execution_denied","agent.executed","agent.executed","agent.grant.approved","agent.grant.approved","agent.grant.requested","agent.enrolled"]
```

## An Agent Auth Protocol client

With `-protocol` the server's discovery document is the
[Agent Auth Protocol](https://agent-auth-protocol.com/specification)'s, and any client of it signs in, here the unmodified
[`@auth/agent-cli`](https://www.npmjs.com/package/@auth/agent-cli) 0.5.1 (Node 22 or newer). The demo above runs as before: the Go agent
SDK reads `/agents/configuration` by itself.

```sh
POLARIS_DEV=1 go run ./examples/agents -protocol
alias auth-agent='npx -y @auth/agent-cli@0.5.1 --url http://localhost:8080 --no-browser' # --url takes a list: keep a flag after it
auth-agent connect --provider http://localhost:8080 --name "CLI bot" \
  --capabilities invoices.list invoices.refund --constraints '{"invoices.refund":{"amount":{"max":100}}}'
```

```
Approval required. Open: http://localhost:8080/approve?user_code=VMSB-CPTK
  Code: VMSB-CPTK
```

The server has never seen this host, and nothing of it exists yet. Your `ApprovalURL` page would show who asks for what;
in another shell, as the owner ([sign in](#sign-in-as-the-owner) first), curl stands in for it. Use the code you were shown:

```sh
APPROVAL=$(curl -s "$B/agents/approvals/code?user_code=VMSB-CPTK" -H "Authorization: Bearer $OWNER" | jq -r .data.id)
curl -s $B/agents/approvals/$APPROVAL/decide -H "Authorization: Bearer $OWNER" -H "$J" -d '{"decision":"approve"}' | jq -c .data.status
```

The client prints its agent's id and goes on. Grant, constraints, budget and receipts are the same as any agent's:

```sh
auth-agent execute $ID invoices.list --args '{}'
auth-agent execute $ID invoices.refund --args '{"invoice_id":"inv_1","amount":60}'  # {"data":{"agent":…,"refunded":60}}
auth-agent execute $ID invoices.refund --args '{"invoice_id":"inv_1","amount":500}' # Error: The arguments violate the grant's constraints.
auth-agent disconnect $ID                                                           # the kill switch
```

`auth-agent mcp`, with the same flags, is the same client as an MCP server for your assistant. The demo asks `step_up` for the
high-risk capability because its owner has no passkey; a real host adds the passkey plugin
([why](../../plugins/agents/README.md#agent-auth-protocol)).

## The host's permissions

`invoices.read` and `invoices.refund` are the host's own permissions (`cfg.Permissions`), and
`cfg.RolePermissions = map[string][]string{"owner": {"invoices.read", "invoices.refund"}}` puts
them in every organization's owner role. Without that, approving the agent's grants fails with
`agents/permission_not_held`: only what you hold can be granted.

## Test

[`main_test.go`](main_test.go) boots the same server on a real listener and plays `runDemo`:

```sh
go test ./examples/agents
```
