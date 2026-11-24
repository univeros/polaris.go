// Drives the unmodified @auth/agent client against the server at AGENT_AUTH_URL, with the session of a
// person in AGENT_AUTH_OWNER (scripts/e2e-agent-auth.sh). § numbers are the Agent Auth Protocol's.
//
// Exit status: 0 the whole flow passed; 3 it stopped where docs/agent-auth-compat.md says the server
// stops today; 1 anything else.
import assert from "node:assert/strict";
import { AgentAuthClient, AgentAuthSDKError, generateKeypair, MemoryStorage } from "@auth/agent";

const url = process.env.AGENT_AUTH_URL;
// urls: without it the client only asks the public directory and never this server.
const client = new AgentAuthClient({ urls: [url], hostName: "polaris-e2e", approvalTimeoutMs: 10_000 });

async function step(name, run) {
  try {
    const out = await run();
    console.log(`ok   ${name}`);
    return out;
  } catch (err) {
    console.error(`FAIL ${name}`);
    throw err;
  }
}

const names = (page) => page.capabilities.map((c) => c.name);

async function readsTheServer() {
  await step("discovery (§5.1)", async () => {
    const [config] = await client.init();
    assert.ok(config, `the client found no configuration at ${url}`);
    assert.equal(config.version, "1.0-draft");
    assert.equal(config.issuer, url);
    assert.deepEqual(config.algorithms, ["Ed25519"]);
    for (const path of Object.values(config.endpoints)) assert.match(path, /^\//, "§5.1: relative to issuer");
  });
  await step("list the capabilities (§5.2)", async () => {
    const page = await client.listCapabilities({ provider: url });
    assert.deepEqual(names(page), ["invoices.list", "invoices.refund"]);
    assert.equal(page.has_more, false);
    assert.ok(page.capabilities.every((c) => !("grant_status" in c)), "no grant status without an agent");
  });
  await step("list them page by page (§5.2)", async () => {
    const first = await client.listCapabilities({ provider: url, limit: 1 });
    assert.deepEqual([names(first), first.has_more], [["invoices.list"], true]);
    const last = await client.listCapabilities({ provider: url, limit: 1, cursor: first.next_cursor });
    assert.deepEqual([names(last), last.has_more], [["invoices.refund"], false]);
  });
  await step("search them (§5.2)", async () => {
    assert.deepEqual(names(await client.listCapabilities({ provider: url, query: "Refund" })), ["invoices.refund"]);
    assert.equal((await client.search("refund an invoice"))[0]?.name, "invoices.refund");
  });
  await step("describe one (§5.2.1)", async () => {
    const c = await client.describeCapability({ provider: url, name: "invoices.refund" });
    assert.deepEqual(c.input.required, ["invoice_id"]);
    await assert.rejects(client.describeCapability({ provider: url, name: "nothing" }), { code: "capability_not_found", status: 404 });
  });
}

// owner calls a route of Polaris's own as the person who owns the host.
async function owner(method, path, body) {
  const res = await fetch(url + path, {
    method,
    headers: { authorization: `Bearer ${process.env.AGENT_AUTH_OWNER}`, "content-type": "application/json" },
    body: body && JSON.stringify(body),
  });
  const answer = await res.json();
  assert.ok(res.ok, `${method} ${path}: ${res.status} ${JSON.stringify(answer)}`);
  return answer.data;
}

// decide is what a person does with the code the client showed them.
let decision = "approve";
async function decide(approval) {
  assert.equal(approval.method, "device_authorization");
  assert.ok(approval.verification_uri && approval.user_code, "§7.1: a URL and a code");
  const waiting = await owner("GET", `/agents/approvals/code?user_code=${encodeURIComponent(approval.user_code)}`);
  await owner("POST", `/agents/approvals/${waiting.id}/decide`, { decision });
}

// aPreRegisteredHost signs an agent in through a host whose key its owner registered (§2.8).
async function aPreRegisteredHost() {
  const keypair = await generateKeypair();
  const storage = new MemoryStorage();
  await storage.setHostIdentity({ keypair, createdAt: Date.now() });
  const host = await owner("POST", "/agents/hosts", { name: "Nightwatch", public_key: keypair.publicKey });
  const client = new AgentAuthClient({ urls: [url], storage, hostName: "polaris-e2e", approvalTimeoutMs: 20_000, onApprovalRequired: decide });
  await client.init();

  await step("list the capabilities with a host's key (§5.2)", async () => {
    assert.equal((await client.listCapabilities({ provider: url })).capabilities.length, 2);
  });
  const agent = await step("register an agent, approved by policy (§5.3)", async () => {
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "e2e", reason: "the harness" });
    assert.deepEqual([out.status, out.hostId, out.capabilityGrants.map((g) => g.status)], ["active", host.id, ["active"]]);
    return out.agentId;
  });
  await step("execute a capability (§5.11)", async () => {
    const out = await client.executeCapability({ agentId: agent, capability: "invoices.list" });
    assert.deepEqual(out, { data: ["inv_1", "inv_2"] });
  });
  await step("list with grant status (§5.2)", async () => {
    const page = await client.listCapabilities({ provider: url, agentId: agent });
    assert.deepEqual(page.capabilities.map((c) => c.grant_status), ["granted", "not_granted"]);
    assert.equal((await client.describeCapability({ provider: url, name: "invoices.list", agentId: agent })).grant_status, "granted");
  });
  await step("request a capability, approved by a person (§5.4)", async () => {
    const constraints = { invoice_id: { in: ["inv_1"] } };
    const out = await client.requestCapability({ agentId: agent, capabilities: [{ name: "invoices.refund", constraints }] });
    assert.ok(out.granted.includes("invoices.refund"), JSON.stringify(out));
    await assert.rejects(client.requestCapability({ agentId: agent, capabilities: ["invoices.refund"] }), { code: "already_granted", status: 409 });
  });
  await step("execute it within its constraints (§5.11)", async () => {
    const out = await client.executeCapability({ agentId: agent, capability: "invoices.refund", arguments: { invoice_id: "inv_1" } });
    assert.deepEqual(out, { data: { refunded: "inv_1" } });
    const other = client.executeCapability({ agentId: agent, capability: "invoices.refund", arguments: { invoice_id: "inv_2" } });
    await assert.rejects(other, { code: "constraint_violated", status: 403 });
  });
  await step("execute in a batch: the client falls back to one by one", async () => {
    const { responses } = await client.batchExecuteCapabilities({ agentId: agent, requests: [{ capability: "invoices.list" }] });
    assert.deepEqual(responses.map((r) => r.status), ["completed"]);
  });
  await step("status (§5.5)", async () => {
    const out = await client.agentStatus(agent);
    assert.deepEqual([out.status, out.mode, out.agent_capability_grants.map((g) => g.status)], ["active", "delegated", ["active", "active"]]);
    assert.ok(out.created_at);
  });
  await step("every execution left a receipt, and each verifies", async () => {
    const receipts = await owner("GET", `/agents/${agent}/receipts`);
    assert.equal(receipts.length, 3);
    for (const r of receipts) assert.equal((await owner("GET", `/agents/receipts/${r.id}/verify`)).valid, true);
  });
  await step("register an agent a person must approve (§5.3)", async () => {
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.refund"], name: "approved" });
    assert.deepEqual([out.status, out.capabilityGrants.map((g) => g.status)], ["active", ["active"]]);
  });
  await step("a denied registration is rejected (§7.1)", async () => {
    decision = "deny";
    const denied = client.connectAgent({ provider: url, capabilities: ["invoices.refund"], name: "denied" });
    await assert.rejects(denied, { code: "agent_rejected" });
  });
  await step("the owner revokes the host: its agents are revoked (§8.5)", async () => {
    await owner("DELETE", `/agents/hosts/${host.id}`);
    const late = client.executeCapability({ agentId: agent, capability: "invoices.list" });
    await assert.rejects(late, { code: "agent_revoked", status: 403 });
    await assert.rejects(client.agentStatus(agent), { code: "host_revoked", status: 403 });
  });
}

// anUnknownHostRegisters answers false when the server refuses a host it does not know.
async function anUnknownHostRegisters() {
  let refusal;
  try {
    await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "e2e" });
    return true;
  } catch (err) {
    refusal = err;
  }
  if (!(refusal instanceof AgentAuthSDKError) || refusal.status !== 401 || refusal.code !== "invalid_jwt" || !/unknown/.test(refusal.message)) {
    console.error("FAIL register from an unknown host (§5.3): not the refusal of an unknown host");
    throw refusal;
  }
  // The client has a host key now and signs a host JWT with it, which the server does not know.
  await step("list the capabilities with an unknown host key (§5.2)", async () => {
    assert.equal(names(await client.listCapabilities({ provider: url })).length, 2);
  });
  return false;
}

try {
  await readsTheServer();
  await aPreRegisteredHost();
  if (!(await anUnknownHostRegisters())) {
    console.error(
      "STOP register from an unknown host (§2.8, §5.3): POST /agent/register answered 401 invalid_jwt. Expected for\n" +
        "     now: dynamic hosts are part 3 of docs/agent-auth-compat.md, which is not built. Everything before it passed.",
    );
    process.exit(3);
  }
  console.error("FAIL the server registers unknown hosts now: extend client.mjs to the next part of docs/agent-auth-compat.md");
  process.exit(1);
} catch (err) {
  console.error(err);
  process.exit(1);
}
