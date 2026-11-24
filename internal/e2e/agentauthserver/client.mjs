// Drives the unmodified @auth/agent client against the server at AGENT_AUTH_URL, with the session of a
// person in AGENT_AUTH_OWNER (scripts/e2e-agent-auth.sh). § numbers are the Agent Auth Protocol's.
//
// Exit status: 0 the whole flow passed; 1 anything else.
import assert from "node:assert/strict";
import { createHash, createPrivateKey, randomUUID, sign } from "node:crypto";
import { AgentAuthClient, generateKeypair, MemoryStorage } from "@auth/agent";

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
    assert.deepEqual(names(page), ["invoices.list", "invoices.refund", "invoices.send"]);
    assert.equal(page.capabilities[2].location, `${url}/api/invoices/send`);
    assert.equal(page.has_more, false);
    assert.ok(page.capabilities.every((c) => !("grant_status" in c)), "no grant status without an agent");
  });
  await step("list them page by page (§5.2)", async () => {
    const first = await client.listCapabilities({ provider: url, limit: 1 });
    assert.deepEqual([names(first), first.has_more], [["invoices.list"], true]);
    const last = await client.listCapabilities({ provider: url, limit: 2, cursor: first.next_cursor });
    assert.deepEqual([names(last), last.has_more], [["invoices.refund", "invoices.send"], false]);
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

// signed is a JWT of the type signed with a host's own key.
function signed(typ, { publicKey, privateKey }, claims) {
  const b64 = (v) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const { crv, kty, x } = publicKey;
  const iss = createHash("sha256").update(JSON.stringify({ crv, kty, x })).digest("base64url");
  const iat = Math.floor(Date.now() / 1000);
  const input = `${b64({ typ, alg: "EdDSA" })}.${b64({ iss, aud: url, iat, exp: iat + 60, jti: randomUUID(), ...claims })}`;
  return `${input}.${sign(null, Buffer.from(input), createPrivateKey({ key: privateKey, format: "jwk" })).toString("base64url")}`;
}

// hostLink is the proof POST /agents/hosts takes with a key (decision 5.9), which the client has no way to
// make: for the owner of the session.
function hostLink(keypair) {
  const { sub } = JSON.parse(Buffer.from(process.env.AGENT_AUTH_OWNER.split(".")[1], "base64url"));
  return signed("host-link+jwt", keypair, { sub });
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
  const host = await owner("POST", "/agents/hosts", { name: "Nightwatch", public_key: keypair.publicKey, proof: hostLink(keypair) });
  const client = new AgentAuthClient({ urls: [url], storage, hostName: "polaris-e2e", approvalTimeoutMs: 20_000, onApprovalRequired: decide });
  await client.init();

  await step("list the capabilities with a host's key (§5.2)", async () => {
    assert.equal((await client.listCapabilities({ provider: url })).capabilities.length, 3);
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
    assert.deepEqual(page.capabilities.map((c) => c.grant_status), ["granted", "not_granted", "not_granted"]);
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
  await step("execute a capability at its location (§2.15)", async () => {
    const asked = await client.requestCapability({ agentId: agent, capabilities: ["invoices.send"] });
    assert.ok(asked.granted.includes("invoices.send"), JSON.stringify(asked));
    const out = await client.executeCapability({ agentId: agent, capability: "invoices.send", arguments: { invoice_id: "inv_1" } });
    assert.deepEqual(out, { data: { status: "pending", sent: "inv_1" } });
    await assert.rejects(client.executeCapability({ agentId: agent, capability: "invoices.send", arguments: {} }), { code: "invalid_request", status: 400 });
  });
  await step("execute in a batch: the client falls back to one by one", async () => {
    const { responses } = await client.batchExecuteCapabilities({ agentId: agent, requests: [{ capability: "invoices.list" }] });
    assert.deepEqual(responses.map((r) => r.status), ["completed"]);
  });
  await step("status (§5.5)", async () => {
    const out = await client.agentStatus(agent);
    assert.deepEqual([out.status, out.mode, out.agent_capability_grants.map((g) => g.status)], ["active", "delegated", ["active", "active", "active"]]);
    assert.ok(out.created_at);
  });
  await step("every execution left a receipt, and each verifies", async () => {
    const receipts = await owner("GET", `/agents/${agent}/receipts`);
    assert.equal(receipts.length, 4);
    for (const r of receipts) assert.equal((await owner("GET", `/agents/receipts/${r.id}/verify`)).valid, true);
  });
  await step("register an agent a person must approve (§5.3)", async () => {
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.refund"], name: "approved" });
    assert.deepEqual([out.status, out.capabilityGrants.map((g) => g.status)], ["active", ["active"]]);
  });
  await step("a paused agent: the client is told to wait, and cannot reactivate it (5.2)", async () => {
    await owner("POST", `/agents/${agent}/suspend`);
    assert.equal((await client.agentStatus(agent)).status, "pending");
    await assert.rejects(client.executeCapability({ agentId: agent, capability: "invoices.list" }), { code: "agent_suspended", status: 403 });
    await assert.rejects(client.reactivateAgent(agent), { code: "agent_pending", status: 403 });
    await owner("POST", `/agents/${agent}/resume`);
    assert.equal((await client.reactivateAgent(agent)).status, "active", "§5.6: an active agent is answered as it is");
  });
  await step("rotate the agent's key (§5.8): with the host's JWT, which the client does not send (5.11)", async () => {
    await assert.rejects(client.rotateAgentKey(agent), { code: "invalid_jwt", status: 401 });
    const next = await generateKeypair();
    const res = await fetch(`${url}/agent/rotate-key`, {
      method: "POST",
      headers: { authorization: `Bearer ${signed("host+jwt", keypair, { host_public_key: keypair.publicKey })}`, "content-type": "application/json" },
      body: JSON.stringify({ agent_id: agent, public_key: next.publicKey }),
    });
    assert.deepEqual([res.status, await res.json()], [200, { agent_id: agent, status: "active" }]);
    await assert.rejects(client.executeCapability({ agentId: agent, capability: "invoices.list" }), { code: "invalid_jwt", status: 401 });
    await storage.setAgentConnection(agent, { ...(await storage.getAgentConnection(agent)), agentKeypair: next });
    assert.deepEqual(await client.executeCapability({ agentId: agent, capability: "invoices.list" }), { data: ["inv_1", "inv_2"] });
  });
  await step("rotate the host's key (§5.9): it is the host's once it names an agent of it", async () => {
    assert.equal((await client.rotateHostKey(url)).status, "active");
    assert.equal((await client.agentStatus(agent)).status, "active");
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "rotated" });
    assert.deepEqual([out.status, out.hostId], ["active", host.id]);
  });
  await step("rotate it again and register at once: its owner approves, and the host stays one (5.12)", async () => {
    await client.rotateHostKey(url);
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "rotated again" });
    assert.deepEqual([out.status, (await client.agentStatus(out.agentId)).host_id], ["active", host.id]);
  });
  await step("revoke an agent (§5.7)", async () => {
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "done" });
    await client.disconnectAgent(out.agentId);
    assert.equal((await owner("GET", `/agents/${out.agentId}`)).status, "revoked");
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

// anUnknownHost signs an agent in through a host the server does not know, which a person approves with
// its agent (§2.8).
async function anUnknownHost() {
  const storage = new MemoryStorage();
  const client = new AgentAuthClient({ urls: [url], storage, hostName: "Ada's laptop", approvalTimeoutMs: 20_000, onApprovalRequired: decide });
  await client.init();
  const hosts = async () => (await owner("GET", "/agents/hosts")).map((h) => h.name);

  await step("list the capabilities with a key the server does not know (§5.2)", async () => {
    await storage.setHostIdentity({ keypair: await generateKeypair(), createdAt: Date.now() });
    assert.equal(names(await client.listCapabilities({ provider: url })).length, 3);
  });
  await step("a denied registration of an unknown host is rejected (§7.1)", async () => {
    decision = "deny";
    const denied = client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "denied" });
    await assert.rejects(denied, { code: "agent_rejected" });
    assert.ok(!(await hosts()).includes("Ada's laptop"), "no host");
  });
  const agent = await step("register from an unknown host, approved by a person with the code (§5.3, §7.1)", async () => {
    decision = "approve";
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "laptop", reason: "the harness" });
    assert.deepEqual([out.status, out.capabilityGrants.map((g) => g.status)], ["active", ["active"]]);
    assert.ok((await hosts()).includes("Ada's laptop"), "§2.9: the host is the approver's");
    return out.agentId;
  });
  await step("execute, and request one more capability", async () => {
    assert.deepEqual(await client.executeCapability({ agentId: agent, capability: "invoices.list" }), { data: ["inv_1", "inv_2"] });
    const out = await client.requestCapability({ agentId: agent, capabilities: ["invoices.refund"] });
    assert.ok(out.granted.includes("invoices.refund"), JSON.stringify(out));
    assert.deepEqual(await client.executeCapability({ agentId: agent, capability: "invoices.refund", arguments: { invoice_id: "inv_2" } }), { data: { refunded: "inv_2" } });
    const receipts = await owner("GET", `/agents/${agent}/receipts`);
    assert.equal(receipts.length, 2);
    for (const r of receipts) assert.equal((await owner("GET", `/agents/receipts/${r.id}/verify`)).valid, true);
  });
  await step("the host is known now: the policy approves its next agent (§2.9)", async () => {
    decision = "deny"; // nobody is asked
    const out = await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "second" });
    assert.deepEqual([out.status, (await client.agentStatus(out.agentId)).status], ["active", "active"]);
  });
}

try {
  await readsTheServer();
  await aPreRegisteredHost();
  await anUnknownHost();
  console.log("PASS the whole flow of docs/agent-auth-compat.md, parts 1 to 4");
} catch (err) {
  console.error(err);
  process.exit(1);
}
