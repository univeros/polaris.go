// Drives the unmodified @auth/agent client against the server at AGENT_AUTH_URL
// (scripts/e2e-agent-auth.sh). § numbers are the Agent Auth Protocol's.
//
// Exit status: 0 the whole flow passed; 3 it stopped where docs/agent-auth-compat.md says the server
// stops today; 1 anything else.
import assert from "node:assert/strict";
import { AgentAuthClient, AgentAuthSDKError } from "@auth/agent";

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

// registers answers false when the server has no registration endpoint.
async function registers() {
  let refusal;
  try {
    await client.connectAgent({ provider: url, capabilities: ["invoices.list"], name: "e2e" });
    return true;
  } catch (err) {
    refusal = err;
  }
  if (!(refusal instanceof AgentAuthSDKError) || refusal.status !== 404 || refusal.code !== "not_found") {
    console.error("FAIL register (§5.3): not the refusal of a missing route");
    throw refusal;
  }
  // The client has a host key now and signs a host JWT, which the server does not verify yet.
  await step("list the capabilities with an unknown host key (§5.2)", async () => {
    assert.equal(names(await client.listCapabilities({ provider: url })).length, 2);
  });
  return false;
}

try {
  await readsTheServer();
  if (!(await registers())) {
    console.error(
      "STOP register (§5.3): POST /agent/register answered 404 not_found. Expected for now: registration\n" +
        "     needs host keys, part 2 of docs/agent-auth-compat.md, which is not built. Everything before it passed.",
    );
    process.exit(3);
  }
  console.error("FAIL the server registers agents now: extend client.mjs to the next part of docs/agent-auth-compat.md");
  process.exit(1);
} catch (err) {
  console.error(err);
  process.exit(1);
}
