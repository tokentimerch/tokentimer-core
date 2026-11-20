"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fence = require("../../apps/api/services/certops/agentCredentialFence");
const { generateAgentCredential, validateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { createAgentCredentialAuth } = require("../../apps/api/middleware/agent-auth");
const { recordHeartbeat } = require("../../apps/api/services/certops/agentDispatch");
const { handleAgentRouteError } = require("../../apps/api/routes/certops-agent")._test;

function fixture() {
  const { plaintextCredential } = generateAgentCredential();
  const hash = crypto.createHash("sha256").update(plaintextCredential).digest("hex");
  const row = { id: "row", workspace_id: "workspace", agent_id: "agent", status: "active", credential_hash: hash };
  const calls = []; let writes = 0; let sequences = 0; let validated;
  const client = {
    async query(sql, params) {
      calls.push(sql);
      if (sql.includes("WHERE credential_prefix")) return { rows: [{ ...row }] };
      if (sql.includes("SELECT credential_hash, status") && sql.includes("FOR UPDATE")) {
        assert.deepEqual(params, ["row", "workspace", "agent"]);
        const match = row.id === params[0] && row.workspace_id === params[1] && row.agent_id === params[2];
        return { rows: match ? [{ credential_hash: row.credential_hash, status: row.status }] : [] };
      }
      if (sql.includes("UPDATE certops_agents")) { writes++; return { rows: [{ id: row.id, status: row.status, last_seen_at: new Date("2026-01-01T00:00:00Z") }] }; }
      if (["BEGIN", "COMMIT", "ROLLBACK"].includes(sql)) return { rows: [] };
      throw new Error("unexpected synthetic query");
    },
    release() {},
  };
  const auth = createAgentCredentialAuth({ client, validateAgentCredential: async options => {
    const result = await validateAgentCredential(options); validated = result.agent; return result;
  } });
  async function authenticate() {
    const req = { headers: { authorization: `Bearer ${plaintextCredential}` } }; let called = false;
    const res = { status() { throw new Error("unexpected authentication failure"); } };
    await auth(req, res, error => { if (error) throw error; called = true; });
    assert.equal(called, true); assert.strictEqual(req.certopsAgent, validated);
    return req.certopsAgent;
  }
  const deps = { enforceAgentSequence: async () => { sequences++; }, getActiveSigningKeyPublicInfo: async () => null, getSigningKeyRotationNotice: async () => null };
  const heartbeat = agent => recordHeartbeat({ dbPool: { connect: async () => client }, agent, envelope: { sequence: 1, protocolVersion: "1.0.0" }, body: {}, deps });
  return { row, hash, plaintextCredential, calls, client, authenticate, heartbeat, counts: () => ({ writes, sequences }) };
}

test("both binders keep the same authenticated object for both lock interfaces", async () => {
  const f = fixture(), agent = await f.authenticate();
  assert.strictEqual(fence.bindAuthenticatedCredential(agent, f.plaintextCredential), agent);
  assert.strictEqual(fence.bindAuthenticatedAgent(agent, f.hash), agent);
  assert.equal(JSON.stringify(agent).includes(f.hash), false);
  assert.equal(Object.getOwnPropertySymbols(agent).length, 0);
  await fence.lockCurrentAgentCredential(f.client, agent);
  await fence.assertCurrentAgentCredential({ client: f.client, agent });
  assert.equal((await f.heartbeat(agent)).ok, true);
  assert.deepEqual(f.counts(), { writes: 1, sequences: 1 });
});

test("raw binder creates a snapshot that hash binder cannot replace", async () => {
  const f = fixture(), agent = { id: "row", workspaceId: "workspace", agentId: "agent" };
  assert.strictEqual(fence.bindAuthenticatedCredential(agent, f.plaintextCredential), agent);
  assert.strictEqual(fence.bindAuthenticatedAgent(agent, f.hash), agent);
  await fence.assertCurrentAgentCredential({ client: f.client, agent });
  assert.throws(() => fence.bindAuthenticatedAgent(agent, "f".repeat(64)), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  assert.throws(() => fence.bindAuthenticatedCredential(agent, "different"), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  await fence.lockCurrentAgentCredential(f.client, agent);
});

test("clones, mutated identity and invalid binding fail closed", async () => {
  const f = fixture(), agent = await f.authenticate();
  await assert.rejects(fence.lockCurrentAgentCredential(f.client, { ...agent }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  await assert.rejects(fence.assertCurrentAgentCredential(), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  await assert.rejects(fence.assertCurrentAgentCredential(null), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  await assert.rejects(fence.lockCurrentAgentCredential(null, agent), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  assert.throws(() => fence.bindAuthenticatedCredential(agent, ""));
  for (const invalid of [null, {}, "A".repeat(64), "a".repeat(63)]) {
    assert.throws(() => fence.bindAuthenticatedAgent({ id: "row", workspaceId: "workspace", agentId: "agent" }, invalid));
  }
  for (const field of ["id", "workspaceId", "agentId"]) {
    const fresh = fixture(), bound = await fresh.authenticate(); bound[field] = "different";
    assert.throws(() => fence.bindAuthenticatedAgent(bound, fresh.hash), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
    await assert.rejects(fence.assertCurrentAgentCredential({ client: fresh.client, agent: bound }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  }
});

test("replacement or retirement after authentication rejects before sequence and heartbeat", async () => {
  for (const [change, code] of [
    [{ credential_hash: "f".repeat(64) }, "CERTOPS_AGENT_CREDENTIAL_STALE"],
    [{ credential_hash: null }, "CERTOPS_AGENT_CREDENTIAL_STALE"],
    [{ status: "retired" }, "CERTOPS_AGENT_RETIRED"],
    [{ status: "retired", credential_hash: "f".repeat(64) }, "CERTOPS_AGENT_CREDENTIAL_STALE"],
    [{ agent_id: "different" }, "CERTOPS_AGENT_CREDENTIAL_STALE"],
  ]) {
    const f = fixture(), agent = await f.authenticate(); Object.assign(f.row, change);
    await assert.rejects(f.heartbeat(agent), { code });
    assert.deepEqual(f.counts(), { writes: 0, sequences: 0 });
    assert.ok(f.calls.includes("ROLLBACK"));
  }
});

test("offline with unchanged binding passes and both route codes remain distinct", async () => {
  const f = fixture(), agent = await f.authenticate(); f.row.status = "offline";
  await fence.assertCurrentAgentCredential({ client: f.client, agent });
  for (const [code, expected] of [["CERTOPS_AGENT_CREDENTIAL_STALE", 401], ["CERTOPS_AGENT_RETIRED", 410]]) {
    const res = { status(value) { this.statusCode = value; return this; }, json(value) { this.body = value; return this; } };
    handleAgentRouteError(res, { code }); assert.equal(res.statusCode, expected);
    assert.equal(res.body.code, expected === 401 ? "CERTOPS_AGENT_UNAUTHORIZED" : "CERTOPS_AGENT_RETIRED");
  }
});
