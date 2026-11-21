"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { bindAuthenticatedCredential, assertCurrentAgentCredential } = require("../../apps/api/services/certops/agentCredentialFence");
test("evidence fencing rechecks the authenticated credential and status under row lock", async () => {
  const raw = "ttagent-test-credential", fingerprint = createHash("sha256").update(raw).digest("hex");
  const agent = bindAuthenticatedCredential({ id: "row", workspaceId: "workspace", agentId: "public" }, raw);
  assert.equal(JSON.stringify(agent).includes(fingerprint), false);
  let row = { status: "active", credential_hash: fingerprint };
  const client = {
    async query(sql, params) {
      assert.match(sql, /WHERE id = \$1 AND workspace_id = \$2 AND agent_id = \$3 FOR UPDATE$/);
      assert.deepEqual(params, ["row", "workspace", "public"]);
      return { rows: row ? [row] : [] };
    },
  };
  await assertCurrentAgentCredential({ client, agent });
  row = { status: "retired", credential_hash: fingerprint };
  await assert.rejects(assertCurrentAgentCredential({ client, agent }), { code: "CERTOPS_AGENT_RETIRED" });
  row = { status: "active", credential_hash: "f".repeat(64) };
  await assert.rejects(assertCurrentAgentCredential({ client, agent }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  row = null;
  await assert.rejects(assertCurrentAgentCredential({ client, agent }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  await assert.rejects(assertCurrentAgentCredential({ client, agent: { ...agent } }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
});

test("discovery evidence cannot advance sequence after credential rotation", async () => {
  const { persistAgentDiscoveryEvidenceBatch } = require("../../apps/api/services/certops/agentObservations");
  const agent = bindAuthenticatedCredential({ id: "row", workspaceId: "workspace", agentId: "public" }, "old-credential");
  const calls = [];
  const client = { async query(sql) { calls.push(sql); if (sql.includes("FROM certops_agents")) return { rows: [{ status: "active", agent_id: "public", credential_hash: "f".repeat(64) }] }; return { rows: [] }; }, release() {} };
  await assert.rejects(persistAgentDiscoveryEvidenceBatch({ dbPool: { connect: async () => client }, agent, envelope: { sequence: 1 },
    evidenceItems: [{ evidenceId: "ev-1", eventType: "certificate.observed", observedAt: new Date().toISOString(), fingerprintSha256: "a".repeat(64),
      metadata: [{ name: "filePath", value: "/tmp/cert.pem" }, { name: "targetHost", value: "host.example" },
        { name: "validFrom", value: "2026-01-01T00:00:00.000Z" }, { name: "validTo", value: "2027-01-01T00:00:00.000Z" }] }],
    deps: { enforceAgentSequence: async () => { throw new Error("sequence must not advance"); } } }), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  assert.equal(calls.includes("ROLLBACK"), true);
});
