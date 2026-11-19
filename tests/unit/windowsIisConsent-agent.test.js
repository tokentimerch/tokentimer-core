"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { bindAuthenticatedCredential } = require("../../apps/api/services/certops/agentCredentialFence");
const { checkWindowsIisConsumerForAgent } = require("../../apps/api/services/certops/windowsIisConsent");

test("consent check fences credentials and advances sequence before a fail-closed lookup", async () => {
  const credential = "test-credential";
  const agent = bindAuthenticatedCredential({ id: "agent", workspaceId: "workspace", agentId: "public-agent" }, credential);
  const queries = [];
  const client = { async query(sql) {
    queries.push(sql);
    if (sql.includes("credential_hash FROM certops_agents")) return { rows: [{ status: "active", agent_id: "public-agent", credential_hash: crypto.createHash("sha256").update(credential).digest("hex") }] };
    if (sql.includes("UPDATE certops_agents")) return { rows: [{ id: "agent" }] };
    return { rows: [] };
  }, release() { queries.push("RELEASE"); } };
  const result = await checkWindowsIisConsumerForAgent({ dbPool: { connect: async () => client }, agent,
    jobId: "job", claimId: "claim", consumerId: "consumer", authorizationRevision: 1, sequence: 1 });
  assert.deepEqual(result, { allowed: false });
  assert.equal(queries[0], "BEGIN");
  assert.match(queries[1], /credential_hash FROM certops_agents/);
  assert.match(queries[2], /UPDATE certops_agents/);
  assert.match(queries[3], /FROM certops_windows_iis_renewal_consumers/);
  assert.equal(queries[4], "COMMIT");
  assert.equal(queries[5], "RELEASE");
});

test("consent check refuses a stale credential before looking up consent", async () => {
  const agent = bindAuthenticatedCredential({ id: "agent", workspaceId: "workspace", agentId: "public-agent" }, "old");
  const queries = [];
  const client = { async query(sql) { queries.push(sql); return { rows: [] }; }, release() { queries.push("RELEASE"); } };
  await assert.rejects(checkWindowsIisConsumerForAgent({ dbPool: { connect: async () => client }, agent,
    jobId: "job", claimId: "claim", consumerId: "consumer", authorizationRevision: 1, sequence: 1 }), { code: "CERTOPS_AGENT_CREDENTIAL_INVALID" });
  assert.equal(queries[2], "ROLLBACK");
  assert.equal(queries[3], "RELEASE");
});
test("agent consent route validates and forwards only bounded request fields", async () => {
  const { iisConsentHandler } = require("../../apps/api/routes/certops-agent")._test;
  const requests = [];
  const response = () => ({ status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });
  const body = { claimId: "claim", consumerId: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", authorizationRevision: 1, sequence: 1 };
  const res = response();
  await iisConsentHandler({ params: { jobId: "job" }, body, certopsAgent: { id: "agent" } }, res,
    { checkWindowsIisConsumerForAgent: async (request) => { requests.push(request); return { allowed: false }; } });
  assert.equal(res.code, 200);
  assert.deepEqual(res.body, { allowed: false });
  assert.equal(requests[0].consumerId, body.consumerId);
  for (const invalid of [{ ...body, sequence: 0 }, { ...body, consumerId: "invalid" }, { ...body, extra: true }]) {
    const rejected = response();
    await iisConsentHandler({ params: { jobId: "job" }, body: invalid }, rejected,
      { checkWindowsIisConsumerForAgent: async () => { throw new Error("unexpected"); } });
    assert.equal(rejected.code, 400);
  }
});