"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const dispatch = require("../../apps/api/services/certops/agentDispatch");
const observations = require("../../apps/api/services/certops/agentObservations");
const original = { eventType: "validation.passed", observedAt: "2026-11-27T15:00:00Z", evidenceId: "evidence-1", summary: "verified", metadata: [{ name: "step", value: "safety" }] };
function fixture() {
  const log = [];
  const row = { claimed_by_agent_id: "agent", claim_id: "claim", attempt_count: 2, payload: { target: { type: "windows-cert-store" } }, status: "succeeded", completed_at: "2026-11-27T15:00:01Z", lease_live: false };
  const expected = { step: "safety", summary: "verified", fingerprintSha256: null, agentId: "public-agent", evidenceId: "evidence-1" };
  const client = { release() {}, async query(sql, args) {
    log.push(sql);
    if (sql.includes("FROM certificate_jobs")) return { rows: [row] };
    if (sql.includes("FROM certificate_evidence")) {
      const match = args[0] === "workspace" && args[1] === "job" && args[2] === "agent" && args[3] === "evidence-1" && args[4] === "claim" && args[5] === 2 && args[6] === original.eventType && JSON.stringify(JSON.parse(args[7])) === JSON.stringify(expected) && args[8] === original.observedAt;
      return { rows: match ? [{ id: "stored" }] : [] };
    }
    return { rows: [] };
  } };
  const agent = { id: "agent", agentId: "public-agent", workspaceId: "workspace" };
  return { row, log, args: { dbPool: { connect: async () => client }, agent, jobId: "job", claimId: "claim", evidenceItems: [original], envelope: {}, deps: { assertCurrentAgentCredential: async () => {}, enforceAgentSequence: async () => {}, assertEvidenceClaimOwnership: dispatch.assertEvidenceClaimOwnership, createCertificateEvidence: async () => { throw Error("unexpected write"); } } } };
}
test("terminal Store replay checks committed proof under locks and has no side effects", async () => {
  const f = fixture();
  const r = await observations.persistAgentJobEvidenceBatch(f.args);
  assert.equal(r.duplicate, true);
  assert.ok(f.log.some(s => s.includes("FOR UPDATE")));
  assert.ok(f.log.some(s => s.includes("FOR SHARE")));
  assert.ok(f.log.includes("COMMIT"));
});
test("terminal Store replay rejects changed or missing proof and wrong owner", async () => {
  for (const mutate of [f => f.args.evidenceItems = [{ ...original, summary: "changed" }], f => f.args.evidenceItems = [{ ...original, fingerprintSha256: "a".repeat(64) }], f => f.args.evidenceItems = [{ ...original, eventType: "validation.failed" }], f => f.args.evidenceItems = [{ ...original, evidenceId: "different" }], f => f.args.evidenceItems = [{ ...original, metadata: [{name:"step",value:"adcs.expected-identity"}] }], f => f.args.evidenceItems = [{ ...original, metadata: [{name:"step",value:"acme-store-receipt"}] }], f => f.args.evidenceItems = [{ ...original, metadata: [{name:"agentId",value:"forged"}] }], f => f.args.evidenceItems = [{ ...original, metadata: [{name:"step",value:"safety"},{name:"step",value:"other"}] }], f => f.row.status = "failed", f => f.row.completed_at = null, f => f.row.claim_id = "other", f => f.row.claimed_by_agent_id = "other", f => f.args.evidenceItems = [original, original]]) {
    const f = fixture(); mutate(f);
    await assert.rejects(observations.persistAgentJobEvidenceBatch(f.args));
    assert.ok(f.log.includes("ROLLBACK"));
  }
});
test("ordinary ownership guard remains closed for terminal Store jobs", async () => {
  const f = fixture();
  const dbPool = { query: async () => ({ rows: [f.row] }) };
  await assert.rejects(dispatch.assertEvidenceClaimOwnership({ dbPool, agent: f.args.agent, jobId: "job", claimId: "claim" }), { code: "CERTOPS_AGENT_LEASE_INVALID" });
});
