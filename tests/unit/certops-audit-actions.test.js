"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const { writeAudit, normalizeAuditAction, auditActionSql } = require("../../apps/api/services/audit");

const actions = [
  ["certops.issuer.created", "CERTOPS_ISSUER_CREATED"],
  ["certops.issuer.preflight_dispatched", "CERTOPS_ISSUER_PREFLIGHT_DISPATCHED"],
  ["certops.issuer.key_confirmed", "CERTOPS_ISSUER_KEY_CONFIRMED"],
  ["certops.enrollment.created", "CERTOPS_ENROLLMENT_CREATED"],
  ["certops.enrollment.reconcile_proposed", "CERTOPS_ENROLLMENT_RECONCILE_PROPOSED"],
  ["certops.enrollment.cancelled", "CERTOPS_ENROLLMENT_CANCELLED"],
  ["certops.enrollment.abandoned", "CERTOPS_ENROLLMENT_ABANDONED"],
  ["certops.agent_log.rejected", "CERTOPS_AGENT_LOG_REJECTED"],
];
for (const [legacy, canonical] of actions) {
  it(`writes ${canonical} on the caller transaction with its metadata`, async () => {
    const calls = [];
    const metadata = { enrollmentId: "enrollment-uuid", issuerId: "issuer-uuid", jobId: "job-uuid", requestId: 0 };
    await writeAudit({ client: { query: async (...args) => calls.push(args) }, action: legacy, workspaceId: "workspace-uuid", metadata });
    assert.equal(calls.length, 1);
    assert.equal(calls[0][1][2], canonical);
    assert.equal(calls[0][1][6], metadata);
    assert.equal(normalizeAuditAction(canonical), canonical);
  });
}
it("leaves other audit actions unchanged and rejects unsafe SQL column names", () => {
  assert.equal(normalizeAuditAction("LOGIN_SUCCESS"), "LOGIN_SUCCESS");
  assert.equal(normalizeAuditAction("job.created"), "job.created");
  assert.equal(normalizeAuditAction("__proto__"), "__proto__");
  assert.throws(() => auditActionSql("action; DROP TABLE audit_events"));
});
