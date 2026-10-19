"use strict";
/** Independently owned new unaccepted enrollments must be checked before any
 * broad predecessor certificate removal. Unknown acceptance retains state. */
const assert = require("node:assert/strict");
const store = require("../../../packages/agent/src/windows-cert-store");
const { inspectMachineKeySurvivors } = require("../../../packages/agent/src/windows-key-survivors");
const { assertDrainAbsent } = require("./certops-adcs-webhosting-renewal");
const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function register(receipts, value, run) {
  assert.match(run, /^[a-f0-9]{10}$/); assert.match(value.certificateId, uuid);
  assert.equal(value.domain, `certops-adcs-${run}-cancel.example.test`);
  assert.ok(!receipts.some(item => item.certificateId === value.certificateId));
  const receipt = { certificateId: value.certificateId, domain: value.domain, enrollmentIds: [], removedEnrollmentIds: [], cleanupCompleted: false }; receipts.push(receipt); return receipt;
}
function validateReceipt(receipt, rows) {
  assert.match(receipt.certificateId, uuid); assert.match(receipt.domain, /^certops-adcs-[a-f0-9]{10}-cancel\.example\.test$/);
  assert.equal(receipt.enrollmentIds.length, 1, "Preserve dispatch with unknown enrollment identity"); assert.match(receipt.enrollmentIds[0], uuid);
  assert.equal(rows.length, 1, "Preserve missing or unexpected owned enrollment rows");
  assert.ok(rows[0].id === receipt.enrollmentIds[0] && rows[0].certificate_id === receipt.certificateId, "Owned receipt must bind exact public enrollment and certificate");
  assert.ok(["rejected_invalid", "denied", "refused", "cancelled", "expired", "abandoned", "validation_expired"].includes(rows[0].state), "Preserve nonterminal or accepted enrollment");
  assert.equal(rows[0].active_jobs, 0, "Preserve live continuation jobs"); return store.buildEnrollmentContainerName(rows[0].id);
}
async function cleanup({ receipts, fixture, ps, drain }) {
  if (!receipts.length) return;
  assert.equal(ps("(Get-Service TokenTimerAgent -ErrorAction SilentlyContinue).Status"), "", "Owned service must be deleted before unaccepted cleanup");
  const current = JSON.parse(ps("@{processes=@(Get-CimInstance Win32_Process|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o')}})}|ConvertTo-Json -Depth 4 -Compress")); assertDrainAbsent(drain, current.processes);
  const plans = [];
  // Prove every registered target before any destructive action, including
  // when a key is already absent: public store metadata may still reference it.
  for (const receipt of receipts) {
    const rows = (await fixture.pool.query("SELECT e.id,e.certificate_id,e.state,(SELECT count(*)::int FROM certificate_jobs j WHERE j.workspace_id=e.workspace_id AND j.enrollment_id=e.id AND j.status NOT IN ('succeeded','failed','cancelled','rejected','awaiting_issuer')) AS active_jobs FROM certificate_enrollments e WHERE e.workspace_id=$1 AND e.certificate_id=$2", [fixture.workspaceId, receipt.certificateId])).rows;
    const containerName = validateReceipt(receipt, rows), references = await inspectMachineKeySurvivors({ containerName });
    assert.ok(references.ok === true && references.shared === false, "Preserve accepted or unobservable native key association"); plans.push({ receipt, containerName });
  }
  for (const { receipt, containerName } of plans) {
    const removed = await store.removeAbandonedKeyContainer({ containerName, allowAlreadyAbsent: true }); assert.equal(removed.ok, true, "Unaccepted exact key cleanup must succeed");
    const absent = await store.removeAbandonedKeyContainer({ containerName, requireAlreadyAbsent: true }); assert.equal(absent.ok, true, "Unaccepted exact key must be independently absent");
    receipt.removedEnrollmentIds = [...receipt.enrollmentIds]; receipt.cleanupCompleted = true;
  }
}
function assertComplete(receipts) { for (const receipt of receipts) { assert.equal(receipt.cleanupCompleted, true, "Preserve unresolved unaccepted native ownership"); assert.deepEqual(receipt.removedEnrollmentIds, receipt.enrollmentIds); } }
module.exports = { register, validateReceipt, cleanup, assertComplete };
