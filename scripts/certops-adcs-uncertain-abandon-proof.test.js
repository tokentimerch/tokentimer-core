"use strict";
/* Supporting proof-contract checks, without native host operations. Actual
 * submitting/recovery/abandon qualification requires the disposable forest. */
const assert = require("node:assert/strict");
const test = require("node:test");
const { assertProof, validateDisposableCaAddress, recoveryWaitBudget } = require("../tests/e2e/helpers/certops-adcs-uncertain-abandon");
function fixture() {
  return { scope: "native-zero-request-uncertain-abandon", ownedTransportBlock: true,
    resolvedIssuingCaAddress: "10.64.0.4", ownedObserverDrained: true,
    leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 61000,
    observedSubmittingTermination: true, actualLeaseExpiry: true,
    acknowledgedPublicRecovery: true, sameCsrAndKey: true, noAutomaticResubmit: true,
    publicAbandonAudited: true, unacceptedKeyRemoved: true, originalOrphanPreserved: true,
    recoveryPolicyUnchanged: true, caRequestsAtFault: 0, caRequestsAfterRecovery: 0,
    caRequestsAfterAbandon: 0 };
}
test("uncertain abandon requires every actual native safety observation", () => {
  assert.equal(assertProof(fixture()), true);
  for (const key of Object.keys(fixture())) {
    const report = fixture(); delete report[key]; assert.throws(() => assertProof(report), undefined, key);
  }
});
test("recovery budget follows the actual persisted lease without rewriting clocks", () => {
  const at = "2026-10-14T12:00:00Z";
  assert.deepEqual(recoveryWaitBudget("2026-10-14T12:05:00Z", at), { leaseRemainingAtFaultMs: 300000, recoveryWaitBudgetMs: 390000 });
  assert.deepEqual(recoveryWaitBudget("2026-10-14T11:59:00Z", at), { leaseRemainingAtFaultMs: 0, recoveryWaitBudgetMs: 90000 });
  assert.throws(() => recoveryWaitBudget("2026-10-14T12:30:00Z", at));
  assert.throws(() => recoveryWaitBudget("invalid", at));
});
test("native fault resolves only the provisioned issuing CA, never another host or subnet", () => {
  const ca = "tt-ca.lab.certops.test\\TTQualificationRoot";
  assert.equal(validateDisposableCaAddress(ca, [{ address: "10.64.0.4", family: 4 }]), "10.64.0.4");
  for (const addresses of [[], [{ address: "10.64.0.7" }], [{ address: "10.64.0.5" }], [{ address: "10.65.0.4" }], [{ address: "::1" }], [{ address: "10.64.0.4" }, { address: "10.64.0.7" }]]) assert.throws(() => validateDisposableCaAddress(ca, addresses));
  assert.throws(() => validateDisposableCaAddress("tt-root.lab.certops.test\\TTQualificationOfflineRoot", [{ address: "10.64.0.4" }]));
});
test("a request allocated at any stage or missing safety proof refuses qualification", () => {
  for (const [key, value] of Object.entries(fixture())) {
    if (key === "scope") continue;
    assert.throws(() => assertProof({ ...fixture(), [key]: typeof value === "boolean" ? false : 1 }), undefined, key);
  }
  assert.throws(() => assertProof({ ...fixture(), scope: "enterprise-adcs-journal-phase-experimental" }));
  assert.throws(() => assertProof({ ...fixture(), privateKey: "unapproved report field" }));
});
