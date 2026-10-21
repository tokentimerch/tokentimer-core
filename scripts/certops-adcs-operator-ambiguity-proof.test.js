"use strict";
/**
 * Qualification notes: operator-created uncertain ambiguity
 *
 * Fresh unbound target has real transport-blocked submitting interruption/CA count zero ; separate
 * serving TLS is positive control. Stopped agent/working transport, operator submits retained
 * actual CSR twice as SYSTEM: distinct RequestIds/serials/same SPKI within original 16-ID window,
 * verified CA CN/requester/DER/count; stale watermark fails, never rewrite. After actual lease+
 * grace acknowledged recovery refuses two matches, retains CSR/CNG/empty site/unrelatedTLS;
 * real-now sweeps cannot resubmit. Public selected RequestId + real-now signed continuation
 * installs exact leaf/original key/snapshot/IIS/TLS/claim evidence/proposal+recovery audits,
 * retains unknown job. All-store absence and exact requester/CSR/DER before revoking unused leaf
 * only. Parent owns unresolved CA/custody/process/site, no blind revoke while acceptance unknown.
 * Deliberate operator ambiguity is not deterministic lost successful-submit response.
 *
 * Shared setup, evidence and cleanup policy: docs/certops/e2e-qualification.md.
 */
/** Synthetic bounded report refusals; no native CA/key/service action runs. */
const test = require("node:test"), assert = require("node:assert/strict");
const helper = require("../tests/e2e/helpers/certops-adcs-uncertain-operator-ambiguity");
function fixture() { const enrollmentId = "11111111-1111-1111-1111-111111111111"; return { scope: helper.SCOPE, fixtureOrigin: "operator-created-two-real-system-submissions-of-the-same-public-csr", resolvedIssuingCaAddress: "10.64.0.4", leaseRemainingAtFaultMs: 60000, recoveryWaitBudgetMs: 150000, actualLeaseWaitMs: 120000, caRequestsAtFault: 0, caRequestsAfterOperatorSubmissions: 2, caRequestsAfterAmbiguousRecovery: 2, caRequestsAfterExplicitRecovery: 2, requestIds: ["101", "102"], fingerprints: ["1".repeat(64), "2".repeat(64)], serialNumbers: ["aa", "bb"], csrSpkiSha256: "3".repeat(64), csrSha256: "4".repeat(64), selectedRequestId: "101", unusedRequestId: "102", enrollmentId, containerName: `tokentimer-enr-${enrollmentId}`, jobIds: ["22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333", "44444444-4444-4444-4444-444444444444"], reconcileSearchFrom: 100, scanWindowSize: 16, ...Object.fromEntries(helper.FLAGS.map(flag => [flag, true])) }; }
test("operator ambiguity requires every actual zero-fault/public recovery/owned cleanup fact", () => {
  const valid = fixture(); assert.equal(helper.verifyProof(valid), true);
  for (const flag of helper.FLAGS) { const missing = { ...valid }; delete missing[flag]; assert.throws(() => helper.verifyProof(missing)); for (const value of [false, null, 1, "true"]) assert.throws(() => helper.verifyProof({ ...valid, [flag]: value })); }
  for (const patch of [{ fixtureOrigin: "lost-submit-response" }, { scope: "native-zero-request-uncertain-abandon" }, { resolvedIssuingCaAddress: "10.64.0.7" }, { caRequestsAtFault: 1 }, { caRequestsAfterOperatorSubmissions: 3 }, { caRequestsAfterAmbiguousRecovery: 3 }, { caRequestsAfterExplicitRecovery: 3 }, { actualLeaseWaitMs: 58999 }, { actualLeaseWaitMs: 152000 }, { recoveryWaitBudgetMs: 150001 }, { privateKey: "private" }]) assert.throws(() => helper.verifyProof({ ...valid, ...patch }));
});
test("only two owned distinct candidates inside the actual default window can be selected", () => {
  const valid = fixture();
  for (const field of ["requestIds", "fingerprints", "serialNumbers", "jobIds"]) {
    for (const value of [[], null, valid[field].slice(1), [...valid[field], valid[field][0]], valid[field].map(() => valid[field][0]), valid[field].map(() => "invalid")]) assert.throws(() => helper.verifyProof({ ...valid, [field]: value }));
  }
  for (const field of ["enrollmentId", "containerName", "csrSha256", "csrSpkiSha256", "selectedRequestId", "unusedRequestId"]) { const missing = { ...valid }; delete missing[field]; assert.throws(() => helper.verifyProof(missing)); assert.throws(() => helper.verifyProof({ ...valid, [field]: "invalid" })); }
  for (const patch of [{ selectedRequestId: "103" }, { unusedRequestId: "101" }, { requestIds: ["101", "4294967296"] }, { reconcileSearchFrom: 0 }, { reconcileSearchFrom: 102 }, { reconcileSearchFrom: 86 }, { scanWindowSize: 64 }]) assert.throws(() => helper.verifyProof({ ...valid, ...patch }));
});
