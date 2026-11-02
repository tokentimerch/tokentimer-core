"use strict";
// Synthetic public contract fixture only; never native evidence.
const h = require("../../tests/e2e/helpers/certops-windows-installed-verify-rollback");
const certificateId = "11111111-1111-4111-8111-111111111111",
  jobId = "22222222-2222-4222-8222-222222222222",
  claimId = "33333333-3333-4333-8333-333333333333";
function fixture() {
  return {
    scope: h.SCOPE,
    certificateId,
    jobIds: [jobId, "44444444-4444-4444-8444-444444444444"],
    claimIds: [claimId, "55555555-5555-4555-8555-555555555555"],
    fingerprints: ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
    spkiFingerprints: ["d".repeat(64), "e".repeat(64), "f".repeat(64)],
    failedJobStatus: "failed",
    failureCode: "VERIFY_FAILED",
    rolledBack: true,
    retryJobStatus: "succeeded",
    bindFailureQualified: false,
    rollbackFailureQualified: false,
    expiryCleanupQualified: false,
    transientNewBindingObservationQualified: false,
    appIdPreservationQualified: false,
    ...Object.fromEntries(h.FLAGS.map((k) => [k, true])),
  };
}

module.exports = { fixture };
