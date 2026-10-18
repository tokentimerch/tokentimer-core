"use strict";
// Synthetic verifier input only. It never executes or qualifies a native CA.
exports.proof = () => {
  const h = require("../../tests/e2e/helpers/certops-adcs-uncertain-operator-unique");
  return {
    scope: h.SCOPE,
    resolvedIssuingCaAddress: "10.64.0.4",
    leaseRemainingAtFaultMs: 60000,
    recoveryWaitBudgetMs: 150000,
    actualLeaseWaitMs: 121000,
    caRequestsAtFault: 0,
    caRequestsAfterOperatorSubmission: 1,
    caRequestsAfterRecovery: 1,
    responseLossTimingQualified: false,
    requestId: "201",
    enrollmentId: "77777777-7777-4777-8777-777777777777",
    containerName: "tokentimer-enr-77777777-7777-4777-8777-777777777777",
    fingerprint: "b".repeat(64),
    csrSha256: "c".repeat(64),
    csrSpkiSha256: "d".repeat(64),
    jobIds: [
      "66666666-6666-4666-8666-666666666666",
      "88888888-8888-4888-8888-888888888888",
    ],
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
};
