"use strict";
// Offline public report shape only. No installed/native observation is made.
exports.proof = () => {
  const subject = require("../../tests/e2e/helpers/certops-adcs-result-outbox");
  const uuid = (n) => `10000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
  return {
    scope: subject.SCOPE,
    enrollmentId: uuid(1),
    jobId: uuid(2),
    claimId: uuid(3),
    requestId: 42,
    fingerprints: ["1".repeat(64), "2".repeat(64)],
    caRequestCounts: [10, 11, 11],
    recordedAttempts: 1,
    retryDelayMs: 15000,
    atomicTreeContainmentQualified: false,
    backgroundTimerQualified: false,
    ...Object.fromEntries(subject.FLAGS.map((flag) => [flag, true])),
  };
};
