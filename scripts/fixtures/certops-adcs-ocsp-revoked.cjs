"use strict";
// Offline revoked-status contract input. Native lab execution is still pending.
// These constants do not fabricate a native status or CA operation.
exports.proof = () => {
  const source = require("../../tests/e2e/helpers/certops-adcs-ocsp-revoked"),
    base = require("./certops-adcs-ocsp.cjs").proof();
  return {
    scope: source.SCOPE,
    historicalEnrollmentId: base.enrollmentIds[0],
    currentEnrollmentId: base.enrollmentIds[1],
    historicalRequestId: base.requestIds[0],
    currentRequestId: base.requestIds[1],
    originalCrlSha256: base.publicCrlSha256,
    revokedCrlSha256: "8".repeat(64),
    originalCrlNumber: "0",
    revokedCrlNumber: "1",
    historicalFingerprint: base.leafFingerprints[0],
    currentFingerprint: base.leafFingerprints[1],
    historicalSerial: "A2",
    revocationTime: "2026-10-15T10:00:00.000Z",
    responseSha256: "9".repeat(64),
    signerFingerprint: base.signerFingerprint,
    issuerKeySha256: base.issuerKeySha256,
    nativeVerdict: "revoked",
    caRequestCounts: [base.caRequestCounts.at(-1), base.caRequestCounts.at(-1)],
    ...Object.fromEntries(source.FLAGS.map((flag) => [flag, true])),
    ...Object.fromEntries(source.FALSE_FLAGS.map((flag) => [flag, false])),
  };
};
