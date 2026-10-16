"use strict";
/** Synthetic public proof factory only; never native execution evidence. */
const h = require("../../tests/e2e/helpers/certops-adcs-pending-ca-key-change");
const uuid = (n) => `${String(n).padStart(8, "0")}-1111-1111-1111-111111111111`;
function proof() {
  return {
    scope: h.SCOPE,
    schedulerClock: "supported-scheduler-now-input",
    backgroundWorkerIntervalQualified: false,
    issuerId: uuid(1),
    oldEnrollmentId: uuid(2),
    oldOriginalJobId: uuid(3),
    oldContinuationJobId: uuid(4),
    freshEnrollmentId: uuid(5),
    freshOriginalJobId: uuid(6),
    freshContinuationJobId: uuid(7),
    preflightJobId: uuid(8),
    oldRequestId: "17",
    freshRequestId: "18",
    oldCaKeySha256: "a".repeat(64),
    newCaKeySha256: "b".repeat(64),
    oldSnapshotSha256: "c".repeat(64),
    freshSnapshotSha256: "d".repeat(64),
    oldSpkiSha256: "e".repeat(64),
    freshSpkiSha256: "f".repeat(64),
    predecessorFingerprint: "d".repeat(64),
    freshFingerprint: "2".repeat(64),
    subjectCountBefore: 2,
    subjectCountAfter: 3,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
module.exports = { proof, uuid };
