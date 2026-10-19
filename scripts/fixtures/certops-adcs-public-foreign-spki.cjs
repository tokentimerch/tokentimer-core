"use strict";
/** Synthetic report data only; no native CA, elapsed or installed-agent proof. */
const helper = require("../../tests/e2e/helpers/certops-adcs-public-foreign-spki");
function proof() {
  return {
    scope: helper.SCOPE,
    enrollmentId: "11111111-1111-1111-1111-111111111111",
    failedJobId: "55555555-5555-5555-5555-555555555555",
    foreignRequestId: "103",
    selectedRequestId: "101",
    foreignFingerprint: "a".repeat(64),
    selectedFingerprint: "1".repeat(64),
    foreignSpkiSha256: "c".repeat(64),
    originalSpkiSha256: "3".repeat(64),
    foreignCsrSha256: "e".repeat(64),
    reconcileSearchFrom: 100,
    foreignSubjectRequestCount: 1,
    originalSubjectRequestCount: 2,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
}
module.exports = { proof };
