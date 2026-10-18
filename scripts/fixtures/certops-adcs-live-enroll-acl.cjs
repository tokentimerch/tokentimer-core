"use strict";
// Supporting public proof only; never a native execution result.
const subject = require("../../tests/e2e/helpers/certops-adcs-live-enroll-acl");
function proof(delta = 1) {
  return {
    scope: subject.SCOPE,
    templateGuid: "11111111-2222-4333-8444-555555555555",
    templateOid: "1.3.6.1.4.1.311.21.8.100",
    machineSid: "S-1-5-21-1-2-3-1000",
    originalDaclSha256: "a".repeat(64),
    appliedDaclSha256: "b".repeat(64),
    restoredDaclSha256: "a".repeat(64),
    deniedCaRequestDelta: delta,
    caRequestCounts: [10, 10 + delta, 11 + delta],
    enrollmentIds: [
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
    ],
    jobIds: [
      "33333333-3333-4333-8333-333333333333",
      "44444444-4444-4444-8444-444444444444",
    ],
    fingerprints: ["c".repeat(64), "d".repeat(64)],
    caHresult: "0x80094012",
    preflightRefusalQualified: false,
    signedCmcRenewalQualified: false,
    ...Object.fromEntries(subject.FLAGS.map((name) => [name, true])),
  };
}
module.exports = { proof };
