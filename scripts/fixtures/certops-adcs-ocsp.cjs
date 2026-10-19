"use strict";
// Offline validator input only. These constants never represent native runs.
const subject = require("../../tests/e2e/helpers/certops-adcs-ocsp-proof");
function proof() {
  return {
    scope: subject.SCOPE,
    enrollmentIds: [
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
    ],
    jobIds: [
      "33333333-3333-4333-8333-333333333333",
      "44444444-4444-4444-8444-444444444444",
    ],
    requestIds: [41, 42],
    signerRequestId: 40,
    leafFingerprints: ["a".repeat(64), "b".repeat(64)],
    signerFingerprint: "c".repeat(64),
    issuerKeySha256: "d".repeat(64),
    nativeHelperSha256: "e".repeat(64),
    publicCrlSha256: "f".repeat(64),
    responseSha256: ["1".repeat(64), "2".repeat(64), "3".repeat(64)],
    caRequestCounts: [39, 40, 41, 42],
    nativeVerdicts: ["valid", "revocation_unknown", "valid"],
    deferredRecovery: {
      originalJobId: "55555555-5555-4555-8555-555555555555",
      originalClaimId: "66666666-6666-4666-8666-666666666666",
      continuationJobId: "33333333-3333-4333-8333-333333333333",
      continuationClaimId: "77777777-7777-4777-8777-777777777777",
      requestId: 41,
    },
    ...Object.fromEntries(subject.FLAGS.map((flag) => [flag, true])),
    ...Object.fromEntries(subject.FALSE_FLAGS.map((flag) => [flag, false])),
  };
}
module.exports = { proof };
