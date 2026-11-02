"use strict";
/** Synthetic closed signing/certificate proof only; never native evidence. */
const h = require("../../tests/e2e/helpers/certops-acme-certificate-signing");
function fixture(rotate = true) {
  return {
    scope: h.SCOPE,
    certificateId: "11111111-1111-4111-8111-111111111111",
    jobIds: [
      "22222222-2222-4222-8222-222222222222",
      "33333333-3333-4333-8333-333333333333",
    ],
    claimIds: [
      "44444444-4444-4444-8444-444444444444",
      "55555555-5555-4555-8555-555555555555",
    ],
    signingKeyIds: ["certops-old", "certops-new"],
    fingerprints: ["a".repeat(64), "b".repeat(64)],
    spkiFingerprints: ["c".repeat(64), (rotate ? "d" : "c").repeat(64)],
    client: "certbot",
    rotatePrivateKey: rotate,
    sharedFleetQualified: false,
    forcedCompletionQualified: false,
    atomicTreeContainmentQualified: false,
    ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
  };
}
module.exports = { fixture };
