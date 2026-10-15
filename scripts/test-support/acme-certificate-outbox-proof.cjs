"use strict";
const crypto = require("node:crypto"),
  h = require("../../tests/e2e/helpers/certops-acme-certificate-outbox");
// Offline public contract fixture, never native execution evidence.
exports.proof = (previous) => ({
  scope: h.SCOPE,
  certificateId: crypto.randomUUID(),
  jobId: crypto.randomUUID(),
  claimId: crypto.randomUUID(),
  fingerprints: [
    previous.originalServingFingerprint,
    crypto.randomBytes(32).toString("hex"),
  ],
  attemptCount: 1,
  extraCaOrdersAfterRestart: 0,
  fixtureStopAfterNativeSuccess: true,
  jobCancellationQualified: false,
  ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
});
