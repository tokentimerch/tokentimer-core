"use strict";
const crypto = require("node:crypto"),
  h = require("../../tests/e2e/helpers/certops-acme-disabled-profile");
// Offline public contract fixture, never native evidence.
exports.proof = (previous) => ({
  scope: h.SCOPE,
  certificateId: previous.certificateIds[1],
  profileId: crypto.randomUUID(),
  jobId: crypto.randomUUID(),
  claimId: crypto.randomUUID(),
  fingerprints: [
    previous.fingerprints[3],
    crypto.randomBytes(32).toString("hex"),
  ],
  schedulerSweepQualified: false,
  backgroundWorkerQualified: false,
  ...Object.fromEntries(h.FLAGS.map((x) => [x, true])),
});
