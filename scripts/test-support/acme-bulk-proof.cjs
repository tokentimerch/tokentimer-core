"use strict";
const crypto = require("node:crypto"),
  h = require("../../tests/e2e/helpers/certops-acme-bulk-renewal");
/** Offline schema fixture only: never evidence of agent or CA execution. */
exports.proof = (reuse) => ({
  scope: h.SCOPE,
  client: "certbot",
  certificateIds: [crypto.randomUUID(), crypto.randomUUID()],
  issueJobIds: [crypto.randomUUID(), crypto.randomUUID()],
  jobIds: [crypto.randomUUID(), crypto.randomUUID()],
  claimIds: [crypto.randomUUID(), crypto.randomUUID()],
  originalServingFingerprint: reuse.fingerprints[2],
  originalServingSpki: reuse.spkiFingerprint,
  originalServingProfileId: reuse.sourceProfileId,
  fingerprints: ["1", "2", "3", "4"].map((c) => c.repeat(64)),
  spkiFingerprints: ["5", "6", "7", "8"].map((c) => c.repeat(64)),
  serials: ["11", "22", "33", "44"],
  ...Object.fromEntries(h.FLAGS.map((flag) => [flag, true])),
});
