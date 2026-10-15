"use strict";
const crypto = require("node:crypto");
const helper = require("../../tests/e2e/helpers/certops-acme-native-adoption");
/** Offline schema fixture only, never native qualification evidence. */
exports.proof = (previous) => ({
  scope: helper.SCOPE,
  certificateId: previous.certificateIds[0],
  profileId: crypto.randomUUID(),
  jobIds: [crypto.randomUUID(), crypto.randomUUID()],
  claimIds: [crypto.randomUUID(), crypto.randomUUID()],
  fingerprints: [
    previous.fingerprints[2],
    crypto.randomBytes(32).toString("hex"),
  ],
  spkiFingerprints: [
    previous.spkiFingerprints[2],
    crypto.randomBytes(32).toString("hex"),
  ],
  ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
});
