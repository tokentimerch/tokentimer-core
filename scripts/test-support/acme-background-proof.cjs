"use strict";
/** Offline schema/cross-proof fixtures only; never native execution evidence. */
const helper = require("../../tests/e2e/helpers/certops-acme-background-renewals");
function proof(client = "certbot", reuse) {
  const value = {
    scope: helper.SCOPE,
    client,
    schedulerInvocation: "actual-production-runner-default-cron",
    successfulAutomationCycles: 2,
    sourceProfileId:
      reuse?.sourceProfileId || "12345678-1234-1234-1234-123456789abc",
    sourceProfileFingerprint: "a".repeat(64),
    jobIds: [
      "33333333-3333-4333-8333-333333333333",
      "44444444-4444-4444-8444-444444444444",
    ],
    fingerprints: [
      "d".repeat(64),
      "e".repeat(64),
      reuse?.fingerprints[0] || "f".repeat(64),
    ],
    serials: ["A1", "B2", "C3"],
    spkiFingerprints: [
      "1".repeat(64),
      "2".repeat(64),
      reuse?.spkiFingerprint || "3".repeat(64),
    ],
    expiryEpochs: [1000, 2000, 3000],
    workerLifecycle: {
      failed: false,
      starts: 1,
      tickElapsedMs: [30000, 90000],
      finishes: 2,
      summaries: 2,
      created: 2,
      stops: 1,
      exitCode: 0,
      groupDrained: true,
      closed: true,
      pidfdPinnedBeforeExec: true,
      pidfdSignalUsed: true,
      pidfdClosed: true,
      workerWaited: true,
    },
    ...Object.fromEntries(helper.FLAGS.map((field) => [field, true])),
  };
  helper.verifyProof(value);
  return value;
}
module.exports = { proof };
