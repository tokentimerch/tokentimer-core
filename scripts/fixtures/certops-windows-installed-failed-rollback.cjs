"use strict";
/** Synthetic failed-rollback contract fixture; never native execution. */
const proof = require("../../tests/e2e/helpers/certops-windows-installed-failed-rollback");
const old = require("./certops-windows-installed-verify-rollback.cjs");
function fixture() {
  const baseline = old.fixture();
  return {
    scope: proof.SCOPE,
    ...Object.fromEntries(
      [
        "certificateId",
        "jobIds",
        "claimIds",
        "fingerprints",
        "spkiFingerprints",
      ].map((name) => [name, baseline[name]]),
    ),
    failedJobStatus: "failed",
    failureCode: "VERIFY_FAILED",
    rolledBack: false,
    retryJobStatus: "succeeded",
    bindFailureQualified: false,
    rollbackFailureQualified: true,
    originalOperationAutomaticallyRecovered: false,
    transientNewBindingObservationQualified: false,
    appIdPreservationQualified: false,
    ...Object.fromEntries(proof.FLAGS.map((name) => [name, true])),
  };
}
module.exports = { fixture };
