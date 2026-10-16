"use strict";
/** Closed supporting contract for the separate manual installed failed-rollback
 * journey. Native facts must come from the actual engine/holder; this module
 * alone cannot qualify a machine or an automatically recovered operation. */
const assert = require("node:assert/strict");
const existing = require("./certops-windows-installed-verify-rollback");
const holder = require("./certops-windows-predecessor-holder");
const SCOPE =
  "installed-public-renewal-absent-predecessor-failed-rollback-and-manual-retry";
const SCENARIO = "windows-installed-public-renewal-failed-rollback";
const FLAGS = Object.freeze([
  "originalNativeSniAndTrustedTls",
  "exactOwnedShadowAndSiblingAdmission",
  "actualPublicSignedCurrentClaim",
  "actualCaLeafAndProtectedCngAccepted",
  "originalPublicEntryAbsentBeforeRenewal",
  "retainedOriginalCngPossessionWhilePublicEntryAbsent",
  "actualCurrentClaimVerifyFailureAndFailedRollback",
  "nativePredecessorSniAbsentAfterFailedRollback",
  "trustedShadowAndSiblingPreserved",
  "sameOriginalPublicAssociationRestored",
  "holderNaturalExitAndNativeJobDrained",
  "exactShadowRemovedBeforeRetry",
  "freshPublicSignedRetrySucceeded",
  "freshLeafSpkiProtectedKeyAndTrustedTls",
  "profileAndProtectedStatePreserved",
  "failedAcceptedLeafOwnershipRecorded",
  "ownedEndpointCleanupCompleted",
]);
const REQUIRED_SOURCES = Object.freeze([
  ...new Set([
    "tests/e2e/helpers/certops-windows-installed-failed-rollback.js",
    ...existing.REQUIRED_SOURCES,
    ...holder.REQUIRED_SOURCES,
  ]),
]);
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "scope",
      "certificateId",
      "jobIds",
      "claimIds",
      "fingerprints",
      "spkiFingerprints",
      "failedJobStatus",
      "failureCode",
      "rolledBack",
      "retryJobStatus",
      "bindFailureQualified",
      "rollbackFailureQualified",
      "originalOperationAutomaticallyRecovered",
      "transientNewBindingObservationQualified",
      "appIdPreservationQualified",
      ...FLAGS,
    ].sort(),
  );
  assert.equal(value.scope, SCOPE);
  const uuid = (x) =>
    typeof x === "string" &&
    /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
  assert.ok(uuid(value.certificateId));
  for (const name of ["jobIds", "claimIds"])
    assert.ok(
      Array.isArray(value[name]) &&
        value[name].length === 2 &&
        value[name].every(uuid) &&
        new Set(value[name]).size === 2,
    );
  for (const name of ["fingerprints", "spkiFingerprints"])
    assert.ok(
      Array.isArray(value[name]) &&
        value[name].length === 3 &&
        value[name].every(
          (x) => typeof x === "string" && /^[a-f0-9]{64}$/.test(x),
        ) &&
        new Set(value[name]).size === 3,
    );
  assert.equal(value.failedJobStatus, "failed");
  assert.equal(value.failureCode, "VERIFY_FAILED");
  assert.equal(value.rolledBack, false);
  assert.equal(value.retryJobStatus, "succeeded");
  assert.equal(value.rollbackFailureQualified, true);
  for (const name of [
    "bindFailureQualified",
    "originalOperationAutomaticallyRecovered",
    "transientNewBindingObservationQualified",
    "appIdPreservationQualified",
  ])
    assert.equal(value[name], false);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
module.exports = {
  SCOPE,
  SCENARIO,
  FLAGS,
  REQUIRED_SOURCES,
  verifyProof,
  assertCleanupSafe: holder.assertCleanupSafe,
  qualify: (context) => existing.qualifyFailedRollback(context),
};
