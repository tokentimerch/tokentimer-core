"use strict";
/** Real installed signed renewal with a native duplicate-binding fault. The
 * local script-contract helper remains separate and cannot qualify this scope. */
const assert = require("node:assert/strict");
const existing = require("./certops-windows-installed-verify-rollback");
const interposer = require("./certops-windows-bind-interposer");
const SCOPE = "installed-public-renewal-native-bind-failure-rollback-and-retry";
const SCENARIO = "windows-installed-public-renewal-bind-rollback";
const FLAGS = Object.freeze(["originalNativeSniAndTrustedTls", "actualPublicSignedCurrentClaim", "actualCaLeafAndProtectedCngAccepted", "claimBoundBindFailureAndRollbackEvidence", "nativePredecessorBindingRestored", "predecessorKeyAndTrustedTlsPreserved", "siblingBindingAndTrustedTlsPreserved", "freshPublicSignedRetrySucceeded", "freshLeafSpkiProtectedKeyAndTrustedTls", "profileAndProtectedStatePreserved", "failedAcceptedLeafOwnershipRecorded", "ownedEndpointCleanupCompleted"]);
const REQUIRED_SOURCES = [...new Set([...existing.REQUIRED_SOURCES, ...interposer.SOURCES, "tests/e2e/helpers/certops-windows-installed-bind-failure-native.js"])];
function verifyProof(p) {
  assert.ok(p && typeof p === "object" && !Array.isArray(p));
  assert.deepEqual(Object.keys(p).sort(), ["scope", "certificateId", "jobIds", "claimIds", "fingerprints", "spkiFingerprints", "failedJobStatus", "failureCode", "rolledBack", "retryJobStatus", "bindFailureQualified", "rollbackFailureQualified", "expiryCleanupQualified", "transientNewBindingObservationQualified", "appIdPreservationQualified", "nativeInterposer", "serviceEnvironmentRestored", ...FLAGS].sort());
  assert.equal(p.scope, SCOPE); assert.match(p.certificateId, interposer.UUID);
  for (const field of ["jobIds", "claimIds", "fingerprints", "spkiFingerprints"]) {
    const ids = field.endsWith("Ids"), values = p[field];
    assert.ok(Array.isArray(values) && values.length === (ids ? 2 : 3) && new Set(values).size === values.length);
    for (const value of values) assert.match(value, ids ? interposer.UUID : /^[a-f0-9]{64}$/);
  }
  assert.equal(p.failedJobStatus, "failed"); assert.equal(p.failureCode, "BIND_FAILED");
  assert.equal(p.rolledBack, true); assert.equal(p.retryJobStatus, "succeeded");
  assert.equal(p.bindFailureQualified, true); assert.equal(p.serviceEnvironmentRestored, true);
  for (const field of FLAGS) assert.equal(p[field], true, field);
  for (const field of ["rollbackFailureQualified", "expiryCleanupQualified", "transientNewBindingObservationQualified", "appIdPreservationQualified"]) assert.equal(p[field], false, field);
  interposer.verifyNativeReceipt(p.nativeInterposer, { jobId: p.jobIds[0], selector: p.nativeInterposer.selector, predecessor: p.nativeInterposer.predecessorThumbprint, candidate: p.nativeInterposer.candidateThumbprint });
  assert.notEqual(p.nativeInterposer.predecessorThumbprint, p.nativeInterposer.candidateThumbprint);
  assert.equal(p.nativeInterposer.predecessorFingerprintSha256, p.fingerprints[0]);
  assert.equal(p.nativeInterposer.candidateFingerprintSha256, p.fingerprints[1]);
  return true;
}
async function qualify(c) {
  const nativeBindInterposer = await interposer.start(c);
  // No finally teardown: an uncertain native state intentionally preserves its
  // guard and original registry receipt for owned runner disposal/recovery.
  const result = await existing.qualifyBindFailure({ ...c, nativeBindInterposer });
  await nativeBindInterposer.restore();
  result.proof.serviceEnvironmentRestored = true;
  verifyProof(result.proof);
  return result;
}
module.exports = { SCOPE, SCENARIO, FLAGS, REQUIRED_SOURCES, verifyProof, qualify };
