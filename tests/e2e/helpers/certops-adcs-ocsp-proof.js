"use strict";
// Closed signed-good OCSP availability report. Authoritative revoked status
// is a separate proof and stays false here. Native lab execution is still pending.
const assert = require("node:assert/strict");
const SCOPE =
  "real-installed-adcs-native-microsoft-ocsp-good-unavailable-recovered";
const REQUIRED_SCENARIOS = Object.freeze([
  "adcs-real-native-ocsp-delegated-signer",
  "adcs-real-ocsp-only-leaf-native-endpoint-recovery",
  "adcs-real-ocsp-original-publication-renewal-and-drain",
  "adcs-real-ocsp-deferred-same-leaf-signed-continuation",
  "adcs-real-ocsp-authoritative-historical-revoked-status",
]);
const FLAGS = Object.freeze([
  "originalCaAndRoleAbsenceBound",
  "ownedTemplateAndSignerRequestBound",
  "actualNonexportableSignerAndServiceAcl",
  "independentDelegatedSignatureAndNoCheck",
  "nativeResponderConfigurationBound",
  "actualOcspOnlyLeaf",
  "actualPublicRenewalsAndClaimEvidence",
  "independentNativeRequestIds",
  "originalPublicationRestoredBeforeFault",
  "actualSignedGoodResponses",
  "actualProgramScopedFirewallFault",
  "nativeValidUnknownValid",
  "sameCustodyBindingAndTrustedTls",
  "restoredPublicationReplacementInstalled",
  "originalCachePolicyAndFirewallRestored",
  "ownedConfigurationAndTemplateRemoved",
  "ownedSignerCertificateAndKeyAbsent",
  "ownedResponderAndIisStoppedDisabledDrained",
  "ownedGuardReleased",
  "installedAgentFaultRecoveryQualified",
]);
const FALSE_FLAGS = Object.freeze([
  "authoritativeRevokedStatusQualified",
  "signedCmcRenewalQualified",
  "individualFeaturePackageRemovalQualified",
]);
const FIELDS = Object.freeze([
  "scope",
  "enrollmentIds",
  "jobIds",
  "requestIds",
  "signerRequestId",
  "leafFingerprints",
  "signerFingerprint",
  "issuerKeySha256",
  "nativeHelperSha256",
  "publicCrlSha256",
  "responseSha256",
  "caRequestCounts",
  "nativeVerdicts",
  "deferredRecovery",
  ...FLAGS,
  ...FALSE_FLAGS,
]);
function verifyProof(value) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...FIELDS].sort());
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS)
    assert.equal(value[flag], true, `Missing OCSP fact: ${flag}`);
  for (const flag of FALSE_FLAGS)
    assert.equal(value[flag], false, `Unsupported OCSP promotion: ${flag}`);
  for (const key of ["enrollmentIds", "jobIds"]) {
    assert.ok(Array.isArray(value[key]) && value[key].length === 2);
    assert.ok(
      value[key].every(
        (id) =>
          typeof id === "string" &&
          /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id),
      ),
    );
    assert.equal(new Set(value[key].map((id) => id.toLowerCase())).size, 2);
  }
  const positiveId = (id) => Number.isInteger(id) && id > 0 && id <= 0xffffffff;
  assert.ok(positiveId(value.signerRequestId));
  assert.ok(
    Array.isArray(value.requestIds) &&
      value.requestIds.length === 2 &&
      value.requestIds.every(positiveId),
  );
  assert.equal(new Set([value.signerRequestId, ...value.requestIds]).size, 3);
  const recovery = value.deferredRecovery;
  assert.ok(
    recovery && typeof recovery === "object" && !Array.isArray(recovery),
  );
  assert.deepEqual(
    Object.keys(recovery).sort(),
    [
      "originalJobId",
      "originalClaimId",
      "continuationJobId",
      "continuationClaimId",
      "requestId",
    ].sort(),
  );
  for (const key of [
    "originalJobId",
    "originalClaimId",
    "continuationJobId",
    "continuationClaimId",
  ])
    assert.match(
      recovery[key],
      /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i,
    );
  assert.ok(
    !value.jobIds
      .map((id) => id.toLowerCase())
      .includes(recovery.originalJobId.toLowerCase()),
  );
  assert.notEqual(
    recovery.originalClaimId.toLowerCase(),
    recovery.continuationClaimId.toLowerCase(),
  );
  assert.equal(recovery.continuationJobId, value.jobIds[0]);
  assert.equal(recovery.requestId, value.requestIds[0]);
  for (const key of ["leafFingerprints", "responseSha256"]) {
    assert.ok(
      Array.isArray(value[key]) &&
        value[key].length === (key === "leafFingerprints" ? 2 : 3),
    );
    assert.ok(
      value[key].every(
        (digest) => typeof digest === "string" && /^[a-f0-9]{64}$/.test(digest),
      ),
    );
  }
  assert.notEqual(value.leafFingerprints[0], value.leafFingerprints[1]);
  for (const key of [
    "signerFingerprint",
    "issuerKeySha256",
    "nativeHelperSha256",
    "publicCrlSha256",
  ])
    assert.match(value[key], /^[a-f0-9]{64}$/);
  assert.ok(!value.leafFingerprints.includes(value.signerFingerprint));
  assert.ok(
    Array.isArray(value.caRequestCounts) &&
      value.caRequestCounts.length === 4 &&
      value.caRequestCounts.every(
        (n) => Number.isSafeInteger(n) && n >= 0 && n <= 2048,
      ),
  );
  for (let i = 1; i < 4; i++)
    assert.equal(value.caRequestCounts[i] - value.caRequestCounts[i - 1], 1);
  assert.deepEqual(value.nativeVerdicts, [
    "valid",
    "revocation_unknown",
    "valid",
  ]);
  return value;
}
module.exports = {
  SCOPE,
  REQUIRED_SCENARIOS,
  FLAGS,
  FALSE_FLAGS,
  FIELDS,
  verifyProof,
};
