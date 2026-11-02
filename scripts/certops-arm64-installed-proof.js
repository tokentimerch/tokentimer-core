"use strict";
/** Actual installed ARM64 agent/API proof. Certificate planning and native
 * discovery are separate observations; neither qualifies issuance or IIS. */
const assert = require("node:assert/strict");
const suite = "windows-arm64-installed-agent";
const SCOPE = "native-windows11-arm64-installed-agent-api-signed-file-plan-and-my-discovery";
const FLAGS = Object.freeze(["canonicalRootAndServiceInitiallyAbsent", "originalCandidateInstallerUnchanged", "actualNativeArm64NodePwshAndPackagedHost", "actualLocalSystemAgentChild", "publicBootstrapExchangedAndScrubbed", "authenticatedRegistrationAndHeartbeat", "actualSignedNoopCompleted", "actualSignedCertificateDryRunPlan", "claimBoundPersistedEvidence", "nativeMyCertificateObservedByAgent", "exactProtectedMyCustodyUnchanged", "restartCreatedFreshOwnedProcesses", "authenticatedHeartbeatAfterRestart", "configurationCredentialSigningPinPreserved", "unmodifiedProductUninstall", "retainedOwnedProcessesDrained", "completeMachineWideSurvivorGuardBeforeDeletion", "exactNativeCertificateAndKeyRemoved", "exactServiceRegistryAndOwnedRootsAbsent"]);
const REQUIRED_SCENARIOS = Object.freeze(["windows-arm64-product-install-and-registration", "windows-arm64-signed-noop-and-certificate-file-plan", "windows-arm64-my-native-discovery-and-restart", "windows-arm64-installed-agent-owned-cleanup"]);
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "architecture", "productType", "build", "certificateDryRunTarget", "postgresArchitecture", "postgresExecution", "postgresVersion", "postgresArchiveSha256", "candidateArchiveSha256", "hostSha256", "certificateFingerprint", "jobIds", "claimIds", "agentRowId", "issuanceQualified", "iisQualified", "serverQualified", "publicCertificateAdmissionQualified", "serviceCreatedDryRun", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE); assert.equal(value.architecture, "arm64"); assert.equal(value.productType, 1);
  assert.match(value.build, /^[0-9]{5,6}$/); assert.ok(Number(value.build) >= 22000);
  assert.equal(value.certificateDryRunTarget, "file-path"); assert.equal(value.postgresArchitecture, "x64"); assert.equal(value.postgresExecution, "windows11-x64-emulation");
  const lock = require("./certops-arm64-postgres-lock.json");
  assert.equal(value.postgresVersion, lock.version); assert.equal(value.postgresArchiveSha256, lock.sha256);
  for (const key of ["candidateArchiveSha256", "hostSha256", "certificateFingerprint"]) assert.match(value[key], /^[a-f0-9]{64}$/);
  for (const key of ["issuanceQualified", "iisQualified", "serverQualified", "publicCertificateAdmissionQualified"]) assert.equal(value[key], false);
  assert.equal(value.serviceCreatedDryRun,true);
  const uuid = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
  assert.match(value.agentRowId, uuid);
  for (const field of ["jobIds", "claimIds"]) {
    assert.ok(Array.isArray(value[field]) && value[field].length === 2); value[field].forEach(id => assert.match(id, uuid)); assert.equal(new Set(value[field]).size, 2);
  }
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function verifyRuntimeReport(report){
 verifyProof(report.nativeArm64InstalledAgent);assert.equal(report.platform,"win32");assert.equal(report.architecture,"arm64");const env=report.qualificationEnvironment;
 assert.equal(env.osFamily,"windows");assert.equal(env.productType,1);assert.equal(env.architecture,"arm64");assert.equal(env.osVersion,`desktop-${report.nativeArm64InstalledAgent.build}`);assert.equal(env.measurement,"native");assert.equal(env.identity,"LocalSystem");assert.equal(report.cleanup.status,"passed");return true;
}
module.exports = { suite, SCOPE, FLAGS, REQUIRED_SCENARIOS, verifyProof,verifyRuntimeReport };
