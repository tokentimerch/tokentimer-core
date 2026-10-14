"use strict";
/** Desktop ARM64 SCM proof consumes actual packaged-host/mock-child measurements.
 * It never qualifies the real agent, API, installer, IIS or Windows Server. */
const assert = require("node:assert/strict");
const suite = "windows-arm64-packaged-scm";
const SCOPE = "native-windows11-arm64-candidate-packaged-servicehost-mockchild-lifecycle";
const FLAGS = Object.freeze(["canonicalServiceInitiallyAbsent", "candidateArchiveDigestVerified", "packagedHostExactDigestAndArm64Pe", "nativeArm64DesktopAndRuntimes", "exactLocalSystemServiceConfiguration", "actualScmRunningWithOwnedChild", "stopDrainedExactProcessTree", "restartCreatedFreshOwnedProcesses", "nonzeroChildExitTriggeredScmRecovery", "retiredChildExitStoppedWithoutRespawn", "exactServiceAndRegistryAbsent", "allCapturedProcessesAbsent", "ownedFixtureRemoved", "originalFileIdentitiesPreserved"]);
const REQUIRED_SCENARIOS = Object.freeze(["windows-arm64-packaged-servicehost-and-native-desktop", "windows-arm64-scm-start-stop-restart", "windows-arm64-scm-failure-recovery-and-retirement", "windows-arm64-scm-exact-owned-cleanup"]);
function verifyProof(value) {
  assert.deepEqual(Object.keys(value).sort(), ["scope", "architecture", "productType", "build", "hostSha256", "archiveSha256", "realAgentQualified", "apiQualified", "fullInstallerQualified", "iisQualified", "serverQualified", "retirementObservationMs", "generations", ...FLAGS].sort());
  assert.equal(value.scope, SCOPE); assert.equal(value.architecture, "arm64"); assert.equal(value.productType, 1); assert.match(value.build, /^[0-9]{5,6}$/); assert.ok(Number(value.build) >= 22000);
  for (const key of ["hostSha256", "archiveSha256"]) assert.match(value[key], /^[a-f0-9]{64}$/);
  for (const key of ["realAgentQualified", "apiQualified", "fullInstallerQualified", "iisQualified", "serverQualified"]) assert.equal(value[key], false, key);
  assert.ok(Number.isSafeInteger(value.retirementObservationMs) && value.retirementObservationMs >= 5000 && value.retirementObservationMs <= 20000);
  assert.ok(Array.isArray(value.generations) && value.generations.length === 3);
  const identities = new Set();
  for (const row of value.generations) {
    assert.deepEqual(Object.keys(row).sort(), ["hostPid", "hostCreated", "childPid", "childCreated"].sort());
    for (const key of ["hostPid", "childPid"]) { assert.ok(Number.isSafeInteger(row[key]) && row[key] > 0 && row[key] <= 0xffffffff); }
    assert.notEqual(row.hostPid, row.childPid);
    for (const key of ["hostCreated", "childCreated"]) { assert.match(row[key], /^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z$/); assert.ok(Number.isFinite(Date.parse(row[key]))); }
    assert.ok(Date.parse(row.childCreated) >= Date.parse(row.hostCreated));
    for (const prefix of ["host", "child"]) { const id = row[`${prefix}Pid`] + ":" + row[`${prefix}Created`]; assert.ok(!identities.has(id), "Recovery must create fresh actual processes"); identities.add(id); }
  }
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  return true;
}
function verifyRuntimeReport(report) {
  verifyProof(report.nativeArm64Scm); assert.equal(report.platform, "win32"); assert.equal(report.architecture, "arm64");
  const environment=report.qualificationEnvironment; assert.equal(environment.osFamily,"windows"); assert.equal(environment.productType,1); assert.equal(environment.architecture,"arm64"); assert.equal(environment.osVersion,`desktop-${report.nativeArm64Scm.build}`); assert.equal(environment.measurement,"native"); assert.equal(report.cleanup.status,"passed");
  const fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto"),root=path.resolve(__dirname,"..");
  const sources=require("./certops-arm64-scm-runtime").REQUIRED_SOURCES;
  assert.deepEqual(report.fixtureSources.map(row=>row.file).sort(),[...sources].sort());
  for(const row of report.fixtureSources){assert.deepEqual(Object.keys(row).sort(),["file","sha256"]);assert.equal(row.sha256,crypto.createHash("sha256").update(fs.readFileSync(path.join(root,row.file))).digest("hex"));}
  assert.deepEqual(report.fixtureSource,report.fixtureSources.find(row=>row.file==="scripts/certops-arm64-scm-runtime.js"));return true;
}
module.exports = { suite, SCOPE, FLAGS, REQUIRED_SCENARIOS, verifyProof, verifyRuntimeReport };
