"use strict";
// Exercise archive extraction and immutable installed bytes, not a mocked tar
// listing. The packaging regression in packages/agent covers the real Go files.
const { test } = require("node:test"), assert = require("node:assert/strict"), fs = require("node:fs"), os = require("node:os"), path = require("node:path"), { spawnSync } = require("node:child_process");
const { extractVerified, verifyInstalled, digest, verifyAdcsAcceptance, verifyOperatorScope, ADCS_ACCEPTANCE_SCENARIOS } = require("./certops-agent-package");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-package-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const file of ["package/bin/tokentimer-agent.js", "package/scripts/install-agent.ps1", "package/scripts/install-agent.sh", "package/package.json"]) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), file.endsWith("json") ? "{}" : "fixture-only");
  }
  const archive = path.join(root, "agent.tgz");
  assert.equal(spawnSync("tar", ["-czf", "agent.tgz", "package"], { cwd: root }).status, 0);
  return { root, archive };
}

test("AD CS package receipt rejects missing execution, skipped scenarios and release promotion", () => {
  const candidateSha = "a".repeat(40), artifact = { candidateSha, sha256: "b".repeat(64), buildMode: "qualification-only-not-release" };
  const report = {
    suite: "adcs-package-operator-acceptance", status: "passed", strict: true,
    candidateSha, packageSha256: artifact.sha256, qualificationStatus: "not-qualified", buildMode: artifact.buildMode,
    publishedReleaseQualified: false, certificateDatabaseInjection: false, workerDriven: true,
    nativeEnvironment:{osFamily:"windows",productType:"3",windowsVersion:"2022",build:"20348",language:"en-US",uiCulture:"en-US",systemLocale:"en-US",identitySid:"S-1-5-18",domain:"lab.certops.test",installedDisplayResources:true,measurement:"native"},
    cleanup: { status: "passed" }, requiredScenarios: [...ADCS_ACCEPTANCE_SCENARIOS],
    packagePendingWorker: { scheduler: "deployed-production-runner", pollIntervalSeconds: 60,
      enrollmentId: "11111111-1111-4111-8111-111111111111", initialJobId: "22222222-2222-4222-8222-222222222222", continuationJobId: "33333333-3333-4333-8333-333333333333", requestId: "42",
      actualManagerApproval: true, claimBoundContinuation: true, originalCsrKeyAndSnapshotPreserved: true, trustedIisCutover: true, noSchedulerOrClockOverride: true },
    missingScenarios: [], missingCapabilities: [], scenarios: ADCS_ACCEPTANCE_SCENARIOS.map(id => ({ id, status: "passed" })),
  };
  const browser=require("../tests/e2e/helpers/certops-adcs-browser-journey");
  report.nativeBrowserAdcs={scope:browser.SCOPE,lifecycle:"renew-existing-inventory-not-first-issue-or-manual-job",scheduler:"production-maintenance-worker",browserEngine:"chromium",browserMutationCount:6,successfulEnrollments:1,fingerprints:["1".repeat(64),"2".repeat(64)],spkiFingerprints:["3".repeat(64),"4".repeat(64)],requestId:"41",...Object.fromEntries(["enrollmentId","jobId","profileId","issuerId"].map((field,i)=>[field,`${i+1}1111111-1111-4111-8111-111111111111`])),...Object.fromEntries(browser.FLAGS.map(flag=>[flag,true]))};
  assert.equal(verifyAdcsAcceptance(report, artifact, candidateSha), true);
  const previousSha=process.env.GITHUB_SHA;
  try{
    process.env.GITHUB_SHA=candidateSha;
    const infrastructure={candidateSha,scope:"disposable-enterprise-adcs-infrastructure",qualificationScope:"operator-acceptance",status:"provisioned-and-native-scenarios-completed",scenarioReport:"enterprise-adcs-package-acceptance.json",stages:["installed-language-verified","installed-language-verified","acceptance-worker-started","operator-package-acceptance-passed","acceptance-worker-stopped","operator-acceptance-only-completed-not-comprehensive"].map(value=>`CERTOPS_STAGE=${value}`)};
    assert.equal(verifyOperatorScope(infrastructure,report),true);
    for(const mutate of [value=>{delete value.scope;},value=>{value.scope="other";},value=>{value.qualificationScope="comprehensive";},value=>{value.scenarioReport="enterprise-adcs-real.json";},value=>{value.stages.pop();},value=>{value.stages.shift();},value=>{value.stages.push("CERTOPS_STAGE=real-enterprise-adcs-tests-passed");}]){const invalid=structuredClone(infrastructure);mutate(invalid);assert.throws(()=>verifyOperatorScope(invalid,report));}
    const invalid=structuredClone(report);invalid.nativeEnvironment.language="fr-FR";assert.throws(()=>verifyOperatorScope(infrastructure,invalid));
    for(const mutate of [value=>{delete value.nativeBrowserAdcs;},value=>{value.nativeBrowserAdcs.scheduler="production-default-sweep-not-background-worker-loop";},value=>{value.nativeBrowserAdcs.nonexportableMachineCng=false;},value=>{value.nativeBrowserAdcs.nativeCaRequestMatched=false;},value=>{value.nativeBrowserAdcs.requestId="0";}]){const invalid=structuredClone(report);mutate(invalid);assert.throws(()=>verifyOperatorScope(infrastructure,invalid));assert.throws(()=>verifyAdcsAcceptance(invalid,artifact,candidateSha));}

    for(const mutate of [value=>{value.buildMode="release";},value=>{delete value.buildMode;},value=>{value.packageSha256="not-a-digest";},value=>{delete value.packageSha256;}]){const invalid=structuredClone(report);mutate(invalid);assert.throws(()=>verifyOperatorScope(infrastructure,invalid));}
  }finally{if(previousSha===undefined)delete process.env.GITHUB_SHA;else process.env.GITHUB_SHA=previousSha;}
  for (const change of [
    r => { r.scenarios.pop(); }, r => { r.scenarios[0].status = "skipped"; },
    r => { r.scenarios.push(r.scenarios[0]); }, r => { r.cleanup.status = "failed"; },
    r => { r.packageSha256 = "c".repeat(64); }, r => { r.workerDriven = false; },
    r => { r.certificateDatabaseInjection = true; }, r => { r.publishedReleaseQualified = true; },
    r => { r.missingCapabilities.push("adcs-enroll-v1"); }, r => { r.qualificationStatus = "qualified"; },
    r => { delete r.packagePendingWorker; }, r => { r.packagePendingWorker.noSchedulerOrClockOverride = false; },
    r => {delete r.nativeEnvironment;},r=>{r.nativeEnvironment.build="26100";},r=>{r.nativeEnvironment.uiCulture="fr-FR";},r=>{r.nativeEnvironment.systemLocale="de-DE";},r=>{r.nativeEnvironment.identitySid="S-1-5-21-1";},r=>{r.nativeEnvironment.productType="1";},r=>{r.nativeEnvironment.installedDisplayResources=false;},r=>{r.nativeEnvironment.measurement="simulated";},
  ]) {
    const invalid = structuredClone(report); change(invalid);
    assert.throws(() => verifyAdcsAcceptance(invalid, artifact, candidateSha));
  }
  assert.throws(() => verifyAdcsAcceptance(report, artifact, "d".repeat(40)));
});
test("operator-only provisioning rejects fault experiments before any Azure operation",()=>{
  for(const extra of [["-JournalPhaseExperiment","issued"],["-ResponseLossExperiment","1"]]){
    const result=spawnSync("pwsh",["-NoProfile","-NonInteractive","-File",path.resolve(__dirname,"../infra/certops-adcs/provision-lab.ps1"),"-ResourceGroup","tt-certops-123-1","-Location","swedencentral","-QualificationScope","operator-acceptance",...extra],{encoding:"utf8",windowsHide:true,timeout:15000});
    assert.ifError(result.error);assert.notEqual(result.status,0);assert.match(result.stdout+result.stderr,/Operator acceptance cannot include fault experiments/);
  }
});
test("acceptance verifies archive checksum and all installed bytes, refusing tampering and added files", t => {
  const { root, archive } = fixture(t);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: "0".repeat(64), destination: path.join(root, "bad") }));
  assert.equal(fs.existsSync(path.join(root, "bad")), false);
  const extracted = extractVerified({ tarball: archive, expectedSha256: digest(archive), destination: path.join(root, "extracted") });
  const installed = path.join(root, "installed"); fs.cpSync(extracted.root, installed, { recursive: true });
  assert.doesNotThrow(() => verifyInstalled(extracted.files, installed));
  fs.writeFileSync(path.join(installed, "unexpected.js"), "fixture-only");
  assert.throws(() => verifyInstalled(extracted.files, installed));
  fs.unlinkSync(path.join(installed, "unexpected.js"));
  fs.appendFileSync(path.join(installed, "bin/tokentimer-agent.js"), "tampered");
  assert.throws(() => verifyInstalled(extracted.files, installed));
});
test("acceptance refuses reused extraction roots and incomplete packages", t => {
  const { root, archive } = fixture(t), destination = path.join(root, "existing");
  fs.mkdirSync(destination);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: digest(archive), destination }));
  fs.unlinkSync(path.join(root, "package/scripts/install-agent.ps1"));
  assert.equal(spawnSync("tar", ["-czf", "agent.tgz", "package"], { cwd: root }).status, 0);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: digest(archive), destination: path.join(root, "incomplete") }));
});
test("acceptance rejects hard links before extracting an otherwise valid package", t => {
  const { root, archive } = fixture(t);
  fs.linkSync(path.join(root, "package/bin/tokentimer-agent.js"), path.join(root, "package/bin/linked.js"));
  assert.equal(spawnSync("tar", ["-czf", "agent.tgz", "package"], { cwd: root }).status, 0);
  assert.throws(() => extractVerified({ tarball: archive, expectedSha256: digest(archive), destination: path.join(root, "links") }));
  assert.equal(fs.existsSync(path.join(root, "links")), false);
});
