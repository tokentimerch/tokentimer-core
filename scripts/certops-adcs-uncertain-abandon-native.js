"use strict";
/** Native sidecar reuses the executed zero-request transport-refusal journey.
 * This never qualifies lost-submit response loss or local marker contracts. */
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const native=require("../tests/e2e/helpers/certops-adcs-uncertain-abandon"),browser=require("../tests/e2e/helpers/certops-adcs-browser-abandon");
const SOURCE="scripts/certops-adcs-uncertain-abandon-native.js",SUITE="adcs-uncertain-abandon",SCOPE="native-zero-request-browser-abandon-and-protected-key-cleanup";
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
function nativeRequiredScenarios(){return ["adcs-real-installed-native-language","adcs-real-agent-registration-system","adcs-real-uncertain-zero-request-owned-termination","adcs-real-uncertain-zero-request-acknowledged-recovery","adcs-real-uncertain-zero-request-public-abandon-cleans-key",...browser.REQUIRED_SCENARIOS,"adcs-real-owned-cleanup"];}
function nativeRequiredSources(){return [...new Set([SOURCE,"scripts/certops_adcs_uncertain_abandon_proof.py",...native.REQUIRED_SOURCES,...browser.REQUIRED_SOURCES,"infra/certops-adcs/provision-lab.ps1","infra/certops-adcs/read-report.ps1","infra/certops-adcs/run-windows-tests.ps1","infra/certops-adcs/control-plane.sh",".github/workflows/certops-enterprise-adcs-qualification.yml"])];}
function verifyNativeProof(p){
 assert.deepEqual(Object.keys(p).sort(),["scope","nativeExecutionQualified","disposableForestRan","hostCapabilityAbsentIsPass","responseLossQualified","parentSuite","native","browser","identity"].sort());
 assert.equal(p.scope,SCOPE);assert.equal(p.nativeExecutionQualified,true);assert.equal(p.disposableForestRan,true);assert.equal(p.hostCapabilityAbsentIsPass,false);assert.equal(p.responseLossQualified,false);assert.equal(p.parentSuite,"enterprise-adcs-real");
 native.assertProof(p.native);browser.verifyProof(p.browser);
 assert.deepEqual(Object.keys(p.identity).sort(),["enrollmentId","originalJobId","recoveryJobId","cleanupJobId","containerName","csrSha256","csrSpkiSha256"].sort());
 for(const key of ["enrollmentId","originalJobId","recoveryJobId","cleanupJobId"])assert.match(p.identity[key],UUID);
 assert.equal(new Set([p.identity.originalJobId,p.identity.recoveryJobId,p.identity.cleanupJobId]).size,3);
 assert.equal(p.identity.containerName,"tokentimer-enr-"+p.identity.enrollmentId);
 for(const key of ["csrSha256","csrSpkiSha256"])assert.match(p.identity[key],/^[a-f0-9]{64}$/);
 assert.equal(p.browser.enrollmentId,p.identity.enrollmentId);assert.equal(p.browser.cleanupJobId,p.identity.cleanupJobId);return true;
}
function createNativeReport(parent, { candidateSha = process.env.GITHUB_SHA, root = path.resolve(__dirname, "..") } = {}) {
  assert.match(candidateSha || "", /^[a-f0-9]{40}$/);
  assert.equal(parent.suite, "enterprise-adcs-real");
  assert.equal(parent.experimental === true || parent.qualificationStatus === "not-qualified", false);
  assert.equal(parent.artifactQualification, "workflow-checkout-source");
  assert.equal(parent.platform, "win32"); assert.equal(parent.architecture, "x64");
  for (const [field, value] of Object.entries({osFamily:"windows",osVersion:"2022",nativeLanguage:"en-US",identity:"LocalSystem",measurement:"native"})) assert.equal(parent.qualificationEnvironment?.[field], value);
  assert.equal(parent.cleanup?.status, "passed");
  assert.deepEqual(require("./certops-qualification-report").verifyReport(parent, undefined, {expectedSha:candidateSha}), []);
  const fingerprint = file => ({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  assert.deepEqual(parent.fixtureSource, fingerprint("tests/e2e/certops-adcs-real-e2e.test.js"));
  const fixtureSources = nativeRequiredSources().map(file => {
    const actual = fingerprint(file), entries = parent.fixtureSources?.filter(entry => entry.file === file);
    assert.equal(entries?.length, 1, "Native abandonment producer source must be observed exactly once");
    assert.deepEqual(entries[0], actual);
    return actual;
  });
  const requiredScenarios = nativeRequiredScenarios();
  const scenarios = requiredScenarios.map(id => {
    const records = parent.scenarios.filter(entry => entry.id === id);
    assert.equal(records.length, 1); assert.equal(records[0].status, "passed");
    assert.equal(records[0].evidenceLevel, "real-host");
    return {...records[0]};
  });
  const ordered = scenarios.filter(row=>!require("../tests/e2e/helpers/certops-adcs-browser-abandon").REQUIRED_SCENARIOS.includes(row.id));
  for (let i=1;i<ordered.length;i++) assert.ok(Date.parse(ordered[i-1].finishedAt) <= Date.parse(ordered[i].startedAt), "Actual native stages must complete in order");
  const abandonStage=scenarios.find(row=>row.id==="adcs-real-uncertain-zero-request-public-abandon-cleans-key");
  const browserStages=browser.REQUIRED_SCENARIOS.map(id=>scenarios.find(row=>row.id===id));
  for(const row of browserStages)assert.ok(Date.parse(row.startedAt)>=Date.parse(abandonStage.startedAt)&&Date.parse(row.finishedAt)<=Date.parse(abandonStage.finishedAt),"Browser action must belong to actual native abandonment");
  assert.ok(Date.parse(browserStages[0].finishedAt)<=Date.parse(browserStages[1].startedAt));
  const proof = {scope:SCOPE,nativeExecutionQualified:true,disposableForestRan:true,hostCapabilityAbsentIsPass:false,responseLossQualified:false,parentSuite:parent.suite,native:structuredClone(parent.nativeUncertainAbandon),browser:structuredClone(parent.nativeBrowserAbandon),identity:structuredClone(parent.nativeUncertainAbandonIdentity)};
  verifyNativeProof(proof);
  const report = {...parent,suite:SUITE,evidenceLevel:"real-host",fixtureSource:fingerprint(SOURCE),fixtureSources,requiredScenarios,scenarios,
    requiredCapabilities:["windows","elevated","domain","api","qualifiedBuild","browserRuntime","dashboard"],missingScenarios:[],missingCapabilities:[],nativeAdcsUncertainAbandon:proof};
  // Copy only bounded public fields; do not republish unrelated native receipts.
  const keys = ["schemaVersion","suite","strict","status","candidateSha","startedAt","finishedAt","platform","architecture","cleanup","qualificationEnvironment","artifactQualification","evidenceLevel","fixtureSource","fixtureSources","requiredScenarios","scenarios","requiredCapabilities","capabilities","missingScenarios","missingCapabilities","nativeAdcsUncertainAbandon"];
  const result = Object.fromEntries(keys.map(key => [key,report[key]]));
  assert.deepEqual(require("./certops-qualification-report").verifyReport(result, undefined, {expectedSha:candidateSha}), []);
  return result;
}

module.exports={SOURCE,SUITE,SCOPE,nativeRequiredScenarios,nativeRequiredSources,verifyNativeProof,createNativeReport};
