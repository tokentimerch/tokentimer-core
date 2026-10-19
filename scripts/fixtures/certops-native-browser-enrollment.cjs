"use strict";
// Synthetic verifier input only: no browser, enrollment, CA or host is executed.
const fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const root = path.resolve(__dirname,"../..");
const helper = require("../../tests/e2e/helpers/certops-adcs-browser-enrollment");
const journey = require("../../tests/e2e/helpers/certops-adcs-browser-journey");
const contract = require("../../docs/certops/qualification-suites.json");
function parentReport() {
  const uuid = digit => `${digit.repeat(8)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(4)}-${digit.repeat(12)}`;
  const native = {scope:journey.SCOPE,lifecycle:"renew-existing-inventory-not-first-issue-or-manual-job",scheduler:"production-default-sweep-not-background-worker-loop",browserEngine:"chromium",browserMutationCount:6,successfulEnrollments:1,
    fingerprints:["a".repeat(64),"b".repeat(64)],spkiFingerprints:["c".repeat(64),"d".repeat(64)],requestId:"17",enrollmentId:uuid("1"),jobId:uuid("2"),profileId:uuid("3"),issuerId:uuid("4"),...Object.fromEntries(journey.FLAGS.map(key=>[key,true]))};
  const suite="enterprise-adcs-real",stamp="2026-10-18T00:00:00.000Z";
  const fingerprint = file => ({file,sha256:crypto.createHash("sha256").update(fs.readFileSync(path.join(root,file))).digest("hex")});
  const scenarios=contract.suites[suite].map(id=>({id,status:"passed",evidenceLevel:"real-host",startedAt:stamp,finishedAt:stamp}));
  helper.nativeRequiredScenarios().forEach((id,i)=>{const entry=scenarios.find(row=>row.id===id);entry.startedAt=new Date(Date.parse(stamp)+i*1000).toISOString();entry.finishedAt=new Date(Date.parse(stamp)+i*1000+500).toISOString();});
  return {schemaVersion:1,suite,strict:true,status:"passed",candidateSha:"a".repeat(40),startedAt:stamp,finishedAt:"2026-10-18T01:00:00.000Z",platform:"win32",architecture:"x64",cleanup:{status:"passed"},evidenceLevel:"real-host",artifactQualification:"workflow-checkout-source",
    qualificationEnvironment:{osFamily:"windows",osVersion:"2022",nativeLanguage:"en-US",identity:"LocalSystem",measurement:"native"},
    requiredCapabilities:contract.requiredCapabilities[suite],capabilities:Object.fromEntries(contract.requiredCapabilities[suite].map(key=>[key,{available:true}])),
    requiredScenarios:contract.suites[suite],scenarios,missingScenarios:[],missingCapabilities:[],fixtureSource:fingerprint("tests/e2e/certops-adcs-real-e2e.test.js"),fixtureSources:helper.nativeRequiredSources().map(fingerprint),nativeBrowserAdcs:native};
}
function nativeReport(){const parent=parentReport();return helper.createNativeReport(parent,{candidateSha:parent.candidateSha});}
module.exports={parentReport,nativeReport};
