"use strict";
/**
 * Checks explicitly experimental lost-response observations from the isolated native CA harness.
 * Invoked by its manual experiment workflow; requires the recorded fault window and source
 * identity without promoting uncertain or experimental outcomes into release qualification.
 */
const fs=require("node:fs");
const assert=require("node:assert/strict");
const {verifyCandidateProof}=require("../tests/e2e/helpers/certops-adcs-response-loss-candidates");
function verify(report,candidate){
  assert.equal(report.scope,"enterprise-adcs-response-loss-experimental");
  assert.equal(report.qualificationStatus,"not-qualified");
  assert.equal(report.status,"passed");
  assert.match(candidate,/^[a-f0-9]{40}$/);assert.equal(report.candidateSha,candidate);
  assert.equal(report.fault?.caRequestObserved,true);assert.equal(report.fault?.ownedServiceTree,true);
  assert.ok(Number.isInteger(report.fault.requestId)&&report.fault.requestId>0&&report.fault.requestId<=0xffffffff);
  assert.ok(Number.isInteger(report.fault.killedProcessId)&&report.fault.killedProcessId>0);
  assert.equal(report.fault.fault,"real-native-certreq-termination-after-CA-observation");
  assert.equal(report.foreignRequestRefused,true);
  assert.equal(report.recoveredOwnedKey,true);
  verifyCandidateProof(report.candidateSearch);
  assert.equal(report.candidateSearch.requestIds[0],String(report.fault.requestId));
  return true;
}
module.exports={verify};
if(require.main===module){try{verify(JSON.parse(fs.readFileSync(process.argv[2],"utf8")),process.env.GITHUB_SHA);console.log("Real response-loss experiment passed; remains excluded from release qualification");}catch(error){console.error(error.message);process.exitCode=1;}}
