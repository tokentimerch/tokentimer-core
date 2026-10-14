"use strict";
const fs=require("node:fs");
const assert=require("node:assert/strict");
function verify(report,candidate){
  assert.equal(report.scope,"enterprise-adcs-response-loss-experimental");
  assert.equal(report.qualificationStatus,"not-qualified");
  assert.equal(report.status,"passed");
  assert.match(candidate,/^[a-f0-9]{40}$/);assert.equal(report.candidateSha,candidate);
  assert.equal(report.fault?.caRequestObserved,true);assert.equal(report.fault?.ownedServiceTree,true);
  assert.ok(Number.isInteger(report.fault.requestId)&&report.fault.requestId>0);
  assert.ok(Number.isInteger(report.fault.killedProcessId)&&report.fault.killedProcessId>0);
  assert.equal(report.fault.fault,"real-native-certreq-termination-after-CA-observation");
  assert.equal(report.foreignRequestRefused,true);
  assert.equal(report.recoveredOwnedKey,true);
  return true;
}
module.exports={verify};
if(require.main===module){try{verify(JSON.parse(fs.readFileSync(process.argv[2],"utf8")),process.env.GITHUB_SHA);console.log("Real response-loss experiment passed; remains excluded from release qualification");}catch(error){console.error(error.message);process.exitCode=1;}}
