"use strict";
/* Portable rejection tests for response-loss experiment evidence; run with node --test. Synthetic
 * reports check the verifier only and never qualify native AD CS behavior.
 */
const {test}=require("node:test");
const assert=require("node:assert/strict");
const {verify}=require("./certops-adcs-response-loss-report");
const candidate="ab".repeat(20);
const proof=()=>({scope:"enterprise-adcs-response-loss-experimental",qualificationStatus:"not-qualified",status:"passed",candidateSha:candidate,foreignRequestRefused:true,recoveredOwnedKey:true,fault:{requestId:12,killedProcessId:123,caRequestObserved:true,ownedServiceTree:true,fault:"real-native-certreq-termination-after-CA-observation"}});
test("experimental fault evidence requires actual CA observation and owned process proof",()=>{
  assert.equal(verify(proof(),candidate),true);
  for(const field of ["caRequestObserved","ownedServiceTree"]){const report=proof();report.fault[field]=false;assert.throws(()=>verify(report,candidate));}
  const missing=proof();delete missing.fault;assert.throws(()=>verify(missing,candidate));
});
test("missed fault windows and foreign request acceptance cannot be green",()=>{
  const failed=proof();failed.status="failed";assert.throws(()=>verify(failed,candidate));
  const foreign=proof();foreign.foreignRequestRefused=false;assert.throws(()=>verify(foreign,candidate));
});
test("experimental results never promote themselves into release qualification",()=>{
  const promoted=proof();promoted.qualificationStatus="qualified";assert.throws(()=>verify(promoted,candidate));
  assert.throws(()=>verify(proof(),"cd".repeat(20)));
});
