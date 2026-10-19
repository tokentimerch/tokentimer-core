/**
 * Regression coverage: standalone verifier accepts only complete scoped feasibility.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const {test}=require("node:test");
const assert=require("node:assert/strict");
const {verify,required}=require("./certops-standalone-report");
const sha="a".repeat(40);
function report(){return{scope:"standalone-native-certreq-cng-smoke",caType:"StandaloneRootCA",candidateSha:sha,experimental:true,qualified:false,status:"passed",cleanup:"completed",cleanupErrors:[],identity:"disposable\\operator",host:{measurement:"native",version:"10.0.20348",build:"20348"},scenarios:[...required],sourceSha256:"b".repeat(64)};}
test("standalone verifier accepts only complete scoped feasibility",()=>assert.deepEqual(verify(report(),{candidateSha:sha,sourceDigest:"b".repeat(64)}),[]));
test("standalone verifier rejects green empty and duplicate native execution",()=>{
  for(const scenarios of [[],[required[0],required[0],required[2]],required.slice(0,2)])assert.ok(verify({...report(),scenarios},{candidateSha:sha}).length);
});
test("standalone verifier rejects cleanup failure and qualification promotion",()=>{
  for(const fields of [{cleanup:"failed"},{cleanupErrors:["owned key remains"]},{qualified:true},{experimental:false},{caType:"EnterpriseRootCA"}])assert.ok(verify({...report(),...fields},{candidateSha:sha}).length);
});
test("standalone verifier rejects stale candidate source and missing native identity",()=>{
  assert.ok(verify(report(),{candidateSha:"c".repeat(40)}).length);
  assert.ok(verify(report(),{candidateSha:sha,sourceDigest:"d".repeat(64)}).length);
  assert.ok(verify({...report(),host:{measurement:"label",version:"2022",build:"20348"}},{candidateSha:sha}).length);
});
