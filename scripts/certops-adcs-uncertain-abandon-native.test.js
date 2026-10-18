"use strict";
// Verifier regressions use synthetic reports, never native fault execution.
const {test}=require("node:test"),assert=require("node:assert/strict");
const h=require("./certops-adcs-uncertain-abandon-native"),fixture=require("./fixtures/certops-native-uncertain-abandon.cjs");
const {verifyMatrix}=require("./certops-release-qualification");
const slot=require("../docs/certops/qualification-suites.json").slots.find(s=>s.suite===h.SUITE);
function errors(report){return verifyMatrix([{kind:"host",suite:h.SUITE,environment:slot.environment,report}],{candidateSha:report.candidateSha,specification:{schemaVersion:1,slots:[slot]}});}
test("executed zero-request browser abandonment sidecar satisfies its exact native cell",()=>{const report=fixture.nativeReport();assert.equal(report.scenarios.length,8);assert.deepEqual(errors(report),[]);});
test("sidecar refuses missing actual stages, source, candidate, cleanup and experiments",()=>{
 for(const mutate of [p=>{p.cleanup.status="failed";},p=>{p.experimental=true;},p=>{p.candidateSha="b".repeat(40);},p=>{p.nativeUncertainAbandonIdentity.cleanupJobId=p.nativeUncertainAbandonIdentity.originalJobId;},p=>{p.scenarios=p.scenarios.filter(s=>s.id!=="adcs-real-uncertain-zero-request-owned-termination");},p=>{p.fixtureSources[0].sha256="0".repeat(64);},p=>{p.nativeUncertainAbandon.caRequestsAfterRecovery=1;}]){const p=fixture.parentReport();mutate(p);assert.throws(()=>h.createNativeReport(p,{candidateSha:"a".repeat(40)}));}
});
test("local proofs, fabricated response-loss qualification and mismatched native identities cannot qualify",()=>{
 const report=fixture.nativeReport();
 for(const mutate of [p=>{p.nativeExecutionQualified=false;},p=>{p.responseLossQualified=true;},p=>{p.native.caRequestsAtFault=1;},p=>{p.native.actualLeaseWaitMs=0;},p=>{p.browser.exactUnacceptedKeyAbsent=false;},p=>{p.identity.enrollmentId=p.identity.originalJobId;},p=>{p.identity.cleanupJobId=p.identity.recoveryJobId;},p=>{p.privateSentinel="not-public";}]){const bad=structuredClone(report);mutate(bad.nativeAdcsUncertainAbandon);assert.ok(errors(bad).length);}
 const local=require("./certops-adcs-uncertain-abandon").abandonUncertain({state:"submission_uncertain"}).proof;
 assert.ok(errors({...report,nativeAdcsUncertainAbandon:local}).length);
});
