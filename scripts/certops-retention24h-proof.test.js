"use strict";
/** Synthetic strict/composite refusal checks only; no elapsed/native execution. */
const test=require("node:test"),assert=require("node:assert/strict"),helper=require("./certops-retention24h-proof"),fixture=require("./certops-retention24h-test-fixture.cjs");
test("only complete real-day composite after independent owned cleanup yields strict named report",()=>{
 const c=fixture(),p=helper.verifyCompositeProof(c);assert.equal(helper.verifyProof(p),true);const report=helper.createQualificationReport(c);assert.equal(report.suite,helper.SUITE);assert.deepEqual(report.requiredScenarios,helper.REQUIRED_SCENARIOS);assert.equal(report.nativeRetention24h.scope,helper.SCOPE);
 const pending={...c,cleanup:"pending"};delete pending.cleanupFinishedAt;assert.equal(helper.verifyCompositeProof(pending,{requireCleanup:false}).ownedAzureCleanupVerified,false);assert.throws(()=>helper.createQualificationReport(pending));
});
test("every native retention fact and bounded identity is mandatory",()=>{
 const p=helper.verifyCompositeProof(fixture());for(const key of Object.keys(p)){const missing={...p};delete missing[key];assert.throws(()=>helper.verifyProof(missing),key);}
 for(const flag of helper.FLAGS)for(const bad of [false,1,"true",null])assert.throws(()=>helper.verifyProof({...p,[flag]:bad}),flag);
 for(const change of [{scope:"native-collector-supporting-ledger-reference-lifecycle"},{monotonicElapsedMs:86399999},{monotonicElapsedMs:90000001},{retentionHours:168},{keptSweepCount:2},{maximumSweepGapMs:3900001},{processId:0},{oldNotAfter:p.cleanupDeadline},{cleanupDeadline:p.oldNotAfter},{preDeadlineObservedAt:p.cleanupDeadline},{cleanupFinishedAt:p.startedAt},{startedAt:p.verifiedCutoverAt},{requestIds:["11","4294967296"]},{rawCngInventory:"private"}])assert.throws(()=>helper.verifyProof({...p,...change}));
 for(const field of ["requestIds","enrollmentIds","jobIds","thumbprints","containerNames","fingerprints","spkiSha256","serialNumbers"]){assert.throws(()=>helper.verifyProof({...p,[field]:[p[field][0],p[field][0]]}));assert.throws(()=>helper.verifyProof({...p,[field]:[]}));}
});
test("original task boot config and all current orchestration source custody remain bound",()=>{
 const good=fixture();for(const target of ["handoffObserved","finalObserved"]){for(const field of ["vmId","nonce","candidateSha","taskXmlSha256","configSha256","bootTime","processCreatedAt","processId"]){const bad=structuredClone(good);bad[target][field]=typeof bad[target][field]==="number"?1:"wrong";assert.throws(()=>helper.verifyCompositeProof(bad),target+field);}}
 for(const field of ["nativeCustodyVerified","trustedTlsVerified","soleAgentStoppedAndDrained","productionCutoverVerified","ledgerUnmodified","replacementCngCustodyVerified","replacementIisSniBindingVerified","currentNativeDeletionVerified","actualPredecessorCertificateAbsent","actualPredecessorKeyAbsent"]){const bad=structuredClone(good);bad.finalObserved[field]=false;assert.throws(()=>helper.verifyCompositeProof(bad),field);}
 for(const patch of [{fixtureSources:[]},{sourceCount:0},{ledgerIdentitySha256:"bad"}]){const bad=structuredClone(good);Object.assign(bad.publicPreparation,patch);assert.throws(()=>helper.verifyCompositeProof(bad));}
 const duplicate=structuredClone(good);duplicate.publicPreparation.fixtureSources[1]=duplicate.publicPreparation.fixtureSources[0];assert.throws(()=>helper.verifyCompositeProof(duplicate));
 const foreign=structuredClone(good);foreign.publicPreparation.fixtureSources[0].file="private/foreign.js";assert.throws(()=>helper.verifyCompositeProof(foreign));
});

test("actual later handoff phase is bounded by original four-hour lease and initial prepared custody",()=>{
 const good=fixture();for(const patch of [{nativeVerificationStartedAt:good.publicPreparation.startedAt},{nativeVerificationFinishedAt:"2026-10-14T04:00:00.000Z"},{nativeVerificationStartedAt:"2026-10-14T03:00:00.000Z"}]){const bad=structuredClone(good);Object.assign(bad.handoffObserved,patch);assert.throws(()=>helper.verifyCompositeProof(bad));}
 const swapped=structuredClone(good);swapped.publicPreparation.task.processId=888;assert.throws(()=>helper.verifyCompositeProof(swapped));
 const p=helper.verifyCompositeProof(good);for(const patch of [{bootTime:p.finishedAt},{processCreatedAt:p.finishedAt},{bootTime:"2026-10-13T00:00:00.000Z"}])assert.throws(()=>helper.verifyProof({...p,...patch}));
});

test('real-day native deletion interruption is mandatory and bound to the original resident result',()=>{
 const c=fixture(),h=require('../tests/e2e/helpers/certops-retention24h-interrupted');
 for(const key of Object.keys(c.residentResult.interruptedDelete)){const bad=structuredClone(c);delete bad.residentResult.interruptedDelete[key];assert.throws(()=>helper.verifyCompositeProof(bad),key);}
 const good=helper.verifyCompositeProof(c);for(const flag of h.FLAGS){const bad=structuredClone(good);bad.interruptedDelete[flag]=false;assert.throws(()=>helper.verifyProof(bad));}
 for(const patch of [{cleanupDeadline:c.publicPreparation.oldNotAfter},{productionSixHourCadenceQualified:true},{full168HourRetentionQualified:true},{monotonicElapsedBeforeCrashMs:c.residentResult.monotonicElapsedMs+1},{interruptedAt:c.publicPreparation.cleanupDeadline},{resumedAt:c.cleanupFinishedAt}]){const bad=structuredClone(good);Object.assign(bad.interruptedDelete,patch);assert.throws(()=>helper.verifyProof(bad));}
 const missing=structuredClone(c);delete missing.residentResult.interruptedDelete;assert.throws(()=>helper.verifyCompositeProof(missing));
 const foreign=structuredClone(c);foreign.finalObserved.residentResult=structuredClone(c.residentResult);foreign.finalObserved.residentResult.interruptedDelete.resumedAt=c.cleanupFinishedAt;assert.throws(()=>helper.verifyCompositeProof(foreign));
});
