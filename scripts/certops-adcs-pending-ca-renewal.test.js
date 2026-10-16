"use strict";
/** Pure pending/CA-renewal source/proof controls. No CA, CNG or service executes. */
const test=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),h=require("../tests/e2e/helpers/certops-adcs-pending-ca-renewal");
function proof(){return{scope:h.SCOPE,schedulerClock:"supported-scheduler-now-input",backgroundWorkerIntervalQualified:false,enrollmentId:"11111111-1111-1111-1111-111111111111",originalJobId:"22222222-2222-2222-2222-222222222222",continuationJobId:"33333333-3333-3333-3333-333333333333",requestId:"17",caKeySha256:"a".repeat(64),caCertificateCountBefore:1,caCertificateCountAfter:2,csrSha256:"b".repeat(64),spkiSha256:"c".repeat(64),leafFingerprint:"d".repeat(64),predecessorFingerprint:"e".repeat(64),...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};}
test("pending CA renewal proof requires actual pending continuity and cannot promote scheduler scope",()=>{
 assert.equal(h.verifyProof(proof()),true);
 for(const key of Object.keys(proof())){const missing=proof();delete missing[key];assert.throws(()=>h.verifyProof(missing));const wrong=proof();wrong[key]=typeof wrong[key]==="boolean"?!wrong[key]:"invalid";assert.throws(()=>h.verifyProof(wrong));}
 for(const patch of [{requestId:"4294967296"},{caCertificateCountBefore:true},{caCertificateCountAfter:1},{caCertificateCountAfter:17},{leafFingerprint:proof().predecessorFingerprint},{continuationJobId:proof().originalJobId},{schedulerClock:"default-real-now"},{backgroundWorkerIntervalQualified:true},{rawReceipt:"private"}])assert.throws(()=>h.verifyProof({...proof(),...patch}));
});
test("pending CSR/key/native request exist before sole real CA renewal and exact same-request approval",()=>{
 const source=fs.readFileSync(path.resolve(__dirname,"../tests/e2e/helpers/certops-adcs-pending-ca-renewal.js"),"utf8");
 const guard=source.indexOf("receipt.pendingCaRenewalUnresolved=true"),create=source.indexOf('fixture.request(`${api}/enrollments`'),pending=source.indexOf('original.journal.state,"pending"'),renew=source.indexOf("await renewCaAndObserve()"),approve=source.indexOf('"-Action","approve"'),finish=source.indexOf("receipt.pendingCaRenewalUnresolved=false");
 assert.ok(guard<create&&create<pending&&pending<renew&&renew<approve&&approve<finish);assert.equal(source.match(/await renewCaAndObserve\(\)/g).length,1);
 for(const token of ["Current served leaf must match one actual installed owned journal","signPending()","crypto.verify(",'record.jobId,originalJobId',"e.claim_id=j.claim_id",'receipt.enrollmentIds.push(id)',"nativeSamePendingKeyAndLeaf"]){assert.ok(source.includes(token),token);}
 assert.doesNotMatch(source,/issuer[s]?\/.*confirm|writeEnrollmentJournal|UPDATE certificate_|ownedThumbprints\.add|clock.*injected/i);
 for(const file of h.REQUIRED_SOURCES)assert.ok(fs.statSync(path.resolve(__dirname,"..",file)).isFile(),file);
});

test("pending CA guard precedes every broad native deletion and durable-state cleanup",()=>{
 const source=fs.readFileSync(path.resolve(__dirname,"../tests/e2e/certops-adcs-real-e2e.test.js"),"utf8");
 assert.ok(source.includes('nativeCleanupGuard.run(()=>{assertPendingCaResolved();return action();})'));
 assert.ok(source.includes('for(const ownedBinding of ownedNativeBindings)await clean(async()=>{assertPendingCaResolved();'));
 assert.ok(source.includes('for (const site of ownedSites) await clean(async()=>{assertPendingCaResolved();'));
 assert.ok(source.includes('const assertNativeStateReleased=()=>{assertPendingCaResolved();'));
 assert.ok(source.includes('assertPendingCaResolved();fs.rmSync(workDir'));
 assert.ok(source.includes('await cleanNative(()=>webHostingJourney.cleanupCapacity('));
 assert.ok(source.includes('...pendingCaJourney.REQUIRED_SCENARIOS,'));
});
