"use strict";
/** Synthetic cross-stage adversaries. Native-only facts never establish the
 * independently owned CA counters or control-plane scheduler isolation. */
const test=require("node:test"),assert=require("node:assert/strict"),h=require("./certops-adcs-ttl24h-proof"),{fixture}=require("./fixtures/certops-adcs-ttl24h-proof.cjs");
function pending(){const f=fixture(),value=Object.fromEntries(Object.entries(f.proof).filter(([key])=>!h.EXTERNAL_FIELDS.includes(key)));return {...f,value};}
test("native stage cannot promote itself into independent CA or scheduler evidence",()=>{
 const f=pending();assert.equal(h.verifyNativeFacts(f.value,f.prepared,f.observed),true);assert.throws(()=>h.verifyProof(f.value));
 for(const key of h.EXTERNAL_FIELDS){assert.throws(()=>h.verifyNativeFacts({...f.value,[key]:f.proof[key]},f.prepared,f.observed));}
 assert.equal(h.verifyAgainstPrepared({...f.value,...Object.fromEntries(h.EXTERNAL_FIELDS.map(key=>[key,f.proof[key]]))},f.prepared,f.observed),true);
 for(const patch of [{caRequestCounts:[0,1,2,2]},{noBackgroundSchedulerDuringResident:false},{originalCaRequestNotResubmitted:false}])assert.throws(()=>h.verifyAgainstPrepared({...f.proof,...patch},f.prepared,f.observed));
});
test("each pending native field is mandatory and private or controller-only extras refuse",()=>{
 const f=pending();assert.deepEqual(Object.keys(f.value).sort(),[...h.NATIVE_FACT_FIELDS].sort());
 for(const field of h.NATIVE_FACT_FIELDS){const bad=structuredClone(f.value);delete bad[field];assert.throws(()=>h.verifyNativeFacts(bad,f.prepared,f.observed),field);}
 for(const flag of h.FLAGS.filter(key=>!h.EXTERNAL_FIELDS.includes(key)))assert.throws(()=>h.verifyNativeFacts({...f.value,[flag]:false},f.prepared,f.observed),flag);
 for(const key of ["privateCredential","nativeRawCngIdentity","residentTiming","caRequestCounts"])assert.throws(()=>h.verifyNativeFacts({...f.value,[key]:"must-not-qualify"},f.prepared,f.observed));
});
test("well-formed native-stage context replacement cannot cross authenticated originals",()=>{
 const f=pending(),other="1".repeat(64);
 const patches=[{candidateSha:"f".repeat(40)},{prepareRunId:"999"},{prepareRunAttempt:"9"},{nonce:other},{nodeSha256:other},{keeperSha256:other},{preparedSha256:other},{snapshotSha256:other},{processId:9876},{taskXmlSha256:other},{requestIds:["99",...f.value.requestIds.slice(1)]},{fingerprints:[other,...f.value.fingerprints.slice(1)]},{spkiFingerprints:[other,...f.value.spkiFingerprints.slice(1)]}];
 for(const patch of patches)assert.throws(()=>h.verifyNativeFacts({...f.value,...patch},f.prepared,f.observed),Object.keys(patch)[0]);
});

test("only internal pending fresh RequestId may await an independent CA observation", () => {
 const f=pending(), value={...f.value,requestIds:[...f.value.requestIds.slice(0,2),null]};
 assert.equal(h.verifyNativeFacts(value,f.prepared,f.observed),true);
 assert.throws(()=>h.verifyAgainstPrepared({...f.proof,requestIds:value.requestIds},f.prepared,f.observed));
 for(const index of [0,1]) { const bad=structuredClone(value);bad.requestIds[index]=null;assert.throws(()=>h.verifyNativeFacts(bad,f.prepared,f.observed)); }
 for(const id of [undefined,"",0,"0","4294967296"]) { const bad=structuredClone(value);bad.requestIds[2]=id;assert.throws(()=>h.verifyNativeFacts(bad,f.prepared,f.observed)); }
});
