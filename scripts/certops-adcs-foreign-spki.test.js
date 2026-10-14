"use strict";
/** Offline foreign-SPKI contract checks; native CA execution remains protected and pending. */
const {test}=require("node:test"),assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path"),crypto=require("node:crypto");
const helper=require("../tests/e2e/helpers/certops-adcs-native-reconcile");
const {retrieveProposedEnrollmentCandidate}=require("../packages/agent/src/issuers/adcs-enrollment-reconcile");
const valid=()=>({scope:helper.foreignScope,...Object.fromEntries(helper.foreignFlags.map(flag=>[flag,true])),requestIds:["17","18"],spkiFingerprints:["a".repeat(64),"b".repeat(64)]});
test("foreign candidate proof cannot promote read-only retrieval into uncertain recovery",()=>{
 assert.equal(helper.verifyForeignProof(valid()),true);
 for(const flag of helper.foreignFlags){for(const invalid of [false,1,null,"true"])assert.throws(()=>helper.verifyForeignProof({...valid(),[flag]:invalid}));const missing=valid();delete missing[flag];assert.throws(()=>helper.verifyForeignProof(missing));}
 for(const change of [{scope:"public-uncertain-recovery"},{requestIds:["17","17"]},{requestIds:["17","4294967296"]},{requestIds:["17",18]},{spkiFingerprints:["a".repeat(64),"a".repeat(64)]},{rawKey:"private"},{installedCertificate:true}])assert.throws(()=>helper.verifyForeignProof({...valid(),...change}));
});
test("production explicit candidate check with a public fixture leaf refuses another CSR key",async()=>{
 const pem=fs.readFileSync(path.resolve(__dirname,"../packages/agent/src/verify/fixtures/leaf.crt.pem"),"utf8"),leaf=new crypto.X509Certificate(pem);
 const actual=crypto.createHash("sha256").update(leaf.publicKey.export({format:"der",type:"spki"})).digest("hex");
 const foreign=actual==="0".repeat(64)?"1".repeat(64):"0".repeat(64),calls=[];
 const issuer={retrieve(requestId){calls.push(requestId);return Promise.resolve({outcome:"issued",requestId,certificatePem:pem});}};
 const args={issuer,requestId:18,reconcileSearchFrom:17,assertIssuanceOutcome:value=>value};
 const control=await retrieveProposedEnrollmentCandidate({...args,csrSpkiSha256:actual});assert.equal(control.status,"unique_candidate");assert.equal(control.attachmentEligible,true);
 const refused=await retrieveProposedEnrollmentCandidate({...args,csrSpkiSha256:foreign});assert.equal(refused.status,"error");assert.equal(refused.error,"Proposed RequestId certificate SPKI does not match this enrollment");assert.equal(refused.certificatePem,undefined);assert.equal(refused.requestId,undefined);assert.deepEqual(calls,[18,18]);
});
