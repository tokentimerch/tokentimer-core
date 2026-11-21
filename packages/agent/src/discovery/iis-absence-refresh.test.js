"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { runIisAbsenceProofRefresh } = require("../index");
const thumb="aa".repeat(20);
const item = { locationKind:"iis_binding",siteName:"Default Web Site",port:443,boundAddress:"192.0.2.10",thumbprint:thumb,fingerprintSha256:"b".repeat(64) };
const snapshot = { iis:[{site:item.siteName,address:item.boundAddress,port:443,hostname:"",flags:0}],http:[{keyedBy:"ipport",ipPort:"192.0.2.10:443",thumbprint:thumb,storeName:"My"}],certificates:[{thumbprint:thumb,fingerprintSha256:item.fingerprintSha256,hasPrivateKey:true}] };
test("proof refresh sends only a distinct proof and never replays certificate observation", async () => {
  const sent=[]; const client={reportIisAbsenceProof:async p=>sent.push(p),reportEvidence:async()=>assert.fail("must not update inventory")};
  assert.deepEqual(await runIisAbsenceProofRefresh({client,candidates:[item],read:async()=>snapshot}),{proofs:1});
  assert.equal(sent.length,1); assert.equal(sent[0][0].fingerprintSha256,item.fingerprintSha256);
  assert.equal(sent[0][0].site,item.siteName); assert.equal(sent[0][0].address,item.boundAddress);
  assert.match(sent[0][0].evidenceId,/^[0-9a-f-]{36}$/);
});
test("proof refresh rejects changed native topology, cancellation and overlarge candidate sets", async () => {
  let count=0; const client={reportIisAbsenceProof:async()=>count++};
  const wildcard={...snapshot,http:[...snapshot.http,{keyedBy:"ipport",ipPort:"0.0.0.0:443",thumbprint:thumb}]};
  assert.deepEqual(await runIisAbsenceProofRefresh({client,candidates:[item],read:async()=>wildcard}),{proofs:0});
  assert.deepEqual(await runIisAbsenceProofRefresh({client,candidates:Array(65).fill(item),read:async()=>assert.fail("bounded")}),{proofs:0,incomplete:true});
  const signal=AbortSignal.abort();
  assert.deepEqual(await runIisAbsenceProofRefresh({client,candidates:[item],signal,read:async()=>snapshot}),{proofs:0,incomplete:true});
  assert.equal(count,0);
});

test("proof refresh rejects rotated certificate material and a missing private key", async () => {
  const client={reportIisAbsenceProof:async()=>assert.fail("must not report")};
  for (const certificates of [[], [{...snapshot.certificates[0],hasPrivateKey:false}], [{...snapshot.certificates[0],fingerprintSha256:"c".repeat(64)}]]) {
    assert.deepEqual(await runIisAbsenceProofRefresh({client,candidates:[item],read:async()=>({...snapshot,certificates})}),{proofs:0});
  }
});
