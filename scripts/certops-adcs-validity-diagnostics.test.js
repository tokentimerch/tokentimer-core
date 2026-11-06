"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {classifyRemainingKey,classifyRequestCleanupRetry}=require("../tests/e2e/helpers/certops-adcs-validity-boundaries");
test("retained invalid keys report only bounded native reference categories",()=>{
  const containerName="tokentimer-enr-11111111-1111-4111-8111-111111111111";
  const call=(probe,requestListing)=>classifyRemainingKey({probe,requestListing,containerName});
  assert.equal(call({ok:false}),"CERTOPS_VALIDITY_KEY_PROBE_FAILED");
  assert.equal(call({ok:true,shared:false}),"CERTOPS_VALIDITY_KEY_UNREFERENCED");
  assert.equal(call({ok:true,shared:true}),"CERTOPS_VALIDITY_KEY_REQUEST_PROBE_FAILED");
  assert.equal(call({ok:true,shared:true},`private ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_CONTAINER_UNPARSED");
  assert.equal(call({ok:true,shared:true},`Key Container = ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_HASH_UNPARSED");
  assert.equal(call({ok:true,shared:true},`===== Certificate 0 =====\nCert Hash(sha1): ${"AB".repeat(20)}\nConteneur de cle = ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_MATCHED");
  assert.equal(call({ok:true,shared:true},`===== Certificate 0 =====\nHach\uFFFD cert\uFFFD (sha1)\uFFFD: ${"AB".repeat(20)}\nConteneur de cle = ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_MATCHED");
  assert.equal(call({ok:true,shared:true},"private"),"CERTOPS_VALIDITY_KEY_OTHER_REFERENCE");
});
test("cleanup retry exposes bounded results and only passes the owned container",async()=>{
  const container="tokentimer-enr-11111111-1111-4111-8111-111111111111";
  for(const [result,expected] of [[{removed:1,aborted:false},"REMOVED"],[{removed:0,aborted:false},"NO_REMOVAL"],[{removed:0,aborted:true},"ABORTED"]]){
    assert.equal(await classifyRequestCleanupRetry(container,async args=>{assert.deepEqual(args,{containerName:container});return result;}),`CERTOPS_VALIDITY_KEY_REQUEST_RETRY_${expected}`);
  }
  assert.equal(await classifyRequestCleanupRetry(container,async()=>{throw new Error("private");}),"CERTOPS_VALIDITY_KEY_REQUEST_RETRY_ERROR");
});
