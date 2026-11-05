"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {classifyRemainingKey}=require("../tests/e2e/helpers/certops-adcs-validity-boundaries");
test("retained invalid keys report only bounded native reference categories",()=>{
  const containerName="tokentimer-enr-11111111-1111-4111-8111-111111111111";
  const call=(probe,requestListing)=>classifyRemainingKey({probe,requestListing,containerName});
  assert.equal(call({ok:false}),"CERTOPS_VALIDITY_KEY_PROBE_FAILED");
  assert.equal(call({ok:true,shared:false}),"CERTOPS_VALIDITY_KEY_UNREFERENCED");
  assert.equal(call({ok:true,shared:true}),"CERTOPS_VALIDITY_KEY_REQUEST_PROBE_FAILED");
  assert.equal(call({ok:true,shared:true},`private ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_CONTAINER_UNPARSED");
  assert.equal(call({ok:true,shared:true},`Key Container = ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_HASH_UNPARSED");
  assert.equal(call({ok:true,shared:true},`===== Certificate 0 =====\nCert Hash(sha1): ${"AB".repeat(20)}\nConteneur de cle = ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_MATCHED");
  assert.equal(call({ok:true,shared:true},"private"),"CERTOPS_VALIDITY_KEY_OTHER_REFERENCE");
});
