"use strict";
const {test}=require("node:test"),assert=require("node:assert/strict");
const {classifyRemainingKey}=require("../tests/e2e/helpers/certops-adcs-validity-boundaries");
test("retained invalid keys report only bounded native reference categories",()=>{
  const containerName="tokentimer-enr-11111111-1111-4111-8111-111111111111";
  const call=(probe,requestListing)=>classifyRemainingKey({probe,requestListing,containerName});
  assert.equal(call({ok:false}),"CERTOPS_VALIDITY_KEY_PROBE_FAILED");
  assert.equal(call({ok:true,shared:false}),"CERTOPS_VALIDITY_KEY_UNREFERENCED");
  assert.equal(call({ok:true,shared:true}),"CERTOPS_VALIDITY_KEY_REQUEST_PROBE_FAILED");
  assert.equal(call({ok:true,shared:true},`private ${containerName}`),"CERTOPS_VALIDITY_KEY_REQUEST_REFERENCED");
  assert.equal(call({ok:true,shared:true},"private"),"CERTOPS_VALIDITY_KEY_OTHER_REFERENCE");
});
