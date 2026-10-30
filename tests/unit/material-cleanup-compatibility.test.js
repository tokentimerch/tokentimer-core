"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {cleanupIdentity,cleanupStoreIntent}=require("../../packages/contracts/certops/material-cleanup.cjs");
const {providerOf,validProviderVersion}=require("../../packages/contracts/certops/material-provider.cjs");
const {validateDistributionContract,hashIntent}=require("../../apps/api/services/certops/materialDistribution");
test("cleanup operation and provider are independently identified by the shared PR 460 provider contract",()=>{
  for(const intent of [{type:"vault-kv2-soft-delete"},{provider:"vault-kv2",operation:"soft-delete"}]){
    const snapshot=structuredClone(intent),hash=hashIntent(intent),adapter=cleanupStoreIntent(intent,"workspace");
    assert.equal(cleanupIdentity(intent).method,"vault-kv2-soft-delete");
    assert.equal(adapter.operation,"soft-delete");assert.equal(providerOf(adapter),"vault-kv2");
    assert.equal(validProviderVersion(providerOf(adapter),1),true);
    assert.equal(validProviderVersion(providerOf(adapter),"opaque"),false);
    assert.deepEqual(intent,snapshot);assert.equal(hashIntent(intent),hash,"Never rewrite previously approved signed intent");
  }
});
test("unknown providers, mixed discriminator meanings and missing cleanup identity fail closed",()=>{
  for(const intent of [{},{type:"vault-kv2"},{operation:"soft-delete",provider:"azure-key-vault"},{operation:"soft-delete",provider:"openbao-kv2"},{type:"vault-kv2-soft-delete",provider:"azure-key-vault"},{type:"vault-kv2-soft-delete",operation:"soft-delete",provider:"vault-kv2"}])
    assert.throws(()=>cleanupIdentity(intent),{code:"material_cleanup_intent_invalid"});
  assert.throws(()=>validateDistributionContract("materialCleanup",{}));
});
