"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {retentionReasons}=require("../../apps/api/services/certops/distributionAdministration");
const {serviceKey}=require("../../apps/api/services/certops/consumerDiscovery");
const {CONNECTORS}=require("../../packages/contracts/certops/service-connectors.cjs");
const {DEFAULT_POLICY}=require("../../apps/api/services/certops/distributionLifecycle");
const now=Date.now(),policy=DEFAULT_POLICY.retention;
test("retention eligibility protects each consumer/job/approval/recovery reference independently",()=>{
  const version={id:"old",state:"published",published_at:new Date(now-100*86400000)};
  assert.deepEqual(retentionReasons(version,{rank:4,policy,now,references:new Map(),latestId:"new"}),[]);
  for(const reason of ["desired_consumer_version","observed_consumer_version","resumable_rollout","uncertain_or_reconcilable_deployment","job_or_pending_approval"])
    assert.ok(retentionReasons(version,{rank:4,policy,now,references:new Map([["old",[reason]]]),latestId:"new"}).includes(reason));
  assert.ok(retentionReasons(version,{rank:1,policy,now,references:new Map(),latestId:"old"}).includes("minimum_version_count"));
});
test("service identity survives fingerprint rotation and store-only inventory is not a consuming service",()=>{
  const base={agentRowId:"agent",targetHost:"web",locationKind:"iis_binding",locationSlot:"site1:443",fingerprintSha256:"old"};
  assert.equal(serviceKey(base),serviceKey({...base,fingerprintSha256:"new"}));
  assert.notEqual(serviceKey(base),serviceKey({...base,locationSlot:"site2:443"}));
  assert.equal(serviceKey({...base,locationKind:"windows_store"}),null);
});
test("connectors expose bounded typed actions without advertising unmerged Windows execution",()=>{
  assert.deepEqual(CONNECTORS.find(value=>value.available).activationMethods,["none","reload"]);
  assert.equal(CONNECTORS.find(value=>value.id==="windows-material-iis-v1").available,false);
  assert.ok(!JSON.stringify(CONNECTORS).includes("shell"));
});
test("lifecycle public schema accepts manual defaults and rejects credentials or unapproved cleanup",()=>{
  const Ajv=require("ajv"),addFormats=require("ajv-formats"),ajv=new Ajv({strict:false});addFormats(ajv);
  const schema=require("../../packages/contracts/certops/distribution-lifecycle.schema.json");ajv.addSchema(schema);
  const valid=ajv.compile({$ref:`${schema.$id}#/definitions/policyRequest`});
  assert.equal(valid({policy:structuredClone(DEFAULT_POLICY),expectedRevision:0}),true);
  assert.equal(valid({policy:{...structuredClone(DEFAULT_POLICY),token:"secret"},expectedRevision:0}),false);
  const policy=structuredClone(DEFAULT_POLICY);policy.retention.requiresApproval=false;
  assert.equal(valid({policy,expectedRevision:0}),false);
});
test("cleanup contracts permit only one exact Vault version and exclude credentials, purge and unapproved deletion",()=>{
  const {validate}=require("../../packages/contracts/certops/validate-material-distribution.cjs"),{randomUUID}=require("node:crypto");
  const value={type:"vault-kv2-soft-delete",cleanupId:randomUUID(),groupId:randomUUID(),managementPeriodId:randomUUID(),materialVersionId:randomUUID(),materialStoreRef:"customer",profileRevision:1,providerVersion:1,
    policyRevision:1,scopeHash:"a".repeat(64),expiresAt:new Date(Date.now()+3600000).toISOString(),retentionPolicy:{minimumSeconds:0,minimumVersions:2,rollbackSeconds:0,cleanupEnabled:true,reportOnly:false,requiresApproval:true}};
  assert.equal(validate("materialCleanup",value),true);
  for(const change of [{type:"azure-purge"},{providerVersion:[1,2]},{providerVersion:0},{tokenFile:"forbidden"},{privateKeyPem:"forbidden"},{retentionPolicy:{...value.retentionPolicy,requiresApproval:false}},{retentionPolicy:{...value.retentionPolicy,reportOnly:true}}])assert.equal(validate("materialCleanup",{...value,...change}),false);
});
