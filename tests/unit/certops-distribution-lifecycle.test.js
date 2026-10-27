"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {DEFAULT_POLICY,validatePolicy,approvalMatches} = require("../../apps/api/services/certops/distributionLifecycle");
const {computeJobPayloadApprovalHash} = require("../../apps/api/services/certops/jobApprovals");

test("existing installations default to manual, verification disabled, retention report-only",()=>{
  const policy=validatePolicy(structuredClone(DEFAULT_POLICY));
  assert.equal(policy.mode,"manual"); assert.equal(policy.verification.enabled,false);
  assert.equal(policy.retention.cleanupEnabled,false); assert.equal(policy.retention.reportOnly,true);
  policy.verification.enabled=true; assert.equal(DEFAULT_POLICY.verification.enabled,false);
});
test("lifecycle policy rejects unknown inputs, credentials, destructive cleanup and unbounded authority",()=>{
  for (const change of [p=>p.token="bearer-value",p=>p.maxParallel=17,p=>p.verification.intervalSeconds=0,
    p=>p.retention.cleanupEnabled=true,p=>p.retention.reportOnly=false,p=>p.mode="automatic",
    p=>{p.mode="preauthorized";},p=>{p.authorizationExpiresAt=new Date(Date.now()+31*86400000).toISOString();}]) {
    const policy=structuredClone(DEFAULT_POLICY);change(policy);assert.throws(()=>validatePolicy(policy));
  }
});
test("standing policy authority requires a genuine exact, nonexpired approval and matching revision",()=>{
  const expiresAt=new Date(Date.now()+86400000).toISOString();
  const scope={groupId:"group",bindings:[{bindingId:"consumer",activationClass:"reload"}]};
  const policy={group_id:"group",revision:1,scope_hash:computeJobPayloadApprovalHash(scope),policy:{authorizationExpiresAt:expiresAt}};
  const job={status:"pending",approved_by_user_id:2,approved_at:new Date(),payload:{distributionPolicyApproval:{groupId:"group",revision:1,scopeHash:policy.scope_hash,scope,expiresAt}}};
  job.approved_payload_hash=computeJobPayloadApprovalHash(job.payload);
  assert.equal(approvalMatches(job,policy),true);
  for (const changed of [{...job,approved_by_user_id:null},{...job,approved_payload_hash:null},{...job,status:"cancelled"},
    {...job,payload:{distributionPolicyApproval:{...job.payload.distributionPolicyApproval,revision:2}}}]) assert.equal(approvalMatches(changed,policy),false);
  assert.equal(approvalMatches(job,{...policy,revision:2}),false);
  assert.equal(approvalMatches(job,{...policy,scope_hash:"b".repeat(64)}),false);
});
