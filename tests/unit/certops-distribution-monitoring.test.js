"use strict";
const test=require("node:test"),assert=require("node:assert/strict");
const {consumerHealth,consumerConditions,verificationFailureCounts,consumerVerificationFailureCount}=require("../../apps/api/services/certops/distributionMonitoring");
const {DEFAULT_POLICY}=require("../../apps/api/services/certops/distributionLifecycle");
const now=Date.now();
const row={binding_state:"active",agent_status:"active",agent_last_seen_at:new Date(now),required:true,converged:true,
  desired_material_version_id:"new",observed_material_version_id:"new",desired_fingerprint_sha256:"a",observed_fingerprint_sha256:"a",
  observed_valid_to:new Date(now+5*86400000),observed_at:new Date(now),freshness_seconds:3600,verification_policy:"served",verification_method:"served"};
test("consumer health distinguishes installation, served/trust proof, drift, stale evidence, offline agents and uncertainty",()=>{
  assert.equal(consumerHealth(row,{now}),"up_to_date_fresh");
  for(const [change,status] of [[{verification_policy:"installed"},"installed_not_proven_served"],
    [{verification_policy:"trust",converged:false},"served_trust_unknown"],[{observed_material_version_id:"old"},"old_certificate_active"],
    [{observed_fingerprint_sha256:"b"},"drift_detected"],[{observed_at:new Date(now-3600000)},"verification_overdue"],
    [{agent_status:"offline"},"agent_offline"],[{latest_deployment:{stage:"orphaned_unknown_effect"}},"uncertain_external_effects"],
    [{converged:false,verification_method:null,latest_deployment:{stage:"failed"}},"failed_verification"]])
    assert.equal(consumerHealth({...row,...change},{now}),status);
  assert.equal(consumerHealth(row,{now,latestVersionId:"renewed-source"}),"old_certificate_active");
});
test("deployed expiry is independent of source renewal and evidence freshness",()=>{
  assert.deepEqual(consumerConditions(row,DEFAULT_POLICY,now).codes,["consumer_certificate_expiring"]);
  assert.ok(consumerConditions({...row,observed_valid_to:new Date(now-1)},DEFAULT_POLICY,now).codes.includes("consumer_certificate_expired"));
});
test("a failed current verification is not hidden by older installed or served evidence",()=>{
  for(const method of ["installed","served","trust"]){
    const failed={...row,verification_policy:method,verification_method:"installed",converged:false,
      latest_deployment:{stage:"failed",jobStatus:"failed",attemptCount:1}};
    assert.equal(consumerHealth(failed,{now}),"failed_verification");
    assert.ok(consumerConditions(failed,DEFAULT_POLICY,now).codes.includes("verification_failed"));
  }
});
test("verification thresholds use only the current binding's own cycle count, never attempts or another consumer",()=>{
  const counts=new Map([["A",{failures:2,generation:5}],["B",{failures:1,generation:5}],["optional",{failures:0,generation:5}]]);
  const consumer=id=>({binding_id:id,desired_generation:5,required:id!=="optional",latest_deployment:{attemptCount:99}});
  assert.equal(consumerVerificationFailureCount(consumer("A"),counts),2);
  assert.equal(consumerVerificationFailureCount(consumer("B"),counts),1);
  assert.equal(consumerVerificationFailureCount(consumer("optional"),counts),0);
  assert.equal(consumerVerificationFailureCount(consumer("new"),counts),0);
  assert.equal(consumerVerificationFailureCount({...consumer("A"),desired_generation:6},counts),0,"Pending work or a manual deployment cannot borrow an older cycle's failures");
});
test("monitoring loads all consumer summaries with one workspace/group-scoped query",async()=>{
  let calls=0;
  const client={async query(sql,params){
    calls++;assert.deepEqual(params,["workspace","group"]);
    assert.ok(sql.includes("certops_consumer_current_state"));
    assert.ok(!sql.includes("certops_distribution_schedules"));
    assert.ok(!sql.includes("certops_consumer_verification_outcomes"),"Monitoring must not scan the outcome ledger");
    return {rows:Array.from({length:1000},(_,index)=>({id:String(index),failures:String(index%3),generation:"8",uncertain:false}))};
  }};
  const counts=await verificationFailureCounts(client,"workspace","group");
  assert.equal(calls,1);assert.equal(counts.size,1000);assert.equal(counts.get("2").failures,2);
});
test("reconciliation flags retain their uncertainty classification even when a job reports failed",()=>{
  const uncertain={...row,converged:false,latest_deployment:{stage:"failed",jobStatus:"failed",needsOperatorReconciliation:true}};
  assert.equal(consumerHealth(uncertain,{now}),"uncertain_external_effects");
  assert.ok(consumerConditions(uncertain,DEFAULT_POLICY,now).codes.includes("uncertain_effects"));
  assert.ok(!consumerConditions(uncertain,DEFAULT_POLICY,now).codes.includes("verification_failed"));
});

test("one primary health label cannot hide simultaneous offline, overdue and deployed-expiry conditions",()=>{
  const conditions=consumerConditions({...row,agent_status:"offline",observed_material_version_id:"old",
    observed_at:new Date(now-7200000),observed_valid_to:new Date(now-1)},DEFAULT_POLICY,now);
  assert.equal(conditions.health,"agent_offline");
  assert.deepEqual(new Set(conditions.codes),new Set(["required_consumer_offline","verification_overdue","consumer_certificate_expired"]));
});
test("distribution channel payloads contain stable incident correlation and explicit recovery",async()=>{
  const module=await import("../../apps/worker/src/shared/distributionAlerts.js");
  const alert={workspace_id:"11111111-1111-4111-8111-111111111111",metadata:{incidentId:"22222222-2222-4222-8222-222222222222",groupId:"33333333-3333-4333-8333-333333333333",code:"certificate_drift",transition:"resolved",severity:"warning",evidence:{desiredVersionId:"v2"}}};
  const payload=module.buildDistributionWebhookPayload("pagerduty",alert,{routingKey:"synthetic-fixture-only"});
  assert.equal(payload.event_action,"resolve");assert.equal(payload.dedup_key,`distribution:${alert.metadata.incidentId}`);
  const email=module.buildDistributionEmailContent(alert);assert.match(email.subject,/resolved/);assert.match(email.text,/certops\/distribution/);
  assert.deepEqual(Object.keys(module.distributionWhatsAppVariables(alert,"Sam")),["recipient_name","incident","evidence_url"]);
});
