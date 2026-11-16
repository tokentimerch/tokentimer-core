"use strict";
const { test, after }=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto");
assert.equal(process.env.DB_HOST,"127.0.0.1");
assert.match(process.env.DB_NAME || "",/^distribution_lifecycle_[a-f0-9]+_test$/);
const {pool}=require("../../apps/api/db/database");
const {migrations,runMigrations}=require("../../apps/api/migrations/migrate");
after(()=>pool.end());
test("upgrade preserves accepted PagerDuty triggers and verifies historical destinations before recovery",async()=>{
  const index=migrations.findIndex(entry=>entry.version===114);
  assert.notEqual(index,-1);
  const pending=migrations.splice(index,1);
  try {
    await runMigrations();
    const f=await require("../helpers/distribution-lifecycle-fixture.cjs").fixture();
    const incident=(await pool.query(`INSERT INTO certops_distribution_incidents(workspace_id,group_id,code,dedupe_key,severity)
      VALUES($1,$2,'required_consumer_offline',$3,'critical') RETURNING id`,[f.workspaceId,f.groupId,crypto.randomUUID()])).rows[0];
    const queued=(await pool.query(`INSERT INTO alert_queue(user_id,certops_agent_id,alert_key,threshold_days,due_date,channels,status,metadata)
      VALUES($1,$2,$3,0,CURRENT_DATE,'["webhooks"]','sent',$4::jsonb) RETURNING id`,[f.actor,f.consumer,
      `cert_distribution:${incident.id}:opened`,JSON.stringify({incidentId:incident.id,transition:"opened"})])).rows[0];
    const insert=async(status,metadata)=>pool.query(`INSERT INTO alert_delivery_log(alert_queue_id,user_id,workspace_id,channel,status,metadata)
      VALUES($1,$2,$3,'webhooks',$4,$5::jsonb)`,[queued.id,f.actor,f.workspaceId,status,JSON.stringify(metadata)]);
    await insert("success",{kind:"pagerduty",destination_id:"a".repeat(64)});
    await insert("success",{kind:"pagerduty",destination_id:"a".repeat(64)});
    await insert("failed",{kind:"pagerduty",destination_id:"b".repeat(64)});
    await insert("success",{kind:"pagerduty",urlHash:"c".repeat(64)});
    const hook={kind:'pagerduty',url:'https://events.pagerduty.com/v2/enqueue',routingKey:'a'.repeat(32)};
    const {pagerDutyDestinationId}=await import('../../apps/worker/src/shared/webhookDestinations.js');
    const exact=pagerDutyDestinationId(f.workspaceId,hook);
    await insert('success',{kind:'pagerduty',urlHash:exact});
    const oldIncident=(await pool.query(`INSERT INTO certops_distribution_incidents(workspace_id,group_id,code,dedupe_key,severity,resolved_at)
      VALUES($1,$2,'required_consumer_offline',$3,'critical',clock_timestamp()) RETURNING id`,[f.workspaceId,f.groupId,crypto.randomUUID()])).rows[0];
    for(const transition of ["opened","resolved"]){
      const q=(await pool.query(`INSERT INTO alert_queue(user_id,certops_agent_id,alert_key,threshold_days,due_date,channels,status,metadata)
        VALUES($1,$2,$3,0,CURRENT_DATE,'["webhooks"]','sent',$4::jsonb) RETURNING id`,[f.actor,f.consumer,`cert_distribution:${oldIncident.id}:${transition}`,JSON.stringify({incidentId:oldIncident.id,transition})])).rows[0];
      await pool.query(`INSERT INTO alert_delivery_log(alert_queue_id,user_id,workspace_id,channel,status,metadata)
        VALUES($1,$2,$3,'webhooks','success',$4::jsonb)`,[q.id,f.actor,f.workspaceId,JSON.stringify({kind:"pagerduty",urlHash:exact})]);
    }
    const before=(await pool.query("SELECT * FROM alert_delivery_log WHERE alert_queue_id=$1 ORDER BY id",[queued.id])).rows;
    migrations.push(...pending);await runMigrations();
    const records=(await pool.query("SELECT destination_id,trigger_accepted_at,trigger_delivery_uncertain,last_error FROM certops_distribution_pagerduty WHERE incident_id=$1",[incident.id])).rows;
    assert.equal(records.length,3);
    assert.equal(records.find(row=>row.destination_id==="a".repeat(64)).trigger_delivery_uncertain,false);
    for(const id of ["c".repeat(64),exact]){const candidate=records.find(row=>row.destination_id===id);
      assert.ok(candidate.trigger_accepted_at);assert.equal(candidate.trigger_delivery_uncertain,true);assert.equal(candidate.last_error,"historical_destination_unverified");}
    await pool.query(`INSERT INTO workspace_settings(workspace_id,webhook_urls) VALUES($1,$2::jsonb)
      ON CONFLICT(workspace_id) DO UPDATE SET webhook_urls=EXCLUDED.webhook_urls`,[f.workspaceId,JSON.stringify([hook])]);
    const lifecycle=require("../../apps/api/services/certops/distributionLifecycle"),policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.alerts.enabled=true;
    await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
    await pool.query("UPDATE workspace_settings SET webhooks_alerts_enabled=true WHERE workspace_id=$1",[f.workspaceId]);
    assert.ok((await pool.query("SELECT historical_resolution_at FROM certops_distribution_pagerduty WHERE incident_id=$1",[oldIncident.id])).rows[0].historical_resolution_at);
    await pool.query("UPDATE certops_distribution_incidents SET resolved_at=clock_timestamp() WHERE id=$1",[incident.id]);
    const service=await import('../../apps/worker/src/shared/distributionPagerDuty.js'),sent=[];
    const client=await pool.connect();
    try {await service.reconcileDistributionPagerDuty(client,{send:async(_url,payload)=>{sent.push(payload);return {success:true};}});} finally {client.release();}
    assert.equal(sent.length,1);assert.equal(sent[0].event_action,"resolve");assert.equal(sent[0].routing_key,hook.routingKey);
    const after=(await pool.query("SELECT destination_id,resolved_at,trigger_delivery_uncertain FROM certops_distribution_pagerduty WHERE incident_id=$1",[incident.id])).rows;
    assert.ok(after.find(row=>row.destination_id===exact).resolved_at);
    assert.ok((await pool.query("SELECT resolved_at FROM certops_distribution_pagerduty WHERE incident_id=$1",[oldIncident.id])).rows[0].resolved_at);
    assert.equal(after.find(row=>row.destination_id==="c".repeat(64)).resolved_at,null);
    assert.deepEqual((await pool.query("SELECT * FROM alert_delivery_log WHERE alert_queue_id=$1 ORDER BY id",[queued.id])).rows,before);
  } finally {
    if(!migrations.some(entry=>entry.version===114))migrations.push(...pending);
  }
});
