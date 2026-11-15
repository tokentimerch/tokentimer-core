"use strict";
const { test, after }=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto");
assert.equal(process.env.DB_HOST,"127.0.0.1");
assert.match(process.env.DB_NAME || "",/^distribution_lifecycle_[a-f0-9]+_test$/);
const {pool}=require("../../apps/api/db/database");
const {migrations,runMigrations}=require("../../apps/api/migrations/migrate");
after(()=>pool.end());
test("upgrade preserves history and backfills only accepted exact PagerDuty triggers",async()=>{
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
    const before=(await pool.query("SELECT * FROM alert_delivery_log WHERE alert_queue_id=$1 ORDER BY id",[queued.id])).rows;
    migrations.push(...pending);await runMigrations();
    const records=(await pool.query("SELECT destination_id,trigger_accepted_at FROM certops_distribution_pagerduty WHERE incident_id=$1",[incident.id])).rows;
    assert.equal(records.length,1);assert.equal(records[0].destination_id,"a".repeat(64));assert.ok(records[0].trigger_accepted_at);
    assert.deepEqual((await pool.query("SELECT * FROM alert_delivery_log WHERE alert_queue_id=$1 ORDER BY id",[queued.id])).rows,before);
  } finally {
    if(!migrations.some(entry=>entry.version===114))migrations.push(...pending);
  }
});
