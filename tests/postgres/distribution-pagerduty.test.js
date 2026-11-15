"use strict";
const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^distribution_lifecycle_[a-f0-9]+_test$/);
const { pool } = require("../../apps/api/db/database");
const { fixture } = require("../helpers/distribution-lifecycle-fixture.cjs");
const lifecycle = require("../../apps/api/services/certops/distributionLifecycle");
let workerPool;
after(async () => { await pool.end(); if(workerPool) await workerPool.end(); });

test("worker resolves the integration that received the distribution trigger", async () => {
  const f = await fixture();
  const a = { name:"original",kind:"pagerduty",url:"https://events.pagerduty.com/v2/enqueue",routingKey:"a".repeat(32) };
  const b = { ...a,name:"replacement",routingKey:"b".repeat(32) };
  const groups = [{id:"original",name:"Original",webhook_names:["original"]},{id:"replacement",name:"Replacement",webhook_names:["replacement"]}];
  await pool.query(`INSERT INTO workspace_settings(workspace_id,webhook_urls,contact_groups)
    VALUES($1,$2::jsonb,$3::jsonb) ON CONFLICT(workspace_id) DO UPDATE
    SET webhook_urls=EXCLUDED.webhook_urls,contact_groups=EXCLUDED.contact_groups`,
  [f.workspaceId,JSON.stringify([a,b]),JSON.stringify(groups)]);
  const policy=structuredClone(lifecycle.DEFAULT_POLICY);
  policy.alerts.enabled=true;policy.alerts.contactGroupIds=["original"];
  await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
  const incident=(await pool.query(`INSERT INTO certops_distribution_incidents(workspace_id,group_id,code,dedupe_key,severity)
    VALUES($1,$2,'required_consumer_offline',$3,'critical') RETURNING id`,[f.workspaceId,f.groupId,crypto.randomUUID()])).rows[0];
  const queue=async transition=>pool.query(`INSERT INTO alert_queue(user_id,certops_agent_id,alert_key,threshold_days,due_date,channels,status,metadata)
    VALUES($1,$2,$3,0,CURRENT_DATE,'["webhooks"]','pending',$4::jsonb)`,
  [f.actor,f.consumer,`cert_distribution:${incident.id}:${transition}`,JSON.stringify({incidentId:incident.id,groupId:f.groupId,transition})]);
  await queue("opened");
  const worker=await import("../../apps/worker/src/delivery-worker.js");
  workerPool=(await import("../../apps/worker/src/db.js")).pool;
  const sent=[];
  const send=async(url,payload,kind)=>{sent.push({url,payload,kind});return {success:true,status:202};};
  await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
  assert.equal(sent.length,1);assert.equal(sent[0].payload.routing_key,a.routingKey);
  await lifecycle.putPolicy({...f,policy:{...policy,alerts:{...policy.alerts,contactGroupIds:["replacement"]}},expectedRevision:1,actorUserId:f.actor});
  await pool.query("UPDATE certops_distribution_incidents SET resolved_at=clock_timestamp() WHERE id=$1",[incident.id]);
  await queue("resolved");
  await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
  assert.equal(sent.length,2);
  assert.equal(sent[1].payload.event_action,"resolve");
  assert.equal(sent[1].payload.routing_key,a.routingKey);
  assert.equal(sent[1].payload.dedup_key,sent[0].payload.dedup_key);
});

test("uncertain trigger acceptance never manufactures a recovery", async () => {
  const f=await fixture();
  const incident=(await pool.query(`INSERT INTO certops_distribution_incidents(workspace_id,group_id,code,dedupe_key,severity)
    VALUES($1,$2,'required_consumer_offline',$3,'critical') RETURNING id`,[f.workspaceId,f.groupId,crypto.randomUUID()])).rows[0];
  const hook={name:"original",kind:"pagerduty",url:"https://events.pagerduty.com/v2/enqueue",routingKey:"a".repeat(32)};
  const service=await import("../../apps/worker/src/shared/distributionPagerDuty.js");
  const client=await pool.connect(),sent=[];
  const send=async(_url,payload)=>{sent.push(payload);return {success:false};};
  try {
    await service.deliverDistributionPagerDutyTrigger(client,{alert:{workspace_id:f.workspaceId,distributionContext:{incidentId:incident.id}},webhook:hook,
      payload:{event_action:"trigger",routing_key:hook.routingKey,dedup_key:`distribution:${incident.id}`},send});
    await pool.query("UPDATE certops_distribution_incidents SET resolved_at=clock_timestamp() WHERE id=$1",[incident.id]);
    const skipped=await service.deliverDistributionPagerDutyTrigger(client,{alert:{workspace_id:f.workspaceId,distributionContext:{incidentId:incident.id}},webhook:hook,
      payload:{event_action:"trigger",routing_key:hook.routingKey,dedup_key:`distribution:${incident.id}`},send});
    assert.equal(skipped.skipped,true);
    await service.reconcileDistributionPagerDuty(client,{send});
    assert.equal(sent.length,1);
    const row=(await pool.query("SELECT trigger_accepted_at,trigger_delivery_uncertain,resolved_at FROM certops_distribution_pagerduty WHERE incident_id=$1",[incident.id])).rows[0];
    assert.equal(row.trigger_accepted_at,null);assert.equal(row.trigger_delivery_uncertain,true);assert.equal(row.resolved_at,null);
  } finally { client.release(); }
});

test("migration backfills only exact accepted distribution trigger destinations", async () => {
  const f=await fixture(),destination="a".repeat(64);
  const incident=(await pool.query(`INSERT INTO certops_distribution_incidents(workspace_id,group_id,code,dedupe_key,severity)
    VALUES($1,$2,'required_consumer_offline',$3,'critical') RETURNING id`,[f.workspaceId,f.groupId,crypto.randomUUID()])).rows[0];
  const queue=(await pool.query(`INSERT INTO alert_queue(user_id,certops_agent_id,alert_key,threshold_days,due_date,channels,status,metadata)
    VALUES($1,$2,$3,0,CURRENT_DATE,'["webhooks"]','sent',$4::jsonb) RETURNING id`,[f.actor,f.consumer,
    `cert_distribution:${incident.id}:opened`,JSON.stringify({incidentId:incident.id,transition:"opened"})])).rows[0];
  await pool.query(`INSERT INTO alert_delivery_log(alert_queue_id,user_id,workspace_id,channel,status,metadata)
    VALUES($1,$2,$3,'webhooks','success',$4::jsonb)`,[queue.id,f.actor,f.workspaceId,JSON.stringify({kind:"pagerduty",destination_id:destination})]);
  const sql=require("node:fs").readFileSync(require("node:path").join(__dirname,"../../apps/api/migrations/114-distribution-pagerduty-recovery.sql"),"utf8");
  await pool.query(sql.slice(sql.indexOf("INSERT INTO certops_distribution_pagerduty")));
  const rows=(await pool.query("SELECT destination_id,trigger_accepted_at FROM certops_distribution_pagerduty WHERE workspace_id=$1 AND incident_id=$2",[f.workspaceId,incident.id])).rows;
  assert.equal(rows.length,1);assert.equal(rows[0].destination_id,destination);assert.ok(rows[0].trigger_accepted_at);
});
