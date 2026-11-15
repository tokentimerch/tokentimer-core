"use strict";
process.env.ALERT_MAX_ATTEMPTS="2";
const {test,after}=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto");
assert.equal(process.env.DB_HOST,"127.0.0.1");
assert.match(process.env.DB_NAME||"",/^distribution_lifecycle_[a-f0-9]+_test$/);
const {pool}=require("../../apps/api/db/database"),{fixture}=require("../helpers/distribution-lifecycle-fixture.cjs");
const lifecycle=require("../../apps/api/services/certops/distributionLifecycle");
let workerPool;
after(async()=>{await pool.end();if(workerPool)await workerPool.end();});
async function setup(){
 const f=await fixture(),hook={name:"original",kind:"pagerduty",url:"https://events.pagerduty.com/v2/enqueue",routingKey:"a".repeat(32)};
 await pool.query(`INSERT INTO workspace_settings(workspace_id,webhook_urls,contact_groups) VALUES($1,$2::jsonb,$3::jsonb)
  ON CONFLICT(workspace_id) DO UPDATE SET webhook_urls=EXCLUDED.webhook_urls,contact_groups=EXCLUDED.contact_groups`,
  [f.workspaceId,JSON.stringify([hook]),JSON.stringify([{id:"original",name:"Original",webhook_names:["original"]}])]);
 const policy=structuredClone(lifecycle.DEFAULT_POLICY);policy.alerts.enabled=true;policy.alerts.contactGroupIds=["original"];
 await lifecycle.putPolicy({...f,policy,expectedRevision:0,actorUserId:f.actor});
 const incident=(await pool.query(`INSERT INTO certops_distribution_incidents(workspace_id,group_id,code,dedupe_key,severity)
  VALUES($1,$2,'required_consumer_offline',$3,'critical') RETURNING id`,[f.workspaceId,f.groupId,crypto.randomUUID()])).rows[0];
 async function queue(transition){return (await pool.query(`INSERT INTO alert_queue(user_id,certops_agent_id,alert_key,threshold_days,due_date,channels,status,metadata)
  VALUES($1,$2,$3,0,CURRENT_DATE,'["webhooks"]','pending',$4::jsonb) RETURNING id`,
  [f.actor,f.consumer,`cert_distribution:${incident.id}:${transition}`,JSON.stringify({incidentId:incident.id,groupId:f.groupId,transition})])).rows[0].id;}
 return {f,hook,incident,queue};
}
async function blocked(){
 const data=await setup(),{f,incident,queue}=data,worker=await import("../../apps/worker/src/delivery-worker.js");
 workerPool=(await import("../../apps/worker/src/db.js")).pool;let recover=false;
 const send=async(_url,payload)=>({success:payload.event_action==="trigger"||recover});
 await queue("opened");await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 await pool.query("UPDATE certops_distribution_incidents SET resolved_at=clock_timestamp() WHERE id=$1",[incident.id]);
 const id=await queue("resolved");
 for(let n=0;n<2;n++){
  await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
  await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
  await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 }
 const row=(await pool.query("SELECT * FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(row.status,"blocked");
 assert.ok((await pool.query("SELECT id FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2 AND resolved_at IS NULL",[f.workspaceId,`delivery_blocked:${id}`])).rowCount);
 return {...data,id,worker,send,allow:()=>{recover=true}};
}
test("late recovery settles the blocked queue and warning",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked();allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 const q=(await pool.query("SELECT status,channels FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"sent");
 assert.equal(q.channels.outcomes.webhooks.state,"sent");assert.deepEqual(q.channels.retry,[]);
 assert.ok((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at);
});
test("late recovery preserves other failed channels and endpoints",async()=>{
 for(const mode of ["channel","endpoint"]){
  const {f,incident,id,worker,send,allow}=await blocked();
  const original=(await pool.query("SELECT channels FROM alert_queue WHERE id=$1",[id])).rows[0].channels;
  if(mode==="channel"){
   original.required.push("email");original.retry.push("email");original.outcomes.email={state:"failed",terminal:false,reason:null,code:null};
  }else original.outcomes.webhooks.endpoints["b".repeat(64)]="failed";
  await pool.query("UPDATE alert_queue SET channels=$2::jsonb WHERE id=$1",[id,JSON.stringify(original)]);allow();
  await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
  await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
  const q=(await pool.query("SELECT status,channels FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"blocked");
  const endpoints=q.channels.outcomes.webhooks.endpoints;assert.equal(endpoints[Object.keys(original.outcomes.webhooks.endpoints)[0]],"sent");
  if(mode==="channel")assert.equal(q.channels.outcomes.email.state,"failed");
  else assert.equal(endpoints["b".repeat(64)],"failed");
  assert.equal((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at,null);
 }
});
test("a later sweep settles an alert that was claimed during recovery",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked(),claim=crypto.randomUUID();
 await pool.query("UPDATE alert_queue SET status='failed',delivery_claim_id=$2 WHERE id=$1",[id,claim]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 const service=await import("../../apps/worker/src/shared/distributionPagerDuty.js"),client=await pool.connect();
 try{await service.reconcileDistributionPagerDuty(client,{send});}finally{client.release();}
 let q=(await pool.query("SELECT status,delivery_claim_id FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"failed");assert.equal(q.delivery_claim_id,claim);
 await pool.query("UPDATE alert_queue SET status='blocked',delivery_claim_id=NULL WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"sent");
 assert.ok((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at);
});

test("all original PagerDuty destinations must recover before the warning is cleared",async()=>{
 const {f,hook,incident,id}=await blocked(),service=await import("../../apps/worker/src/shared/distributionPagerDuty.js");
 const {pagerDutyDestinationId}=await import("../../apps/worker/src/shared/webhookDestinations.js");
 const second={...hook,name:"second",routingKey:"b".repeat(32)},secondId=pagerDutyDestinationId(f.workspaceId,second);
 await pool.query("UPDATE workspace_settings SET webhook_urls=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([hook,second])]);
 await pool.query(`INSERT INTO certops_distribution_pagerduty(workspace_id,incident_id,destination_id,trigger_accepted_at)
  VALUES($1,$2,$3,clock_timestamp())`,[f.workspaceId,incident.id,secondId]);
 const ledger=(await pool.query("SELECT channels FROM alert_queue WHERE id=$1",[id])).rows[0].channels;
 ledger.outcomes.webhooks.endpoints[secondId]="pending";
 await pool.query("UPDATE alert_queue SET channels=$2::jsonb WHERE id=$1",[id,JSON.stringify(ledger)]);
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 const client=await pool.connect();
 try{
  await service.reconcileDistributionPagerDuty(client,{send:async(_url,payload)=>({success:payload.routing_key!==second.routingKey})});
  let q=(await pool.query("SELECT status,channels FROM alert_queue WHERE id=$1",[id])).rows[0];
  assert.equal(q.status,"blocked");assert.equal(q.channels.outcomes.webhooks.endpoints[secondId],"pending");
  assert.equal((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at,null);
  await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
  await service.reconcileDistributionPagerDuty(client,{send:async()=>({success:true})});
  q=(await pool.query("SELECT status,channels FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"sent");assert.equal(q.channels.outcomes.webhooks.endpoints[secondId],"sent");
  assert.ok((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at);
 }finally{client.release();}
});
test("a different blocked reason is not cleared by PagerDuty recovery",async()=>{
 const {incident,id,worker,send,allow}=await blocked();
 await pool.query("UPDATE alert_queue SET error_message='WORKSPACE_FROZEN' WHERE id=$1",[id]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 const q=(await pool.query("SELECT status,error_message FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"blocked");assert.equal(q.error_message,"WORKSPACE_FROZEN");
});


test("legacy webhook-only recovery is requeued and settled by the delivery worker",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked();
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb WHERE id=$1",[id]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 const q=(await pool.query("SELECT status,channels,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"sent");assert.equal(q.channels.version,1);assert.equal(q.metadata.pagerdutyRecoveryRequeued,true);
 assert.ok((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at);
});
test("legacy queues with other retry channels remain blocked",async()=>{
 const {incident,id,worker,send,allow}=await blocked();
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\",\"email\"]'::jsonb WHERE id=$1",[id]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 const q=(await pool.query("SELECT status,channels,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"blocked");assert.deepEqual(q.channels,["webhooks","email"]);assert.equal(q.metadata.pagerdutyRecoveryRequeued,undefined);
});
test("legacy recovery waits for the edition's workspace gate",async()=>{
 const {incident,id,worker,send}=await blocked(),service=await import("../../apps/worker/src/shared/distributionPagerDuty.js");
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb,next_attempt_at=NULL WHERE id=$1",[id]);
 await pool.query("UPDATE certops_distribution_pagerduty SET resolved_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 const client=await pool.connect();
 try{
  await service.reconcileDistributionPagerDuty(client,{send,canRecover:async()=>false});
  let q=(await pool.query("SELECT status,metadata,next_attempt_at FROM alert_queue WHERE id=$1",[id])).rows[0];
  assert.equal(q.status,"blocked");assert.equal(q.metadata.pagerdutyRecoveryRequeued,undefined);assert.ok(q.next_attempt_at);
  await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
  await service.reconcileDistributionPagerDuty(client,{send,canRecover:async()=>true});
  q=(await pool.query("SELECT status,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"pending");assert.equal(q.metadata.pagerdutyRecoveryRequeued,true);
 }finally{client.release();}
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 assert.equal((await pool.query("SELECT status FROM alert_queue WHERE id=$1",[id])).rows[0].status,"sent");
});


test("legacy recovery waits until distribution alerts are enabled",async()=>{
 const {f,incident,id,worker,send}=await blocked(),service=await import("../../apps/worker/src/shared/distributionPagerDuty.js");
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb,next_attempt_at=NULL WHERE id=$1",[id]);
 await pool.query("UPDATE certops_distribution_pagerduty SET resolved_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await pool.query("UPDATE certops_distribution_policies SET policy=jsonb_set(policy,'{alerts,enabled}','false'::jsonb) WHERE workspace_id=$1",[f.workspaceId]);
 const client=await pool.connect();
 try{
  await service.reconcileDistributionPagerDuty(client,{send});
  let q=(await pool.query("SELECT status,metadata,next_attempt_at FROM alert_queue WHERE id=$1",[id])).rows[0];
  assert.equal(q.status,"blocked");assert.equal(q.metadata.pagerdutyRecoveryRequeued,undefined);assert.ok(q.next_attempt_at);
  await pool.query("UPDATE certops_distribution_policies SET policy=jsonb_set(policy,'{alerts,enabled}','true'::jsonb) WHERE workspace_id=$1",[f.workspaceId]);
  await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
  await service.reconcileDistributionPagerDuty(client,{send});
  q=(await pool.query("SELECT status,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"pending");assert.equal(q.metadata.pagerdutyRecoveryRequeued,true);
 }finally{client.release();}
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 assert.equal((await pool.query("SELECT status FROM alert_queue WHERE id=$1",[id])).rows[0].status,"sent");
});


test("legacy recovery resumes after the original contact group is restored",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked();
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb WHERE id=$1",[id]);
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["missing"]}])]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 let q=(await pool.query("SELECT status,channels,metadata,error_message FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.notEqual(q.status,"sent"); for(let n=0;n<3;n++){await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);await worker.deliveryWorkerJob({closePool:false,webhookSender:send});}
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["original"]}])]);
 await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status,channels,metadata,error_message FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"sent");
});


test("legacy recovery waits for every named webhook to be restored",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked();
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb WHERE id=$1",[id]);
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["missing"]}])]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 let q=(await pool.query("SELECT status,channels,metadata,error_message FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.notEqual(q.status,"sent"); for(let n=0;n<3;n++){await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);await worker.deliveryWorkerJob({closePool:false,webhookSender:send});}
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["original","missing"]}])]);
 await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"blocked");
 assert.equal((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at,null);
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["original"]}])]);
 await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status,channels,metadata,error_message FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"sent");
});


test("initial legacy recovery waits for every named webhook",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked();
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb WHERE id=$1",[id]);
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["original","missing"]}])]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 let q=(await pool.query("SELECT status,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"blocked");assert.equal(q.metadata.pagerdutyRecoveryRequeued,undefined);
 assert.equal((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at,null);
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["original"]}])]);
 await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"sent");
 assert.ok((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at);
});


test("initial legacy recovery delivers other configured webhooks",async()=>{
 const {f,hook,incident,id,worker,allow}=await blocked(),events=[];
 const generic={name:"generic",kind:"generic",url:"https://example.test/hook"};
 await pool.query("UPDATE alert_queue SET channels='[\"webhooks\"]'::jsonb WHERE id=$1",[id]);
 await pool.query("UPDATE workspace_settings SET contact_groups=$2::jsonb,webhook_urls=$3::jsonb WHERE workspace_id=$1",[f.workspaceId,JSON.stringify([{id:"original",name:"Original",webhook_names:["original","generic"]}]),JSON.stringify([hook,generic])]);allow();
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:async(url,payload,kind)=>{events.push({url,kind});return {success:true};}});
 assert.equal((await pool.query("SELECT status FROM alert_queue WHERE id=$1",[id])).rows[0].status,"sent");
 assert.equal(events.filter(e=>e.kind==="pagerduty").length,1);assert.equal(events.filter(e=>e.kind==="generic").length,1);
});



test("legacy mixed-channel failures remain blocked through recovery retries",async()=>{
 for(const mode of ["initial","retry-array","retry-ledger"]){
  const {f,incident,id,worker,send,allow}=await blocked();
  const ledger=mode==="retry-ledger" ? {version:1,required:["webhooks"],retry:["webhooks"],outcomes:{webhooks:{state:"failed",endpoints:{}}}} : ["webhooks"];
  const marker=mode==="initial" ? {} : {pagerdutyRecoveryRequeued:true};
  await pool.query(`UPDATE alert_queue SET channels=$2::jsonb,metadata=metadata || $3::jsonb,
    error_message=CASE WHEN $4 THEN 'MAX_ATTEMPTS: No webhook names defined in the selected contact group' ELSE error_message END WHERE id=$1`,
    [id,JSON.stringify(ledger),JSON.stringify(marker),mode!=="initial"]);
  await pool.query(`INSERT INTO alert_delivery_log(alert_queue_id,user_id,workspace_id,channel,status,error_message,metadata)
    VALUES($1,$2,$3,'email','blocked','NO_VERIFIED_RECIPIENTS',$4::jsonb)`,
    [id,f.actor,f.workspaceId,JSON.stringify({code:"NO_VERIFIED_RECIPIENTS"})]);
  allow();
  await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
  for(let n=0;n<2;n++){
   await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
   await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
   const q=(await pool.query("SELECT status,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];
   assert.equal(q.status,"blocked");assert.equal(q.metadata.pagerdutyRecoveryRequeued,marker.pagerdutyRecoveryRequeued);
   assert.equal((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at,null);
  }
  assert.ok((await pool.query("SELECT resolved_at FROM certops_distribution_pagerduty WHERE incident_id=$1",[incident.id])).rows[0].resolved_at);
 }
});


test("legacy mixed-channel failure survives conversion before recovery",async()=>{
 const {f,incident,id,worker,send,allow}=await blocked();
 await pool.query(`INSERT INTO alert_delivery_log(alert_queue_id,user_id,workspace_id,channel,status,error_message,metadata)
   VALUES($1,$2,$3,'email','blocked','NO_VERIFIED_RECIPIENTS',$4::jsonb)`,[id,f.actor,f.workspaceId,JSON.stringify({code:"NO_VERIFIED_RECIPIENTS",recipientDecision:"terminal"})]);
 await pool.query(`UPDATE alert_queue SET channels='["webhooks"]'::jsonb,status='failed',attempts_webhooks=0,next_attempt_at=clock_timestamp() WHERE id=$1`,[id]);
 await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 let q=(await pool.query("SELECT status,channels,metadata FROM alert_queue WHERE id=$1",[id])).rows[0];
 assert.equal(q.status,"blocked");assert.deepEqual(q.channels.required,["webhooks"]);assert.equal(q.metadata.pagerdutyRecoveryRequeued,undefined);
 allow();await pool.query("UPDATE certops_distribution_pagerduty SET next_attempt_at=clock_timestamp() WHERE incident_id=$1",[incident.id]);
 await pool.query("UPDATE alert_queue SET next_attempt_at=clock_timestamp() WHERE id=$1",[id]);
 await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status,next_attempt_at,next_attempt_at > clock_timestamp() AS deferred FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"blocked");assert.equal(q.deferred,true);
 assert.equal((await pool.query("SELECT resolved_at FROM operational_notifications WHERE workspace_id=$1 AND dedupe_key=$2",[f.workspaceId,`delivery_blocked:${id}`])).rows[0].resolved_at,null);
 const deferred=q.next_attempt_at.getTime();await worker.deliveryWorkerJob({closePool:false,webhookSender:send});
 q=(await pool.query("SELECT status,next_attempt_at FROM alert_queue WHERE id=$1",[id])).rows[0];assert.equal(q.status,"blocked");assert.equal(q.next_attempt_at.getTime(),deferred);
});
