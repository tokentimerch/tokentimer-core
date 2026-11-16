"use strict";
const {test,after}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
assert.equal(process.env.DB_HOST,'127.0.0.1');assert.match(process.env.DB_NAME||'',/^distribution_lifecycle_[a-f0-9]+_test$/);
const {pool}=require('../../apps/api/db/database');const {claimJobs}=require('../../apps/api/services/certops/agentDispatch');
after(()=>pool.end());
async function fixture(){
 const workspaceId=crypto.randomUUID(),user=(await pool.query("INSERT INTO users(email,display_name,password_hash,auth_method) VALUES($1,'Dispatch','fixture','local') RETURNING id",[`${crypto.randomUUID()}@example.test`])).rows[0].id;
 await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Dispatch',$2,'team')",[workspaceId,user]);
 const a=(await pool.query(`INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status)
  VALUES($1,$2,'Dispatch','0.18.1','1.0.0',$3,$4,'active') RETURNING *`,[workspaceId,crypto.randomUUID(),'ttagent_'+crypto.randomBytes(8).toString('hex'),crypto.randomBytes(32).toString('hex')])).rows[0];
 return {workspaceId,agent:{id:a.id,agentId:a.agent_id,workspaceId,status:'active',protocolVersion:'1.0.0',agentVersion:'0.18.1'}};
}
async function certificate(f,source='agent_filesystem',ref=crypto.randomUUID()){
 const c=(await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,source_ref,fingerprint_sha256)
  VALUES($1,'Dispatch certificate','active',$2,$3,$4) RETURNING id`,[f.workspaceId,source,ref,crypto.randomBytes(32).toString('hex')])).rows[0];
 const period=(await pool.query('SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL',[f.workspaceId,c.id])).rows[0];assert.ok(period);return {id:c.id,period:period.id};
}
async function job(f,id,cert,when){
 await pool.query(`INSERT INTO certificate_jobs(id,workspace_id,operation,status,source,subject_type,subject_id,assigned_agent_id,management_period_id,created_at,payload)
 VALUES($1,$2,'renew','pending','api',$3,$4,$5,$6,$7,'{}')`,[id,f.workspaceId,cert?'managed_certificate':null,cert?.id||null,f.agent.id,cert?.period||null,when]);
}
const id=n=>`00000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
function claim(f,maxJobs){return claimJobs({dbPool:pool,agent:f.agent,body:{maxJobs,supportedActions:['renew']},env:{CERTOPS_ENABLED:'true'},deps:{assertCurrentAgentCredential:async()=>{},signJobForDispatch:async({job})=>job}});}
test('locked leading jobs do not starve same-timestamp successors or exceed claim limits',async()=>{
 const f=await fixture(),a=await certificate(f),b=await certificate(f),owner=await pool.connect(),when='2026-01-01T00:00:00.123456Z';
 for(const [n,c] of [[1,a],[2,b],[3,null],[4,null],[5,null]])await job(f,id(n),c,n===5?'2026-01-01T00:00:00.123457Z':when);
 try{
  await owner.query('BEGIN');await owner.query('SELECT id FROM certops_management_periods WHERE id=ANY($1::uuid[]) FOR UPDATE',[[a.period,b.period]]);
  const first=await claim(f,2);assert.equal(first.jobs.length,2);assert.deepEqual(first.jobs.map(x=>x.jobId),[id(3),id(4)]);
  const second=await claim(f,1);assert.equal(second.jobs.length,1);assert.equal(second.jobs[0].jobId,id(5));
  const blocked=(await pool.query('SELECT id,status,attempt_count FROM certificate_jobs WHERE id=ANY($1::uuid[]) ORDER BY id',[[id(1),id(2)]])).rows;
  assert.ok(blocked.every(x=>x.status==='pending'&&x.attempt_count===0));
 }finally{await owner.query('ROLLBACK');owner.release();}
});
test('Windows store renewals remain filtered ahead of eligible work',async()=>{
 const f=await fixture(),blocked=await certificate(f,'agent_windows','agent/windows_store/My/1234');
 await job(f,id(11),blocked,'2026-01-01T00:00:00Z');await job(f,id(12),null,'2026-01-01T00:00:01Z');
 const result=await claim(f,1);assert.equal(result.jobs.length,1);assert.equal(result.jobs[0].jobId,id(12));
 assert.equal((await pool.query('SELECT status FROM certificate_jobs WHERE id=$1',[id(11)])).rows[0].status,'pending');
});
test('legacy IIS ambiguous bindings stay excluded ahead of eligible work',async()=>{
 const f=await fixture(),blocked=await certificate(f,'agent_windows','agent/iis_binding/Shop:443');
 await pool.query('UPDATE managed_certificates SET deployed_agent_id=$2 WHERE id=$1',[blocked.id,f.agent.id]);
 const target=(await pool.query(`INSERT INTO certificate_targets(workspace_id,name,target_type,source,source_ref,location_kind,deployment_reference,windows_store,windows_site,windows_port,public_metadata)
  VALUES($1,'IIS','windows-iis','agent_windows',$2,'iis_binding','iis://Shop:443','WebHosting','Shop',443,$3::jsonb) RETURNING id`,[f.workspaceId,crypto.randomUUID(),JSON.stringify({agentId:f.agent.agentId,observationOnly:true,keyPresent:true,boundAddress:'192.0.2.10'})])).rows[0];
 await pool.query(`INSERT INTO certificate_instances(workspace_id,managed_certificate_id,target_id,status,source,source_ref,location_kind,observed_fingerprint_sha256,observed_at,captured_at,presence_state)
  VALUES($1,$2,$3,'discovered','agent_windows',$4,'iis_binding',$5,NOW(),NOW(),'confirmed_present')`,[f.workspaceId,blocked.id,target.id,crypto.randomUUID(),crypto.randomBytes(32).toString('hex')]);
 await job(f,id(21),blocked,'2026-01-01T00:00:00Z');await job(f,id(22),null,'2026-01-01T00:00:01Z');
 const result=await claim(f,1);assert.equal(result.jobs.length,1);assert.equal(result.jobs[0].jobId,id(22));
 assert.equal((await pool.query('SELECT status FROM certificate_jobs WHERE id=$1',[id(21)])).rows[0].status,'pending');
});
test('disabled automatic AD CS renewal stays excluded ahead of eligible work',async()=>{
 const f=await fixture(),blocked=await certificate(f);
 await pool.query(`UPDATE certops_agents SET declared_capabilities='["adcs-enroll-v1","evidence-claim-binding-v1"]'::jsonb,capabilities_updated_at=NOW() WHERE id=$1`,[f.agent.id]);
 const issuer=(await pool.query("INSERT INTO certificate_issuers(workspace_id,kind,name,current_version) VALUES($1,'adcs','Test CA',1) RETURNING id",[f.workspaceId])).rows[0];
 const enrollment=(await pool.query(`INSERT INTO certificate_enrollments(workspace_id,certificate_id,issuer_id,issuer_version,agent_id,state,snapshot_bytes,snapshot_sha256,deploy_target,attempt)
  VALUES($1,$2,$3,1,$4,'requested',$5,$6,'{}',0) RETURNING id`,[f.workspaceId,blocked.id,issuer.id,f.agent.id,Buffer.from('{}'),crypto.createHash('sha256').update('{}').digest('hex')])).rows[0];
 await job(f,id(31),blocked,'2026-01-01T00:00:00Z');
 await pool.query("UPDATE certificate_jobs SET source='automation',enrollment_id=$2 WHERE id=$1",[id(31),enrollment.id]);
 await pool.query('UPDATE certificate_enrollments SET current_job_id=$2 WHERE id=$1',[enrollment.id,id(31)]);
 await job(f,id(32),null,'2026-01-01T00:00:01Z');
 const result=await claim(f,1);assert.equal(result.jobs.length,1);assert.equal(result.jobs[0].jobId,id(32));
 assert.equal((await pool.query('SELECT status FROM certificate_jobs WHERE id=$1',[id(31)])).rows[0].status,'pending');
});
