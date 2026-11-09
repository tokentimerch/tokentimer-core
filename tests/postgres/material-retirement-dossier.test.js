"use strict";
const {test,after}=require("node:test"),assert=require("node:assert/strict"),crypto=require("node:crypto");
assert.equal(process.env.DB_HOST,"127.0.0.1");assert.match(process.env.DB_NAME||"",/^distribution_lifecycle_[a-f0-9]+_test$/);
const {pool}=require("../../apps/api/db/database"),operations=require("../../apps/api/services/certops/distributionOperations");
const {fixture}=require("../helpers/distribution-lifecycle-fixture.cjs");
after(()=>pool.end());
async function setup(){
  const f=await fixture();await operations.requestRollout({...f,actorUserId:f.actor});
  const rollout=(await pool.query("SELECT * FROM certops_distribution_rollouts WHERE workspace_id=$1",[f.workspaceId])).rows[0];
  await operations.transaction(client=>operations.advanceRollout(client,f.workspaceId,f.groupId,rollout.id));
  const original=(await pool.query("SELECT j.* FROM certops_consumer_deployments d JOIN certificate_jobs j ON j.id=d.job_id WHERE d.rollout_id=$1",[rollout.id])).rows[0];
  await pool.query("UPDATE certificate_jobs SET status='rejected',needs_operator_reconciliation=TRUE,attempt_count=3 WHERE id=$1",[original.id]);
  await pool.query("UPDATE certops_consumer_deployments SET stage='failed' WHERE job_id=$1",[original.id]);
  return {...f,original};
}
test("a separately reviewed retirement dossier records unknown history without clearing the obligation",async()=>{
  const f=await setup();await operations.requestRollout({...f,actorUserId:f.actor});
  const service=require("../../apps/api/services/certops/materialRetirementDossier");
  const evidence=Object.fromEntries(["writerInventory","writerIsolation","destinationIsolation","replacementReadback"].map(k=>[k,`sha256:${"a".repeat(64)}`]));
  await assert.rejects(service.request({workspaceId:f.workspaceId,jobId:f.original.id,actorUserId:f.actor,evidence:{}}),{code:"CERTOPS_RETIREMENT_EVIDENCE_INVALID"});
  const d=await service.request({workspaceId:f.workspaceId,jobId:f.original.id,actorUserId:f.actor,evidence});
  await assert.rejects(service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.actor,dossierHash:d.dossierHash}),{code:"CERTOPS_RETIREMENT_REVIEW_STALE"});
  await assert.rejects(service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.approver,dossierHash:"0".repeat(64)}),{code:"CERTOPS_RETIREMENT_REVIEW_STALE"});
  const result=await service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.approver,dossierHash:d.dossierHash});
  assert.equal(result.history,"unknown");assert.equal(result.evidenceVerified,false);assert.equal(result.reconciliationCleared,false);
  await assert.rejects(service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.approver,dossierHash:d.dossierHash}),{code:"CERTOPS_RETIREMENT_REVIEW_STALE"});
  assert.equal((await pool.query("SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",[f.original.id])).rows[0].needs_operator_reconciliation,true);
});
test("retirement review rejects changed generation and evidence",async()=>{
  const f=await setup();await operations.requestRollout({...f,actorUserId:f.actor});
  const service=require("../../apps/api/services/certops/materialRetirementDossier");
  const evidence=Object.fromEntries(["writerInventory","writerIsolation","destinationIsolation","replacementReadback"].map(k=>[k,`sha256:${"a".repeat(64)}`]));
  const d=await service.request({workspaceId:f.workspaceId,jobId:f.original.id,actorUserId:f.actor,evidence});
  await assert.rejects(pool.query("UPDATE certops_material_retirement_dossiers SET evidence=$2::jsonb WHERE id=$1",[d.id,JSON.stringify({...evidence,writerInventory:`sha256:${"b".repeat(64)}`})]),{code:"55000"});
  await operations.requestRollout({...f,actorUserId:f.actor});
  await assert.rejects(service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.approver,dossierHash:d.dossierHash}),{code:"CERTOPS_RETIREMENT_REVIEW_STALE"});
  assert.equal((await pool.query("SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",[f.original.id])).rows[0].needs_operator_reconciliation,true);
});
test("retirement review rejects cross-workspace and revoked or restored authority",async()=>{
  const f=await setup();await operations.requestRollout({...f,actorUserId:f.actor});
  const service=require("../../apps/api/services/certops/materialRetirementDossier");
  const evidence=Object.fromEntries(["writerInventory","writerIsolation","destinationIsolation","replacementReadback"].map(k=>[k,`sha256:${"a".repeat(64)}`]));
  const d=await service.request({workspaceId:f.workspaceId,jobId:f.original.id,actorUserId:f.actor,evidence});
  await assert.rejects(service.review({workspaceId:crypto.randomUUID(),dossierId:d.id,actorUserId:f.approver,dossierHash:d.dossierHash}));
  await pool.query("DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
  await assert.rejects(service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.approver,dossierHash:d.dossierHash}),{code:"CERTOPS_RETIREMENT_AUTHORITY_STALE"});
  await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')",[f.workspaceId,f.approver]);
  await assert.rejects(service.review({workspaceId:f.workspaceId,dossierId:d.id,actorUserId:f.approver,dossierHash:d.dossierHash}),{code:"CERTOPS_RETIREMENT_REVIEW_STALE"});
  assert.equal((await pool.query("SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1",[f.original.id])).rows[0].needs_operator_reconciliation,true);
});
test("retirement middleware and routes preserve injected-session, tenant, validation and review boundaries",async()=>{
  const f=await setup(),other=await fixture();await operations.requestRollout({...f,actorUserId:f.actor});
  const express=require("../../apps/api/node_modules/express"),request=require("supertest"),app=express();
  app.use(express.json());app.use((req,_res,next)=>{const id=Number(req.get("X-Test-Session"));if([f.actor,f.approver,other.actor].includes(id)){req.user={id,auth_method:"local"};req.isAuthenticated=()=>true;}next();});
  const auth=require("../../apps/api/middleware/auth"),rbac=require("../../apps/api/services/rbac");
  app.use("/api/v1/workspaces/:id",auth.requireAuth,rbac.loadWorkspace,rbac.requireWorkspaceMembership);app.use(require("../../apps/api/routes/certops"));
  const prefix=`/api/v1/workspaces/${f.workspaceId}/certops`,url=`${prefix}/distribution-jobs/${f.original.id}/retirement-dossiers`;
  const evidence=Object.fromEntries(["writerInventory","writerIsolation","destinationIsolation","replacementReadback"].map(k=>[k,`sha256:${"a".repeat(64)}`]));
  assert.equal((await request(app).post(url).send({evidence})).status,401);
  assert.equal((await request(app).post(url).set("X-Test-Session",String(other.actor)).send({evidence})).status,403);
  for(const invalid of [[],{nested:evidence.writerInventory}]){
    const result=await request(app).post(url).set("X-Test-Session",String(f.actor)).send({evidence:{...evidence,writerInventory:invalid}});
    assert.equal(result.status,422,JSON.stringify(result.body));assert.equal(result.body.code,"CERTOPS_RETIREMENT_EVIDENCE_INVALID");
  }
  const missing=await request(app).post(`${prefix}/distribution-jobs/${crypto.randomUUID()}/retirement-dossiers`).set("X-Test-Session",String(f.actor)).send({evidence});
  assert.equal(missing.status,404,JSON.stringify(missing.body));
  const created=await request(app).post(url).set("X-Test-Session",String(f.actor)).send({evidence});
  assert.equal(created.status,200,JSON.stringify(created.body));
  const listed=await request(app).get(url).set("X-Test-Session",String(f.approver));
  assert.equal(listed.status,200);assert.equal(listed.body.items[0].id,created.body.id);assert.equal(listed.body.hasMore,false);assert.equal(listed.body.scopeStatus,"unchecked");
  const foreignList=await request(app).get(`/api/v1/workspaces/${other.workspaceId}/certops/distribution-jobs/${f.original.id}/retirement-dossiers`).set("X-Test-Session",String(other.actor));
  assert.equal(foreignList.status,200);assert.deepEqual(foreignList.body.items,[]);
  const review=`${prefix}/retirement-dossiers/${created.body.id}/review`;
  const self=await request(app).post(review).set("X-Test-Session",String(f.actor)).send({dossierHash:created.body.dossierHash});
  assert.equal(self.status,409,JSON.stringify(self.body));assert.equal(self.body.code,"CERTOPS_RETIREMENT_REVIEW_STALE");
  assert.equal((await request(app).get(`${prefix}/retirement-dossiers/${created.body.id}`).set("X-Test-Session",String(other.actor))).status,403);
  const accepted=await request(app).post(review).set("X-Test-Session",String(f.approver)).send({dossierHash:created.body.dossierHash});
  assert.equal(accepted.status,200,JSON.stringify(accepted.body));assert.equal(accepted.body.reconciliationCleared,false);
  const get=()=>request(app).get(`${prefix}/retirement-dossiers/${created.body.id}`).set("X-Test-Session",String(f.actor));
  let result=await get();assert.equal(result.status,200,JSON.stringify(result.body));assert.equal(result.body.scopeStatus,"current");assert.equal(result.body.evidenceVerified,false);
  await pool.query("UPDATE workspace_memberships SET role='viewer' WHERE workspace_id=$1 AND user_id=$2",[f.workspaceId,f.approver]);
  result=await get();assert.equal(result.body.scopeStatus,"stale");
});
test("workspace deletion removes its retirement dossiers",async()=>{
  const f=await setup();await operations.requestRollout({...f,actorUserId:f.actor});
  const service=require("../../apps/api/services/certops/materialRetirementDossier");
  const evidence=Object.fromEntries(["writerInventory","writerIsolation","destinationIsolation","replacementReadback"].map(k=>[k,`sha256:${"a".repeat(64)}`]));
  const d=await service.request({workspaceId:f.workspaceId,jobId:f.original.id,actorUserId:f.actor,evidence});
  await assert.rejects(pool.query("DELETE FROM certops_material_retirement_dossiers WHERE id=$1",[d.id]),{code:"55000"});
  await operations.transaction(client=>require("../../apps/api/services/workspaceDeletion").deleteWorkspaces(client,[f.workspaceId]));
  assert.equal((await pool.query("SELECT 1 FROM certops_material_retirement_dossiers WHERE id=$1",[d.id])).rowCount,0);
});
