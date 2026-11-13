"use strict";
const test = require("node:test"), assert = require("node:assert/strict"), crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^distribution_lifecycle_[a-f0-9]+_test$/);
assert.equal(process.env.NODE_ENV, "test");
const { pool } = require("../../apps/api/db/database");
const { fixture } = require("../helpers/distribution-lifecycle-fixture.cjs");
const operations = require("../../apps/api/services/certops/distributionOperations");
const material = require("../../apps/api/services/certops/materialDistribution");
const maintenance = require("../../apps/api/services/certops/distributionMaintenance");
const { approveJob } = require("../../apps/api/services/certops/jobApprovals");
test.after(() => pool.end());

async function setup({ closed = false } = {}) {
  const f = await fixture();
  if (!closed) await operations.putBinding({ ...f, binding: { ...f.binding, verificationPolicy: "installed" }, actorUserId: f.actor });
  const policy = { method: closed ? "reload" : "none", disruptive: closed, requiresApproval: true,
    timezone: "Europe/Berlin", windows: [], blackouts: [], validUntil: null, emergency: null, independentStaging: true };
  await maintenance.putConsumerPolicy({ ...f, policy, expectedAuthorizationRevision: closed ? 1 : 2, actorUserId: f.actor });
  const requested = await operations.requestRollout({ ...f, actorUserId: f.actor });
  assert.equal(requested.status, "pending_approval");
  await approveJob({ workspaceId: f.workspaceId, jobId: requested.id, approverUserId: f.approver });
  await operations.transaction(client => operations.processDistributionIntent({ client, row: { workspace_id: f.workspaceId, event_type: "distribution_approval_granted" }, payload: { jobId: requested.id } }));
  const rollout = (await pool.query("SELECT * FROM certops_distribution_rollouts WHERE approval_job_id=$1", [requested.id])).rows[0];
  const version = (await pool.query("SELECT valid_to FROM certops_material_versions WHERE id=$1", [f.materialVersionId])).rows[0];
  const advance = () => operations.transaction(client => operations.advanceRollout(client, f.workspaceId, f.groupId, rollout.id));
  await advance();
  const child = async () => (await pool.query("SELECT * FROM certops_consumer_deployments WHERE rollout_id=$1 AND binding_id=$2", [rollout.id, f.bindingId])).rows[0];
  const row = await child();
  assert.ok(row.staging_job_id);
  assert.equal(row.job_id, null);
  const claim = async id => (await pool.query(`UPDATE certificate_jobs SET status='claimed',claimed_by_agent_id=assigned_agent_id,
    claim_id=$2,lease_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1 RETURNING *`, [id, crypto.randomUUID()])).rows[0];
  const accept = async (job, overrides = {}) => {
    const receipt = { schemaVersion: 1, workspaceId: f.workspaceId, groupId: f.groupId, bindingId: f.bindingId,
      materialVersionId: f.materialVersionId, generation: Number(rollout.generation), fetched: true,
      staged: true, installed: false, bound: false, servedVerified: false, trustValidated: false,
      fingerprintSha256: f.fingerprint, validTo: new Date(version.valid_to).toISOString(), observedAt: new Date().toISOString(), ...overrides };
    const accepted = await operations.transaction(async client => {
      const result = await material.acceptDeploymentReceipt({ client, workspaceId: f.workspaceId, agentId: f.consumer, job, receipt, jobStatus: "succeeded" });
      await client.query("UPDATE certificate_jobs SET status='succeeded',completed_at=clock_timestamp() WHERE id=$1", [job.id]);
      return result;
    });
    return accepted;
  };
  return { ...f, rollout, advance, child, claim, accept };
}

test("independently approved staging can finish outside the window without authorizing activation or convergence", async () => {
  const f = await setup({ closed: true }), child = await f.child(), job = await f.claim(child.staging_job_id);
  assert.equal(job.payload.materialDeployment.preparationOnly, true);
  await assert.rejects(f.accept(job, { installed: true }), { code: "CERTOPS_DEPLOYMENT_STAGES_INVALID" });
  await f.accept(job);
  await f.advance();
  const staged = await f.child();
  assert.equal(staged.stage, "staged");
  assert.equal(staged.job_id, null);
  assert.equal(staged.staging_receipt.installed, false);
  const matrix = (await material.consumerMatrix({ client: pool, workspaceId: f.workspaceId, groupId: f.groupId }))[0];
  assert.equal(matrix.converged, false);
  assert.equal(matrix.observed_material_version_id, null);
  assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1", [f.rollout.id])).rows[0].state, "deploying");
});

test("staging and activation use separate immutable child jobs and only installation advances current proof", async () => {
  const f = await setup(), row = await f.child(), preparation = await f.claim(row.staging_job_id);
  assert.equal((await f.accept(preparation)).historicalOnly, true);
  await f.advance();
  const staged = await f.child();
  assert.ok(staged.job_id);
  assert.notEqual(staged.job_id, staged.staging_job_id);
  const activation = await f.claim(staged.job_id);
  assert.equal(activation.payload.materialDeployment.preparationOnly, undefined);
  const { preparationOnly: _phase, ...scope } = preparation.payload.materialDeployment;
  assert.deepEqual(activation.payload.materialDeployment, scope);
  const accepted = await f.accept(activation, { installed: true });
  assert.equal(accepted.historicalOnly, false);
  await f.advance();
  assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1", [f.rollout.id])).rows[0].state, "installed");
  const matrix = (await material.consumerMatrix({ client: pool, workspaceId: f.workspaceId, groupId: f.groupId }))[0];
  assert.equal(matrix.converged, true);
  assert.equal(matrix.verification_method, "installed");
  assert.equal((await f.child()).staging_receipt.servedVerified, false);
});

test("revoking the independent reviewer after staging prevents activation under the old scope", async () => {
  const f = await setup(), row = await f.child();
  await f.accept(await f.claim(row.staging_job_id));
  await pool.query("DELETE FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2", [f.workspaceId, f.approver]);
  const result=await f.advance();
  assert.equal((await f.child()).job_id, null);
  assert.equal(result.reason,"rollout_authorization_stale");
  assert.equal((await pool.query("SELECT state FROM certops_distribution_rollouts WHERE id=$1", [f.rollout.id])).rows[0].state, "paused");
  await pool.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'workspace_manager')",[f.workspaceId,f.approver]);
  assert.equal((await f.advance()).reason,"rollout_authorization_stale","Restoring membership cannot revive the old review after its authority revision changed");
  assert.equal((await f.child()).job_id,null);
});
