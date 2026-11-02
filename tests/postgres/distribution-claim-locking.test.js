"use strict";

// Dedicated migrated PostgreSQL only. Fixtures contain public metadata; these
// tests exercise admission locks without connecting to any material store.
const { test, after } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const { pool } = require("../../apps/api/db/database");
const { lockManagedJobForClaim } = require("../../apps/api/services/certops/managementClaim");
const { resolveDistributionJobDefaults } = require("../../apps/api/services/certops/materialDistribution");
after(() => pool.end());

async function fixture() {
  const workspaceId = crypto.randomUUID();
  const fingerprint = crypto.randomBytes(32).toString("hex");
  const userId = (await pool.query(`INSERT INTO users(email,display_name,password_hash,auth_method)
    VALUES($1,'Distribution lock test','synthetic-fixture','local') RETURNING id`,
  [`distribution-lock-${workspaceId}@example.test`])).rows[0].id;
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'Distribution claim locks',$2,'team')", [workspaceId, userId]);
  const certificateId = (await pool.query(`INSERT INTO managed_certificates(workspace_id,name,status,source,fingerprint_sha256)
    VALUES($1,'Distribution source','active','agent_filesystem',$2) RETURNING id`, [workspaceId, fingerprint])).rows[0].id;
  const period = (await pool.query("SELECT id,current_identity_id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
    [workspaceId, certificateId])).rows[0];
  const agents = [];
  for (let index = 0; index < 3; index++) {
    agents.push((await pool.query(`INSERT INTO certops_agents(workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status)
      VALUES($1,$2,$3,'0.18.1','1.0.0',$4,$5,'active') RETURNING id`,
    [workspaceId, crypto.randomUUID(), `Distribution agent ${index}`, `ttagent_${crypto.randomBytes(8).toString("hex")}`, crypto.randomBytes(32).toString("hex")])).rows[0].id);
  }
  const groupId = (await pool.query(`INSERT INTO certops_distribution_groups(workspace_id,managed_certificate_id,management_period_id,
    issuer_agent_id,material_store_ref,issuance_profile_ref,profile_revision,generation)
    VALUES($1,$2,$3,$4,'customer','issuer',1,1) RETURNING id`,
  [workspaceId, certificateId, period.id, agents[0]])).rows[0].id;
  const publicationJobId = (await pool.query(`INSERT INTO certificate_jobs(workspace_id,operation,subject_type,subject_id,
    executor_kind,assigned_agent_id,status) VALUES($1,'renew','managed_certificate',$2,'agent',$3,'succeeded') RETURNING id`,
  [workspaceId, certificateId, agents[0]])).rows[0].id;
  const versionId = (await pool.query(`INSERT INTO certops_material_versions(workspace_id,group_id,management_period_id,
    publishing_job_id,publishing_claim_id,profile_revision,state,certificate_identity_id,provider_version,fingerprint_sha256,valid_to,published_at)
    VALUES($1,$2,$3,$4,'fixture-publication',1,'published',$5,1,$6,NOW()+INTERVAL '30 days',NOW()) RETURNING id`,
  [workspaceId, groupId, period.id, publicationJobId, period.current_identity_id, fingerprint])).rows[0].id;
  await pool.query("UPDATE certops_distribution_groups SET latest_material_version_id=$3 WHERE workspace_id=$1 AND id=$2", [workspaceId, groupId, versionId]);
  const approvalJobId = (await pool.query(`INSERT INTO certificate_jobs(workspace_id,operation,subject_type,subject_id,
    executor_kind,assigned_agent_id,status) VALUES($1,'noop','managed_certificate',$2,'agent',$3,'succeeded') RETURNING id`,
  [workspaceId, certificateId, agents[0]])).rows[0].id;
  const rolloutId = (await pool.query(`INSERT INTO certops_distribution_rollouts(workspace_id,group_id,material_version_id,
    generation,approved_intent_hash,approval_job_id,max_parallel) VALUES($1,$2,$3,1,$4,$5,2) RETURNING id`,
  [workspaceId, groupId, versionId, "a".repeat(64), approvalJobId])).rows[0].id;
  const jobs = [];
  for (let index = 1; index < agents.length; index++) {
    const profile = `consumer_${index}`;
    const bindingId = (await pool.query(`INSERT INTO certops_consumer_bindings(workspace_id,group_id,assigned_agent_id,
      deployment_profile_ref,profile_revision,verification_policy) VALUES($1,$2,$3,$4,1,'served') RETURNING id`,
    [workspaceId, groupId, agents[index], profile])).rows[0].id;
    const materialDeployment = {
      groupId, rolloutId, bindingId, materialVersionId: versionId,
      materialStoreRef: "customer", providerVersion: 1,
      fingerprintSha256: fingerprint, generation: 1,
      deploymentProfileRef: profile, profileRevision: 1,
      authorizationRevision: 1, verificationPolicy: "served",
    };
    const job = (await pool.query(`INSERT INTO certificate_jobs(workspace_id,operation,subject_type,subject_id,
      executor_kind,assigned_agent_id,payload) VALUES($1,'deploy-from-store','managed_certificate',$2,'agent',$3,$4::jsonb) RETURNING *`,
    [workspaceId, certificateId, agents[index], JSON.stringify({ materialDeployment })])).rows[0];
    await pool.query(`INSERT INTO certops_consumer_deployments(workspace_id,group_id,rollout_id,binding_id,assigned_agent_id,
      deployment_profile_ref,profile_revision,authorization_revision,required,wave,verification_policy,freshness_seconds,job_id)
      VALUES($1,$2,$3,$4,$5,$6,1,1,TRUE,0,'served',3600,$7)`,
    [workspaceId, groupId, rolloutId, bindingId, agents[index], profile, job.id]);
    await pool.query(`INSERT INTO certops_consumer_current_state(workspace_id,group_id,binding_id,desired_material_version_id,desired_generation)
      VALUES($1,$2,$3,$4,1)`, [workspaceId, groupId, bindingId, versionId]);
    jobs.push(job);
  }
  return { workspaceId, groupId, periodId: period.id, jobs };
}

function options(client, job, extra = {}) {
  return {
    client, workspaceId: job.workspace_id, operation: job.operation,
    subjectId: job.subject_id, payload: job.payload,
    assignedAgentId: job.assigned_agent_id, jobId: job.id, ...extra,
  };
}

async function beginClaim(client, job) {
  await client.query("BEGIN; SET LOCAL statement_timeout='1500ms'");
  await client.query("SELECT id FROM certificate_jobs WHERE id=$1 FOR UPDATE", [job.id]);
  assert.equal(await lockManagedJobForClaim({ client, job, workspaceId: job.workspace_id }), true);
}

test("parallel distribution claims yield on shared-period upgrades and succeed on retry", { timeout: 10000 }, async () => {
  const f = await fixture();
  const clients = await Promise.all([pool.connect(), pool.connect()]);
  try {
    // Two agents own distinct jobs for one maxParallel=2 rollout. Both have
    // reached the normal claim-side shared period/identity locks.
    await Promise.all(clients.map((client, index) => beginClaim(client, f.jobs[index])));
    const results = await Promise.allSettled(clients.map((client, index) =>
      resolveDistributionJobDefaults(options(client, f.jobs[index], { forClaim: true }))));
    for (const result of results) {
      assert.equal(result.status, "rejected");
      assert.equal(result.reason.code, "CERTOPS_DISTRIBUTION_BUSY");
    }
    for (const client of clients) {
      assert.equal((await client.query("SELECT 1 AS ok")).rows[0].ok, 1,
        "a skipped candidate must leave the polling transaction usable");
      await client.query("COMMIT");
    }
    for (const job of f.jobs) {
      const client = clients[0];
      await beginClaim(client, job);
      assert.deepEqual(await resolveDistributionJobDefaults(options(client, job, { forClaim: true })), {
        autoAssignedAgentId: job.assigned_agent_id,
      });
      await client.query("UPDATE certificate_jobs SET status='claimed' WHERE id=$1", [job.id]);
      await client.query("COMMIT");
    }
    assert.deepEqual((await pool.query("SELECT DISTINCT status FROM certificate_jobs WHERE id=ANY($1::uuid[])",
      [f.jobs.map(job => job.id)])).rows, [{ status: "claimed" }]);
  } finally {
    await Promise.all(clients.map(async client => {
      await client.query("ROLLBACK");
      client.release();
    }));
  }
});

test("claim admission yields to a group editor and rechecks its committed state", { timeout: 10000 }, async () => {
  const f = await fixture();
  const editor = await pool.connect(), claimant = await pool.connect();
  try {
    await editor.query("BEGIN");
    await editor.query("UPDATE certops_distribution_groups SET state='disabled' WHERE workspace_id=$1 AND id=$2", [f.workspaceId, f.groupId]);
    await beginClaim(claimant, f.jobs[0]);
    await assert.rejects(resolveDistributionJobDefaults(options(claimant, f.jobs[0], { forClaim: true })), {
      code: "CERTOPS_DISTRIBUTION_BUSY", statusCode: 409,
    });
    assert.equal((await claimant.query("SELECT 1 AS ok")).rows[0].ok, 1);
    await claimant.query("COMMIT");
    await editor.query("COMMIT");

    await claimant.query("BEGIN");
    await assert.rejects(resolveDistributionJobDefaults(options(claimant, f.jobs[0], { forClaim: true })), {
      code: "CERTOPS_DISTRIBUTION_INACTIVE",
    });
  } finally {
    await Promise.all([editor.query("ROLLBACK"), claimant.query("ROLLBACK")]);
    editor.release(); claimant.release();
  }
});

test("claim mode preserves not-found and exact deployment-authorization checks", async () => {
  const f = await fixture();
  const client = await pool.connect();
  const job = f.jobs[0];
  try {
    await client.query("BEGIN");
    await assert.rejects(resolveDistributionJobDefaults(options(client, job, {
      forClaim: true,
      payload: { materialDeployment: { ...job.payload.materialDeployment, groupId: crypto.randomUUID() } },
    })), { code: "CERTOPS_DISTRIBUTION_NOT_FOUND", statusCode: 404 });
    await assert.rejects(resolveDistributionJobDefaults(options(client, job, {
      forClaim: true,
      payload: { materialDeployment: { ...job.payload.materialDeployment, authorizationRevision: 2 } },
    })), { code: "CERTOPS_DEPLOYMENT_INTENT_MISMATCH" });
    assert.deepEqual(await resolveDistributionJobDefaults(options(client, job, { forClaim: true })), {
      autoAssignedAgentId: job.assigned_agent_id,
    });
  } finally {
    await client.query("ROLLBACK");
    client.release();
  }
});

test("non-claim callers retain their existing blocking group lock", { timeout: 10000 }, async () => {
  const f = await fixture();
  const editor = await pool.connect(), writer = await pool.connect();
  try {
    await editor.query("BEGIN");
    await editor.query("SELECT id FROM certops_distribution_groups WHERE workspace_id=$1 AND id=$2 FOR UPDATE", [f.workspaceId, f.groupId]);
    await writer.query("BEGIN; SET LOCAL lock_timeout='100ms'");
    await assert.rejects(resolveDistributionJobDefaults(options(writer, f.jobs[0])), { code: "55P03" });
    await writer.query("ROLLBACK");
    await editor.query("COMMIT");
    await writer.query("BEGIN");
    assert.deepEqual(await resolveDistributionJobDefaults(options(writer, f.jobs[0])), {
      autoAssignedAgentId: f.jobs[0].assigned_agent_id,
    });
  } finally {
    await Promise.all([editor.query("ROLLBACK"), writer.query("ROLLBACK")]);
    editor.release(); writer.release();
  }
});
