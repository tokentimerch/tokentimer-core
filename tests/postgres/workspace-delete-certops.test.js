"use strict";

// Dedicated migrated PostgreSQL only. Builds a workspace holding CertOps
// distribution material and deletes it through the production route.
const { before, after, describe, it } = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^pr329_.*_test$/);
assert.equal(process.env.NODE_ENV, "test");
const request = require("supertest");
const express = require("../../apps/api/node_modules/express");
const { pool } = require("../../apps/api/db/database");

const sha = (char) => char.repeat(64);
const hex = (bytes) => crypto.randomBytes(bytes).toString("hex");
let app, userId;

async function insert(table, row) {
  const keys = Object.keys(row);
  const res = await pool.query(
    `INSERT INTO ${table}(${keys.join(",")}) VALUES(${keys.map((_, i) => `$${i + 1}`).join(",")}) RETURNING id`,
    keys.map((key) => row[key]),
  );
  return res.rows[0]?.id;
}

async function buildWorkspace() {
  const ws = crypto.randomUUID();
  await pool.query(
    "INSERT INTO workspaces(id,name,created_by) VALUES($1,'CertOps delete',$2)",
    [ws, userId],
  );
  await pool.query(
    "INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin')",
    [ws, userId],
  );
  const agent = await insert("certops_agents", {
    workspace_id: ws,
    agent_id: `agent-${crypto.randomUUID()}`,
    agent_version: "1.0.0",
    protocol_version: "1.0.0",
    credential_prefix: `ttagent_${hex(8)}`,
    credential_hash: hex(32),
  });
  await insert("certops_agent_bootstrap_tokens", {
    workspace_id: ws,
    name: "bootstrap",
    token_prefix: `ttboot_${hex(8)}`,
    token_hash: hex(32),
    expires_at: new Date(Date.now() + 3600e3),
  });
  const cert = await insert("managed_certificates", { workspace_id: ws });
  // A trigger opens the management period when the certificate is inserted.
  const period = (
    await pool.query(
      "SELECT id FROM certops_management_periods WHERE workspace_id=$1 AND managed_certificate_id=$2 AND ended_at IS NULL",
      [ws, cert],
    )
  ).rows[0].id;
  const identity = await insert("certops_certificate_identities", {
    workspace_id: ws,
    fingerprint_sha256: hex(32),
  });
  const issueJob = await insert("certificate_jobs", {
    workspace_id: ws,
    operation: "issue",
  });
  const approvalJob = await insert("certificate_jobs", {
    workspace_id: ws,
    operation: "distribute-trust",
  });
  const deployJob = await insert("certificate_jobs", {
    workspace_id: ws,
    operation: "deploy",
  });
  await pool.query(
    "INSERT INTO certificate_job_log(workspace_id,job_id,event_type) VALUES($1,$2,'job.created')",
    [ws, issueJob],
  );
  await insert("certops_outbox", {
    workspace_id: ws,
    event_type: "material_published",
    dedupe_key: `k-${crypto.randomUUID()}`,
  });
  const group = await insert("certops_distribution_groups", {
    workspace_id: ws,
    managed_certificate_id: cert,
    management_period_id: period,
    issuer_agent_id: agent,
    material_store_ref: "store",
    issuance_profile_ref: "profile",
    profile_revision: 1,
  });
  const version = await insert("certops_material_versions", {
    workspace_id: ws,
    group_id: group,
    management_period_id: period,
    publishing_job_id: issueJob,
    profile_revision: 1,
  });
  await pool.query(
    "UPDATE certops_distribution_groups SET latest_material_version_id=$1, generation=1 WHERE id=$2",
    [version, group],
  );
  const binding = await insert("certops_consumer_bindings", {
    workspace_id: ws,
    group_id: group,
    assigned_agent_id: agent,
    deployment_profile_ref: "consumer",
    profile_revision: 1,
    verification_policy: "served",
  });
  const rollout = await insert("certops_distribution_rollouts", {
    workspace_id: ws,
    group_id: group,
    material_version_id: version,
    generation: 1,
    approved_intent_hash: sha("b"),
    approval_job_id: approvalJob,
  });
  await insert("certops_consumer_deployments", {
    workspace_id: ws,
    group_id: group,
    rollout_id: rollout,
    binding_id: binding,
    assigned_agent_id: agent,
    deployment_profile_ref: "consumer",
    profile_revision: 1,
    authorization_revision: 1,
    required: true,
    wave: 0,
    verification_policy: "served",
    freshness_seconds: 3600,
    job_id: deployJob,
  });
  await pool.query(
    `INSERT INTO certops_consumer_current_state(workspace_id,group_id,binding_id,
       desired_material_version_id,desired_generation,observed_material_version_id)
     VALUES($1,$2,$3,$4,1,$4)`,
    [ws, group, binding, version],
  );
  await pool
    .query(
      `INSERT INTO audit_events(actor_user_id,subject_user_id,action,target_type,workspace_id,metadata)
     VALUES($1,$1,'TOKEN_CREATED','token',$2,'{}'::jsonb)`,
      [userId, ws],
    )
    .catch(() => {});
  return { ws, group, version };
}

describe(
  "Workspace deletion with CertOps material (real PostgreSQL and HTTP route)",
  { concurrency: false },
  () => {
    before(async () => {
      userId = (
        await pool.query(
          `INSERT INTO users(email,display_name,email_verified,password_hash)
           VALUES($1,'Workspace delete test',TRUE,'synthetic-fixture') RETURNING id`,
          [`ws-delete-${crypto.randomUUID()}@example.test`],
        )
      ).rows[0].id;
      app = express();
      app.use(express.json());
      app.use((req, _res, next) => {
        req.user = { id: userId, email_verified: true };
        req.isAuthenticated = () => true;
        next();
      });
      app.use(require("../../apps/api/routes/workspaces"));
    });
    after(async () => {
      await pool.end();
    });

    it("deletes a workspace that owns distribution groups, material, rollouts and jobs", async () => {
      const { ws, group, version } = await buildWorkspace();
      const latest = await pool.query(
        "SELECT latest_material_version_id FROM certops_distribution_groups WHERE id=$1",
        [group],
      );
      assert.equal(latest.rows[0].latest_material_version_id, version);

      const res = await request(app).delete(`/api/v1/workspaces/${ws}`);
      assert.equal(res.status, 204, JSON.stringify(res.body));

      for (const table of [
        "workspaces",
        "certops_distribution_groups",
        "certops_material_versions",
        "certops_consumer_bindings",
        "certops_distribution_rollouts",
        "certops_consumer_deployments",
        "certops_consumer_current_state",
        "certops_agents",
        "certificate_jobs",
      ]) {
        const col = table === "workspaces" ? "id" : "workspace_id";
        const left = await pool.query(
          `SELECT count(*)::int AS n FROM ${table} WHERE ${col}=$1`,
          [ws],
        );
        assert.equal(left.rows[0].n, 0, `${table} rows must be gone`);
      }
    });

    it("leaves other workspaces untouched", async () => {
      const keep = await buildWorkspace();
      const drop = await buildWorkspace();
      const res = await request(app).delete(`/api/v1/workspaces/${drop.ws}`);
      assert.equal(res.status, 204, JSON.stringify(res.body));
      const left = await pool.query(
        "SELECT count(*)::int AS n FROM certops_material_versions WHERE workspace_id=$1",
        [keep.ws],
      );
      assert.equal(left.rows[0].n, 1);
    });
  },
);
