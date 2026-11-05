"use strict";
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");

// Seed only a uniquely owned disposable database before applying new migrations.
// Public PEM-like test data is never used to claim native trust installation.
async function seedCertOpsUpgrade(client) {
  const workspaceId = randomUUID();
  const user = (await client.query("INSERT INTO users(email,display_name,password_hash,email_verified) VALUES($1,'Release upgrade fixture','synthetic-no-login',true) RETURNING id", [`release-${workspaceId}@example.test`])).rows[0];
  await client.query("INSERT INTO workspaces(id,name,created_by) VALUES($1,'Release upgrade fixture',$2)", [workspaceId, user.id]);
  await client.query("INSERT INTO workspace_memberships(workspace_id,user_id,role) VALUES($1,$2,'admin')", [workspaceId,user.id]);
  const bootstrap = (await client.query("INSERT INTO certops_agent_bootstrap_tokens(workspace_id,name,token_prefix,token_hash,expires_at) VALUES($1,'Release fixture',$2,repeat('a',64),'2035-01-01') RETURNING id", [workspaceId,`ttboot_${randomUUID().replaceAll('-','').slice(0,16)}`])).rows[0];
  const agent = (await client.query("INSERT INTO certops_agents(workspace_id,agent_id,agent_version,protocol_version,credential_prefix,credential_hash,bootstrap_token_id) VALUES($1,$2,'0.18.2','1.0.0',$3,repeat('b',64),$4) RETURNING id", [workspaceId,`release-${randomUUID()}`,`ttagent_${randomUUID().replaceAll('-','').slice(0,16)}`,bootstrap.id])).rows[0];
  const certificate = (await client.query("INSERT INTO managed_certificates(workspace_id,status,fingerprint_sha256) VALUES($1,'active',repeat('c',64)) RETURNING id", [workspaceId])).rows[0];
  const job = (await client.query("INSERT INTO certificate_jobs(workspace_id,operation,status,source,assigned_agent_id) VALUES($1,'noop','pending','api',$2) RETURNING id", [workspaceId,agent.id])).rows[0];
  const anchor = (await client.query("INSERT INTO certops_trust_anchors(workspace_id,name,pem,anchor_type,fingerprint_sha256) VALUES($1,'Release fixture public anchor',$2,'root',repeat('d',64)) RETURNING id", [workspaceId,"-----BEGIN CERTIFICATE-----\nUHVibGljIHVwZ3JhZGUgZml4dHVyZQ==\n-----END CERTIFICATE-----"])).rows[0];
  await client.query("INSERT INTO certops_trust_anchor_installations(workspace_id,trust_anchor_id,agent_id,host,store,fingerprint_sha256,owner,provenance,last_job_id) VALUES($1,$2,$3,'release-fixture','ROOT',repeat('d',64),'release-fixture','tokentimer_installed',$4)", [workspaceId,anchor.id,agent.id,job.id]);
  return { workspaceId, userId: user.id, agentId: agent.id, certificateId: certificate.id, jobId: job.id, anchorId: anchor.id };
}

const TABLES = ["certops_agent_bootstrap_tokens", "certops_agents", "managed_certificates", "certificate_jobs", "certops_trust_anchors", "certops_trust_anchor_installations"];
async function snapshotCertOpsUpgrade(client, fixture) {
  const state = {};
  for (const table of TABLES) {
    state[table] = (await client.query(`SELECT to_jsonb(t) AS value FROM ${table} t WHERE workspace_id=$1 ORDER BY id`, [fixture.workspaceId])).rows.map(row=>row.value);
    assert.equal(state[table].length,1,`Expected owned ${table} row`);
  }
  return state;
}

async function assertCertOpsUpgradePreserved(client, fixture, before) {
  const after = await snapshotCertOpsUpgrade(client, fixture);
  for (const table of TABLES) {
    // Additive migrations may add columns. Every pre-existing column and its
    // exact timestamp/value must survive; do not silently omit changed fields.
    for (let index=0;index<before[table].length;index++) {
      const old = before[table][index];
      assert.deepEqual(Object.fromEntries(Object.keys(old).map(key=>[key,after[table][index][key]])),old,`${table} prior values changed`);
    }
  }
  const links = (await client.query(`SELECT j.assigned_agent_id=a.id AS job_agent,
    i.agent_id=a.id AS trust_agent,i.last_job_id=j.id AS trust_job,i.trust_anchor_id=t.id AS trust_anchor
    FROM certificate_jobs j JOIN certops_agents a ON a.workspace_id=j.workspace_id
    JOIN certops_trust_anchor_installations i ON i.workspace_id=j.workspace_id
    JOIN certops_trust_anchors t ON t.workspace_id=j.workspace_id
    WHERE j.id=$1`, [fixture.jobId])).rows;
  assert.deepEqual(links,[{job_agent:true,trust_agent:true,trust_job:true,trust_anchor:true}]);
  return { tables: TABLES.length, rows: TABLES.length, preservedForeignKeyLinks: 4 };
}

module.exports = { seedCertOpsUpgrade, snapshotCertOpsUpgrade, assertCertOpsUpgradePreserved };
