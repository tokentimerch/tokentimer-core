"use strict";

// Run against a disposable PostgreSQL database. Temporary tables exercise the
// actual recovery SQL without changing any persistent certificate records.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { Client } = require("pg");
const { _test } = require("../../apps/api/services/certops/agentDispatch");

test("recovered store issuance binds the original job to its verified identity", async () => {
  const client = new Client({ host: process.env.DB_HOST, port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASSWORD });
  await client.connect();
  try {
    await client.query("BEGIN");
    await client.query("CREATE SCHEMA store_identity_test");
    await client.query("SET LOCAL search_path TO pg_temp, store_identity_test, public");
    await client.query("CREATE FUNCTION store_identity_test.certops_normalize_fingerprint(text) RETURNS text LANGUAGE SQL IMMUTABLE AS $$ SELECT lower(replace($1, ':', '')) $$");
    await client.query(`CREATE TEMP TABLE certificate_jobs(workspace_id uuid,id uuid,operation text,certificate_identity_id uuid,
      assigned_agent_id uuid,subject_type text,subject_id text,enrollment_id uuid,management_period_id uuid);
      CREATE TEMP TABLE certops_certificate_identities(workspace_id uuid,id uuid,fingerprint_sha256 text);
      CREATE TEMP TABLE certops_management_associations(workspace_id uuid,period_id uuid,identity_id uuid);
      CREATE TEMP TABLE certops_issuance_job_identities(workspace_id uuid,job_id uuid PRIMARY KEY,identity_id uuid);
      CREATE TEMP TABLE certificate_enrollments(workspace_id uuid,id uuid,agent_id uuid,certificate_id uuid,current_job_id uuid);
      CREATE TEMP TABLE certops_adcs_expected_identity_receipts(workspace_id uuid,id uuid,enrollment_id uuid,agent_id uuid,original_job_id uuid,fingerprint_sha256 text);
      CREATE TEMP TABLE certops_adcs_proof_recovery_intents(workspace_id uuid,id uuid,receipt_id uuid,enrollment_id uuid,agent_id uuid,proof_job_id uuid);
      CREATE TEMP TABLE certops_acme_store_enrollments(workspace_id uuid,agent_id uuid,certificate_id uuid,original_job_id uuid,current_job_id uuid,state text,fingerprint_sha256 text)`);
    const workspaceId = randomUUID(), otherWorkspace = randomUUID(), agent = randomUUID(), otherAgent = randomUUID();
    const certificate = randomUUID(), enrollment = randomUUID(), receipt = randomUUID(), period = randomUUID();
    const identity = randomUUID(), originalAdcs = randomUUID(), proof = randomUUID(), originalAcme = randomUUID(), continuation = randomUUID();
    const fingerprint = "a".repeat(64), target = { type: "windows-cert-store", store: "My", reference: "host.example" };
    await client.query("INSERT INTO certops_certificate_identities VALUES ($1,$2,$3)", [workspaceId, identity, fingerprint]);
    await client.query("INSERT INTO certops_management_associations VALUES ($1,$2,$3)", [workspaceId, period, identity]);
    for (const id of [originalAdcs, originalAcme]) await client.query(
      "INSERT INTO certificate_jobs VALUES ($1,$2,'issue',NULL,$3,'managed_certificate',$4,$5,$6)",
      [workspaceId, id, agent, certificate, enrollment, period]);
    await client.query("INSERT INTO certificate_enrollments VALUES ($1,$2,$3,$4,$5)", [workspaceId, enrollment, agent, certificate, originalAdcs]);
    await client.query("INSERT INTO certops_adcs_expected_identity_receipts VALUES ($1,$2,$3,$4,$5,$6)", [workspaceId, receipt, enrollment, agent, originalAdcs, fingerprint]);
    await client.query("INSERT INTO certops_adcs_proof_recovery_intents VALUES ($1,$2,$3,$4,$5,$6)", [workspaceId, randomUUID(), receipt, enrollment, agent, proof]);
    await client.query("INSERT INTO certops_acme_store_enrollments VALUES ($1,$2,$3,$4,$5,'installed',$6)", [workspaceId, agent, certificate, originalAcme, continuation, fingerprint]);
    for (const job of [
      { id: proof, operation: "adcs-installation-proof", enrollment_id: enrollment },
      { id: continuation, operation: "continue-enrollment", enrollment_id: null },
    ]) {
      Object.assign(job, { assigned_agent_id: agent, subject_id: certificate, payload: { target } });
      const invoke = (overrides = {}) => _test.preserveRecoveredIssuanceIdentity({ client, workspaceId, job: { ...job, ...overrides }, fingerprint });
      await invoke();
      await invoke(); // idempotent replay must retain the same identity.
      await assert.rejects(invoke({ assigned_agent_id: otherAgent }), /unavailable or ambiguous/);
      await assert.rejects(_test.preserveRecoveredIssuanceIdentity({ client, workspaceId: otherWorkspace, job, fingerprint }), /unavailable or ambiguous/);
      await assert.rejects(invoke({ subject_id: randomUUID() }), /unavailable or ambiguous/);
      await assert.rejects(_test.preserveRecoveredIssuanceIdentity({ client, workspaceId, job, fingerprint: "b".repeat(64) }), /unavailable or ambiguous/);
      if (job.enrollment_id) await assert.rejects(invoke({ enrollment_id: randomUUID() }), /unavailable or ambiguous/);
    }
    const mapped = await client.query("SELECT job_id,identity_id FROM certops_issuance_job_identities ORDER BY job_id");
    assert.deepEqual(new Set(mapped.rows.map(row => row.job_id)), new Set([originalAdcs, originalAcme]));
    assert.ok(mapped.rows.every(row => row.identity_id === identity));
    await client.query("INSERT INTO certops_adcs_proof_recovery_intents VALUES ($1,$2,$3,$4,$5,$6)", [workspaceId, randomUUID(), receipt, enrollment, agent, proof]);
    await assert.rejects(_test.preserveRecoveredIssuanceIdentity({ client, workspaceId, job: { id: proof, operation: "adcs-installation-proof", enrollment_id: enrollment,
      assigned_agent_id: agent, subject_id: certificate, payload: { target } }, fingerprint }), /ambiguous/);
  } finally {
    await client.query("ROLLBACK");
    await client.end();
  }
});
