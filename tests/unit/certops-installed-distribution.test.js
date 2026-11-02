"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const { acceptDeploymentReceipt, validateDistributionContract } = require("../../apps/api/services/certops/materialDistribution");

function fixture(policy = "installed", changes = {}) {
  const workspaceId = randomUUID(), agentId = randomUUID();
  const intent = { groupId: randomUUID(), bindingId: randomUUID(), rolloutId: randomUUID(), materialVersionId: randomUUID(),
    materialStoreRef: "vault", providerVersion: 1, fingerprintSha256: "a".repeat(64), generation: 1,
    deploymentProfileRef: "files", profileRevision: 1, authorizationRevision: 1, verificationPolicy: policy };
  const job = { id: randomUUID(), claim_id: randomUUID(), claimed_by_agent_id: agentId, payload: { materialDeployment: intent } };
  const validTo = new Date(Date.now() + 86400000).toISOString();
  const receipt = { schemaVersion: 1, workspaceId, groupId: intent.groupId, bindingId: intent.bindingId,
    materialVersionId: intent.materialVersionId, generation: 1, fetched: true, installed: true, bound: false,
    servedVerified: false, trustValidated: false, fingerprintSha256: intent.fingerprintSha256, validTo, observedAt: new Date().toISOString() };
  const row = { job_id: job.id, assigned_agent_id: agentId, group_id: intent.groupId, binding_id: intent.bindingId,
    material_version_id: intent.materialVersionId, generation: 1, fingerprint_sha256: intent.fingerprintSha256,
    valid_to: validTo, verification_policy: policy, authorization_revision: 1, current_authorization_revision: 1,
    deployment_profile_ref: "files", profile_revision: 1, freshness_seconds: 300, certificate_identity_id: randomUUID(),
    binding_state: "active", rollout_state: "deploying", desired_generation: 1, desired_material_version_id: intent.materialVersionId, ...changes };
  let promoted = null;
  const client = { async query(sql, params) {
    if (sql.includes("SELECT g.*")) return { rows: [{ state: "active" }] };
    if (sql.includes("SELECT d.*")) return { rows: [row] };
    if (sql.includes("SELECT 1 FROM certificate_jobs")) return { rowCount: 1, rows: [{}] };
    if (sql.includes("pg_try_advisory_xact_lock_shared")) return { rows: [{ locked: true }] };
    if (sql.includes("SELECT lifecycle_status")) return { rows: [{ lifecycle_status: changes.identityRetired ? "retired" : "active" }] };
    if (sql.includes("UPDATE certops_consumer_current_state")) promoted = params;
    return { rows: [], rowCount: 1 };
  } };
  return { intent, receipt, row, promotion: () => promoted, run: () => acceptDeploymentReceipt({ client, workspaceId, agentId, job, receipt, jobStatus: "succeeded" }) };
}

test("installed receipt promotes only files-installed assurance and never a listener claim", async () => {
  const f = fixture();
  validateDistributionContract("materialDeployment", f.intent);
  assert.deepEqual(await f.run(), { historicalOnly: false, retirementConflict: false, stage: "installed" });
  assert.equal(f.promotion()[6], "installed");
});

test("installation-only evidence cannot satisfy served or trust policies", async () => {
  for (const policy of ["served", "trust"]) {
    const f = fixture(policy);
    await assert.rejects(f.run(), { code: "CERTOPS_DEPLOYMENT_ASSURANCE_MISSING" });
    assert.equal(f.promotion(), null);
  }
  const f = fixture();
  Object.assign(f.receipt, { bound: true, servedVerified: true });
  await assert.rejects(f.run(), { code: "CERTOPS_DEPLOYMENT_ASSURANCE_MISMATCH" });
});

test("Windows receipts cannot downgrade IIS assurance to installed-only", async () => {
  const rejected = fixture("installed", { agent_platform: "win32" });
  await assert.rejects(rejected.run(), { code: "CERTOPS_DEPLOYMENT_ASSURANCE_MISMATCH" });
  assert.equal(rejected.promotion(), null);
  for (const policy of ["served", "trust"]) {
    const accepted = fixture(policy, { agent_platform: "win32" });
    Object.assign(accepted.receipt, { bound: true, servedVerified: true, trustValidated: policy === "trust" });
    assert.equal((await accepted.run()).historicalOnly, false);
  }
});

test("Windows binding admission rejects installed-only assurance without writing authorization", async t => {
  const material = require("../../apps/api/services/certops/materialDistribution");
  const policy = require("../../apps/api/services/certops/distributionPolicy");
  const database = require("../../apps/api/db/database");
  const { putBinding } = require("../../apps/api/services/certops/distributionOperations");
  const statements = [];
  t.mock.method(material, "lockGroup", async () => ({ state: "active" }));
  // The exported policy function was captured by distributionOperations when
  // loaded, so supply its real read prerequisites rather than replace it.
  assert.equal(typeof policy.assertDistributionPolicy, "function");
  const client = { async query(sql) {
    statements.push(sql);
    if (sql.includes("FROM workspaces")) return { rows: [{ id: randomUUID(), certops_paused: false }] };
    if (sql.includes("FROM system_settings")) return { rows: [{ certops_settings: { enabled: true } }] };
    if (sql.includes("SELECT platform FROM certops_agents")) return { rows: [{ platform: "win32" }] };
    return { rows: [], rowCount: 0 };
  }, release() {} };
  t.mock.method(database.pool, "connect", async () => client);
  await assert.rejects(putBinding({ workspaceId: randomUUID(), groupId: randomUUID(), bindingId: randomUUID(),
    binding: { agentId: randomUUID(), deploymentProfileRef: "iis", profileRevision: 1,
      required: true, wave: 0, verificationPolicy: "installed", freshnessSeconds: 300, state: "active" },
  }), { code: "CERTOPS_DEPLOYMENT_ASSURANCE_MISMATCH" });
  assert.equal(statements.some(sql => /(?:INSERT INTO|UPDATE) certops_consumer_bindings/.test(sql)), false);
  assert.equal(statements.at(-1), "ROLLBACK");
});

test("files-only receipts remain historical after reassignment, generation change, retirement or rollout completion", async () => {
  for (const changes of [{ current_authorization_revision: 2 }, { desired_generation: 2 }, { binding_state: "removed" },
    { identityRetired: true }, { rollout_state: "installed" }]) {
    const f = fixture("installed", changes);
    assert.equal((await f.run()).historicalOnly, true);
    assert.equal(f.promotion(), null);
  }
});

test("mode or profile mismatches and stale evidence fail closed", async () => {
  for (const changes of [{ verification_policy: "trust" }, { authorization_revision: 2 }, { profile_revision: 2 }, { deployment_profile_ref: "other" }]) {
    await assert.rejects(fixture("installed", changes).run(), { code: "CERTOPS_DEPLOYMENT_RECEIPT_MISMATCH" });
  }
  const f = fixture();
  f.receipt.observedAt = new Date(Date.now() - 3600000).toISOString();
  await assert.rejects(f.run(), { code: "CERTOPS_DEPLOYMENT_EVIDENCE_STALE" });
});
