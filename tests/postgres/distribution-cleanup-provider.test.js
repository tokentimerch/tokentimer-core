"use strict";

// Run only through the owned-container acceptance runner. No inherited lab,
// customer endpoint, credential, or production capability is accepted here.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { fork } = require("node:child_process");
assert.equal(process.env.TT_CLEANUP_COMPLETION_DISPOSABLE, "1");
assert.equal(process.env.NODE_ENV, "test");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.match(process.env.DB_NAME || "", /^distribution_lifecycle_[a-f0-9]+_test$/);
assert.match(process.env.TT_CLEANUP_VAULT_ADDRESS || "", /^http:\/\/127\.0\.0\.1:\d+$/);

const { pool } = require("../../apps/api/db/database");
const { fixture } = require("../helpers/distribution-lifecycle-fixture.cjs");
const operations = require("../../apps/api/services/certops/distributionOperations");
const lifecycle = require("../../apps/api/services/certops/distributionLifecycle");
const cleanup = require("../../apps/api/services/certops/materialCleanup");
const signing = require("../../apps/api/services/certops/jobSigning");
const { approveJob } = require("../../apps/api/services/certops/jobApprovals");
const { generateAgentCredential } = require("../../apps/api/services/certops/agentCredentials");
const { executeMaterialCleanup } = require("../../packages/agent/src/material-store/cleanup");
const { applyRestrictivePermissions } = require("../../packages/agent/src/platform");
const request = require("supertest");
const vaultAddress = process.env.TT_CLEANUP_VAULT_ADDRESS;
const rootToken = "isolated-completion-fixture-only";
const provider = process.env.TT_CLEANUP_PROVIDER || "vault-kv2";
assert.ok(["vault-kv2", "openbao-kv2"].includes(provider));

test.after(() => pool.end());

function waitMessage(child, type) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { cleanup(); reject(new Error(`Fixture API ${type} timeout`)); }, 15000);
    const message = value => { if (value?.type === type) { cleanup(); resolve(value); } };
    const exit = () => { cleanup(); reject(new Error("Fixture API exited unexpectedly")); };
    function cleanup() { clearTimeout(timer); child.off("message", message); child.off("exit", exit); }
    child.on("message", message); child.once("exit", exit);
  });
}
async function startApi() {
  const child = fork(path.join(__dirname, "../helpers/cleanup-agent-api.cjs"), [], { env: process.env, windowsHide: true, stdio: ["ignore", "ignore", "ignore", "ipc"] });
  const ready = await waitMessage(child, "ready");
  return { child, url: `http://127.0.0.1:${ready.port}` };
}
async function stopApi(api) {
  if (!api || api.child.exitCode !== null) return;
  await new Promise(resolve => { api.child.once("exit", resolve); api.child.kill(); });
}

async function vault(url, method = "GET", body, token = rootToken) {
  const response = await fetch(`${vaultAddress}/v1${url}`, {
    method,
    headers: { "X-Vault-Token": token, "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  return response;
}

async function setup(t) {
  const f = await fixture({ materialProvider: provider });
  const credential = generateAgentCredential();
  await pool.query(`UPDATE certops_agents SET credential_prefix=$2,credential_hash=$3,
    declared_capabilities=declared_capabilities||$5::jsonb,
    supported_operations=supported_operations||'["cleanup-from-store"]'::jsonb,
    declared_target_selectors=declared_target_selectors||$4::jsonb WHERE id=$1`,
  [f.issuer, credential.credentialPrefix, credential.credentialHash, JSON.stringify([f.groupId]), JSON.stringify([`material-cleanup-${provider}-v1`])]);
  const group = (await pool.query("SELECT * FROM certops_distribution_groups WHERE id=$1", [f.groupId])).rows[0];
  const old = [];
  for (let n = 0; n < 3; n++) {
    const id = crypto.randomUUID();
    const job = (await pool.query(`INSERT INTO certificate_jobs(workspace_id,operation,status,source,
      subject_type,subject_id,assigned_agent_id,management_period_id) VALUES($1,'renew','succeeded','api',
      'managed_certificate',$2,$3,$4) RETURNING id`, [f.workspaceId, f.certificateId, f.issuer, group.management_period_id])).rows[0];
    await pool.query(`INSERT INTO certops_material_versions(id,workspace_id,group_id,management_period_id,
      publishing_job_id,profile_revision,state,provider_version,certificate_identity_id,fingerprint_sha256,
      valid_to,published_at,publishing_claim_id,created_at)
      VALUES($1,$2,$3,$4,$5,1,'published',1,$6,$7,clock_timestamp()+interval '30 days',
      clock_timestamp()-($8*interval '1 day'),$9,clock_timestamp()-($8*interval '1 day'))`,
    [id, f.workspaceId, f.groupId, group.management_period_id, job.id, f.identity, f.fingerprint, 100 + n, crypto.randomUUID()]);
    old.push(id);
  }
  const policy = structuredClone(lifecycle.DEFAULT_POLICY);
  Object.assign(policy.retention, { minimumSeconds: 0, minimumVersions: 2, rollbackSeconds: 0, cleanupEnabled: true, reportOnly: false });
  const saved = await lifecycle.putPolicy({ ...f, policy, expectedRevision: 0, actorUserId: f.actor });
  const requested = await cleanup.requestCleanup({ ...f, materialVersionId: old[2], expectedRevision: saved.revision, actorUserId: f.actor });
  await approveJob({ workspaceId: f.workspaceId, jobId: requested.jobId, approverUserId: f.approver });
  const agentRow = (await pool.query("SELECT * FROM certops_agents WHERE id=$1", [f.issuer])).rows[0];
  const agent = { id: f.issuer, workspaceId: f.workspaceId, agentId: agentRow.agent_id, agentVersion: agentRow.agent_version, protocolVersion: agentRow.protocol_version, status: "active" };
  let api = await startApi();
  t.after(() => stopApi(api));
  const restartApi = async () => { await stopApi(api); api = await startApi(); };
  const interruptResponse = async () => {
    const armed = waitMessage(api.child, "armed");
    api.child.send({ type: "interrupt-next-result" });
    await armed;
  };
  let sequence = 0;
  const send = (route, messageType, body) => request(api.url).post(`/api/v1/certops/agent/${route}`)
    .set("Authorization", `Bearer ${credential.plaintextCredential}`).send({ schemaVersion: 1, protocolVersion: "1.0.0", agentId: agent.agentId,
      sentAt: new Date().toISOString(), messageType, sequence: ++sequence, body });
  const claim = async () => {
    const response = await send("jobs/claim", "claim", { maxJobs: 1, supportedActions: ["cleanup-from-store"] });
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert.equal(response.body.jobs.length, 1);
    const pin = await signing.getActiveSigningKeyPublicInfo();
    const verified = require("../../packages/agent/src/signing").verifyJobEnvelope({ claimed: response.body.jobs[0], publicKeyPem: pin.publicKeyPem, pinnedSigningKeyId: pin.signingKeyId });
    assert.equal(verified.allowed, true);
    return verified.job;
  };
  await signing.ensureActiveSigningKey();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "tt-cleanup-completion-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const prefix = `${f.workspaceId}/${f.groupId}`, object = `${prefix}/bundles/${old[2]}`;
  for (let n = 0; n < 2; n++) assert.equal((await vault(`/secret/data/${object}`, "POST", { data: { fixture: "disposable-public-test-value" } })).status, 200);
  const policyName = `completion-${crypto.randomBytes(8).toString("hex")}`;
  const setDeletePermission = async allowed => {
    assert.equal((await vault(`/sys/policies/acl/${policyName}`, "PUT", { policy:
      `path "secret/metadata/${object}" { capabilities = ["read"] }\npath "secret/delete/${object}" { capabilities = ["${allowed ? "update" : "deny"}"] }` })).status, 204);
  };
  await setDeletePermission(true);
  const tokenResponse = await vault("/auth/token/create", "POST", { policies: [policyName], no_default_policy: true, ttl: "15m" });
  assert.equal(tokenResponse.status, 200);
  const cleanupToken = (await tokenResponse.json()).auth.client_token;
  const tokenFile = path.join(directory, "cleanup-token");
  fs.writeFileSync(tokenFile, cleanupToken, { mode: 0o600 });
  applyRestrictivePermissions(tokenFile);
  const stores = { customer: { provider, address: vaultAddress, mount: "secret", tokenFile: path.join(directory, "never-read-publication-token"),
    groups: { [f.groupId]: { workspaceId: f.workspaceId, prefix, sans: ["shared.example.test"], keyAlgorithm: "rsa",
      cleanup: { softDelete: true, profileRevision: 1, minimumSeconds: 0, tokenFile } } } } };
  const stateDir = path.join(directory, "state");
  const readback = async () => (await (await vault(`/secret/metadata/${object}`)).json()).data;
  const execute = job => executeMaterialCleanup({ job, stores, stateDir, fixtureLoopbackHttp: true,
    checkLease: async () => {
      const live = await pool.query("SELECT 1 FROM certificate_jobs WHERE id=$1 AND claim_id=$2 AND lease_expires_at>clock_timestamp()", [job.jobId, job.claimId]);
      if (!live.rowCount) throw Object.assign(new Error("material_lease_unavailable"), { code: "material_lease_unavailable" });
    } });
  const report = (job, outcome) => send("jobs/results", "result", { jobId: job.jobId, claimId: job.claimId, attemptId: job.claimId, nonce: job.nonce, ...outcome });
  return { ...f, ...requested, old, agent, claim, execute, report, readback, setDeletePermission, object, cleanupToken, stateDir, send, restartApi, interruptResponse };
}

async function assertCompleted(f) {
  const job = (await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0];
  const row = (await pool.query("SELECT * FROM certops_material_cleanups WHERE id=$1", [f.cleanupId])).rows[0];
  assert.equal(job.status, "succeeded");
  assert.equal(row.state, "soft_deleted");
  assert.equal(row.receipt.softDeleted, true);
  assert.ok(row.fenced_at && row.completed_at && job.completed_at);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_MATERIAL_CLEANUP_COMPLETED'", [f.workspaceId])).rows[0].n, 1);
  await assert.rejects(pool.query("UPDATE certops_material_cleanups SET state='planned' WHERE id=$1", [f.cleanupId]), { code: "23514" });
  await assert.rejects(operations.requestRollout({ ...f, materialVersionId: f.old[2], actorUserId: f.actor }), { code: "CERTOPS_ROLLOUT_VERSION_INVALID" });
}

test(`real ${provider} policy denial, original-intent retry, signed dispatch and HTTP completion preserve the exact-version fence`, async t => {
  const f = await setup(t);
  await f.setDeletePermission(false);
  const first = await f.claim();
  const denied = await f.execute(first);
  assert.equal(denied.status, "orphaned_unknown_effect");
  assert.equal((await f.readback()).versions["1"].deletion_time, "");
  assert.equal((await f.report(first, denied)).status, 200);
  await f.setDeletePermission(true);
  await operations.retryDistributionJob({ workspaceId: f.workspaceId, jobId: f.jobId, actorUserId: f.actor });
  const job = await f.claim();
  assert.deepEqual(job.materialCleanup, first.materialCleanup);
  const result = await f.execute(job);
  assert.equal(result.status, "succeeded");
  const metadata = await f.readback();
  assert.ok(Date.parse(metadata.versions["1"].deletion_time) <= Date.now());
  assert.equal(metadata.versions["1"].destroyed, false);
  assert.equal(metadata.versions["2"].deletion_time, "");
  assert.equal((await vault(`/secret/data/${f.object}?version=2`, "GET", undefined, f.cleanupToken)).status, 403);
  assert.equal((await vault(`/secret/destroy/${f.object}`, "POST", { versions: [1] }, f.cleanupToken)).status, 403);
  await f.interruptResponse();
  await assert.rejects(f.report(job, result), error => /socket|reset|aborted/i.test(error.message));
  await assertCompleted(f);
  await f.restartApi();
  const duplicate = await f.report(job, result);
  assert.equal(duplicate.status, 200);
  assert.equal(duplicate.body.duplicate, true);
  const contradictory = await f.report(job, { ...result, cleanupReceipt: { ...result.cleanupReceipt, providerVersion: 2 } });
  assert.equal(contradictory.status, 409);
  assert.equal(contradictory.body.code, "CERTOPS_MATERIAL_CLEANUP_RECEIPT_MISMATCH");
  const missing = await f.report(job, { status: "succeeded" });
  assert.equal(missing.status, 422);
  await assertCompleted(f);
  if (process.env.TT_CLEANUP_EVIDENCE_DIR) fs.writeFileSync(path.join(process.env.TT_CLEANUP_EVIDENCE_DIR, "provider-completion.json"),
    JSON.stringify({ workspaceId: f.workspaceId, jobId: f.jobId, cleanupId: f.cleanupId, materialVersionId: f.old[2],
      provider, providerVersion: 1, providerMetadata: metadata, jobState: "succeeded", cleanupState: "soft_deleted",
      permanentFence: "verified", auditCount: 1, interruptedAcknowledgement: "recovered-after-api-process-restart", duplicateStatus: duplicate.status,
      contradictoryReceiptStatus: contradictory.status, missingReceiptStatus: missing.status }, null, 2) + "\n");
});

test(`real ${provider} deletion survives executor restart and receipt rejection without repeating mutation`, async t => {
  const f = await setup(t), job = await f.claim();
  const outcome = await f.execute(job);
  assert.equal(outcome.status, "succeeded");
  const deletedAt = (await f.readback()).versions["1"].deletion_time;
  await f.restartApi();
  // A new executor invocation restores its persisted journal and reads metadata.
  await f.setDeletePermission(false);
  const recovered = await f.execute(job);
  assert.equal(recovered.status, "succeeded");
  assert.equal((await f.readback()).versions["1"].deletion_time, deletedAt);
  const invalid = await f.report(job, { ...recovered, cleanupReceipt: { ...recovered.cleanupReceipt, materialVersionId: f.materialVersionId } });
  assert.equal(invalid.status, 409, JSON.stringify(invalid.body));
  assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [f.jobId])).rows[0].status, "claimed");
  const valid = await f.report(job, recovered);
  assert.equal(valid.status, 200, JSON.stringify(valid.body));
  await assertCompleted(f);
});
