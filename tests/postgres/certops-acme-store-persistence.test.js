"use strict";
const { before, after, test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID, randomBytes } = require("node:crypto");
const { spawnSync } = require("node:child_process");
let pool, container, persistence;
const name = "tt-acme-store-" + randomUUID();
function docker(args) { const r = spawnSync("docker", args, { encoding: "utf8", timeout: 120000 }); assert.equal(r.status, 0, r.stderr || String(r.error)); return r.stdout.trim(); }
before(async () => {
  container = docker(["run", "-d", "--name", name, "--label", "tokentimer.test=acme-store-persistence", "--memory=512m", "--cpus=2", "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=acme_test", "-e", "POSTGRES_PASSWORD=isolated-acme-only", "-e", "POSTGRES_DB=certops_acme_ci_test", "postgres:16-alpine"]);
  const port = JSON.parse(docker(["inspect", container]))[0].NetworkSettings.Ports["5432/tcp"][0].HostPort;
  let ready = false;
  for (let i = 0; i < 240; i++) { if (spawnSync("docker", ["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "acme_test"], { timeout: 10000 }).status === 0) { ready = true; break; } await new Promise(resolve => setTimeout(resolve, 250)); }
  assert.ok(ready);
  Object.assign(process.env, { NODE_ENV: "test", CERTOPS_ENABLED: "true", CERTOPS_SIGNING_ENCRYPTION_KEY: randomBytes(32).toString("hex"), DB_HOST: "127.0.0.1", DB_PORT: port, DB_NAME: "certops_acme_ci_test", DB_USER: "acme_test", DB_PASSWORD: "isolated-acme-only" });
  const migration = spawnSync(process.execPath, ["apps/api/migrations/migrate.js"], { encoding: "utf8", timeout: 120000, env: process.env });
  assert.equal(migration.status, 0, migration.stderr || String(migration.error));
  ({ pool } = require("../../apps/api/db/database"));
  persistence = require("../../apps/api/services/certops/acmeStorePersistence");
}, { timeout: 180000 });
after(async () => {
  if (pool) await pool.end();
  if (container) { const info = JSON.parse(docker(["inspect", container]))[0]; assert.equal(info.Name, "/" + name); assert.equal(info.Config.Labels["tokentimer.test"], "acme-store-persistence"); docker(["rm", "--force", "--volumes", container]); }
});

test("persisted ACME state accepts only the current owner claim and idempotent receipts", async () => {
  const user = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'ACME','x','local',true) RETURNING id", [randomUUID() + "@example.test"])).rows[0].id;
  const workspaceId = randomUUID(), certificateId = randomUUID(), agentId = randomUUID(), otherAgent = randomUUID(), jobId = randomUUID(), claimId = randomUUID(), enrollmentId = randomUUID();
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'ACME',$2,'oss')", [workspaceId, user]);
  await pool.query("INSERT INTO managed_certificates(id,workspace_id,common_name) VALUES($1,$2,'app.example.com')", [certificateId, workspaceId]);
  const agentPublicId = "one-" + randomUUID();
  for (const [agent, publicId] of [[agentId, agentPublicId], [otherAgent, "two-" + randomUUID()]]) await pool.query("INSERT INTO certops_agents(id,workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status) VALUES($1,$2,$3,'ACME','1','1.0.0',$4,$5,'active')", [agent, workspaceId, publicId, "ttagent_" + randomBytes(8).toString("hex"), randomBytes(32).toString("hex")]);
  await pool.query("UPDATE managed_certificates SET status='provisioning',source='agent_issuance',key_mode='os-store-managed',deployed_agent_id=$2 WHERE id=$1", [certificateId, agentId]);
  const target = { type: "windows-cert-store", reference: "app.example.com", store: "My" };
  const payload = { target, caEndpoint: "https://acme.example.com/directory", commandRef: "certbot-csr", dnsProvider: "provider", dnsZone: "example.com", sans: ["app.example.com"], keyAlgorithm: "rsa", keySize: 2048 };
  await pool.query("INSERT INTO certificate_jobs(id,workspace_id,subject_type,subject_id,operation,status,assigned_agent_id,claimed_by_agent_id,claim_id,lease_expires_at,payload) VALUES($1,$2,'managed_certificate',$3,'issue','running',$4,$4,$5,NOW()+INTERVAL '5 minutes',$6::jsonb)", [jobId, workspaceId, certificateId, agentId, claimId, JSON.stringify(payload)]);
  const request = { workspaceId, certificateId, agentId, agentPublicId, jobId, target, caEndpoint: payload.caEndpoint, commandRef: payload.commandRef,
    dnsProvider: payload.dnsProvider, dnsZone: payload.dnsZone, dnsNames: payload.sans, keyAlgorithm: "rsa-2048", acmeKind: "certbot", issuanceMode: "issue", predecessorFingerprintSha256: null };
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const created = await persistence.createAcmeStoreEnrollmentTx({ client, enrollmentId, request });
    const binding = await persistence.loadAcmeStoreBindingTx({ client, workspaceId, jobId, agentId });
    assert.equal(binding.enrollmentId, enrollmentId); assert.equal(binding.requestSha256, created.requestSha256);
    await assert.rejects(persistence.loadAcmeStoreBindingTx({ client, workspaceId, jobId, agentId: otherAgent }));
    const containerName = require("../../apps/api/services/certops/acmeStoreContract").containerForJob(jobId);
    const evidence = { agentId, jobId, enrollmentId, claimId, containerName, requestSha256: created.requestSha256, state: "prepared", csrSha256: "a".repeat(64), csrSpkiSha256: "b".repeat(64) };
    const receiptId = randomUUID(), params = { client, workspaceId, enrollmentId, authenticatedAgentRowId: agentId, claimId, receiptId, evidence };
    assert.deepEqual(await persistence.applyAcmeStoreReceiptTx(params), { replayed: false, state: "prepared" });
    assert.deepEqual(await persistence.applyAcmeStoreReceiptTx(params), { replayed: true, state: "prepared" });
    await assert.rejects(persistence.applyAcmeStoreReceiptTx({ ...params, evidence: { ...evidence, csrSha256: "c".repeat(64) } }));
    await assert.rejects(persistence.applyAcmeStoreReceiptTx({ ...params, authenticatedAgentRowId: otherAgent }));
    await assert.rejects(persistence.applyAcmeStoreReceiptTx({ ...params, claimId: randomUUID() }));
    const newClaimId = randomUUID();
    await client.query("UPDATE certificate_jobs SET claim_id=$2 WHERE id=$1", [jobId, newClaimId]);
    await assert.rejects(persistence.applyAcmeStoreReceiptTx(params));
    assert.deepEqual(await persistence.applyAcmeStoreReceiptTx({ ...params, claimId: newClaimId, evidence: { ...evidence, claimId: newClaimId } }), { replayed: true, state: "prepared" });
    await client.query("UPDATE certificate_jobs SET claim_id=$2 WHERE id=$1", [jobId, claimId]);
    const record = (state, fields) => persistence.applyAcmeStoreReceiptTx({ ...params, receiptId: randomUUID(), evidence: { ...evidence, state, ...fields } });
    const spki = "b".repeat(64), fingerprint = "c".repeat(64);
    await record("submitting", { csrSpkiSha256: spki });
    await assert.rejects(record("issued", { csrSpkiSha256: spki, leafSpkiSha256: "d".repeat(64), fingerprintSha256: fingerprint }));
    await record("issued", { csrSpkiSha256: spki, leafSpkiSha256: spki, fingerprintSha256: fingerprint });
    await record("installing", { csrSpkiSha256: spki, fingerprintSha256: fingerprint });
    const proof = { csrSpkiSha256: spki, fingerprintSha256: fingerprint, store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true };
    await assert.rejects(record("installed", { ...proof, machineKey: false }));
    await record("installed", proof);
    await client.query("COMMIT");
  } catch (error) { await client.query("ROLLBACK"); throw error; }
  finally { client.release(); }
  const stored = (await pool.query("SELECT state,csr_sha256 FROM certops_acme_store_enrollments WHERE id=$1", [enrollmentId])).rows[0];
  assert.equal(stored.state, "installed"); assert.equal(stored.csr_sha256, "a".repeat(64));
  // Authentication and ingestion are distinct moments. A credential rotated
  // or retired between them must never write evidence or advance sequence.
  const { bindAuthenticatedCredential } = require("../../apps/api/services/certops/agentCredentialFence");
  const { persistAgentJobEvidenceBatch } = require("../../apps/api/services/certops/agentObservations");
  const raw = "temporary-test-credential", digest = require("node:crypto").createHash("sha256").update(raw).digest("hex");
  await pool.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1", [agentId, digest]);
  const authenticated = bindAuthenticatedCredential({ id: agentId, workspaceId, agentId: agentPublicId, status: "active" }, raw);
  let advanced = false;
  const batch = { dbPool: pool, agent: authenticated, envelope: {}, jobId, claimId,
    evidenceItems: [{ evidenceId: "race-test", eventType: "validation.passed", observedAt: new Date().toISOString() }],
    deps: { enforceAgentSequence: async () => { advanced = true; }, assertEvidenceClaimOwnership: async () => ({ claimId }),
      createCertificateEvidence: async () => { throw new Error("must not persist"); } } };
  await pool.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1", [agentId, "f".repeat(64)]);
  await assert.rejects(persistAgentJobEvidenceBatch(batch), { code: "CERTOPS_AGENT_CREDENTIAL_STALE" });
  await pool.query("UPDATE certops_agents SET credential_hash=$2,status='retired',retired_at=NOW() WHERE id=$1", [agentId, digest]);
  await assert.rejects(persistAgentJobEvidenceBatch(batch), { code: "CERTOPS_AGENT_RETIRED" });
  assert.equal(advanced, false);
}, { timeout: 120000 });

test("internal ACME store first issue atomically binds owner, enrollment and replay", async () => {
  const user = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'ACME','x','local',true) RETURNING id", [randomUUID() + "@example.test"])).rows[0].id;
  const workspaceId = randomUUID(), agentId = randomUUID();
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'ACME',$2,'oss')", [workspaceId, user]);
  await pool.query(`INSERT INTO certops_agents(id,workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,declared_target_selectors,declared_capabilities,capabilities_updated_at)
    VALUES($1,$2,$3,'ACME','0.18.0','1.0.0',$4,$5,'active','win32',$6::jsonb,$7::jsonb,NOW())`,
  [agentId, workspaceId, "agent-" + randomUUID(), "ttagent_" + randomBytes(8).toString("hex"), randomBytes(32).toString("hex"), JSON.stringify(["app.example.com"]), JSON.stringify(["windows-store-only-acme-v1", "evidence-claim-binding-v1"])]);
  const issue = require("../../apps/api/services/certops/issuance").createCertificateIssuanceJob;
  const options = { workspaceId, assignedAgentId: agentId, idempotencyKey: randomUUID(), operation: "issue", source: "api", mode: "real", requestedByUserId: user,
    transactionOwned: true, payload: { target: { type: "windows-cert-store", reference: "app.example.com", store: "My" },
      caEndpoint: "https://acme.example.com/directory", commandRef: "certbot-csr", dnsProvider: "provider", dnsZone: "example.com", keyAlgorithm: "rsa", keySize: 2048, accountRef: "account-main" } };
  const run = async () => { const client = await pool.connect(); try { await client.query("BEGIN"); const result = await issue({ ...options, client }); await client.query("COMMIT"); return result; } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); } };
  const first = await run();
  assert.equal(first.created, true);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM certops_acme_store_enrollments WHERE original_job_id=$1", [first.job.id])).rows[0].n, 1);
  await pool.query("UPDATE certops_agents SET capabilities_updated_at=NOW()-INTERVAL '2 days' WHERE id=$1", [agentId]);
  const replay = await run();
  assert.equal(replay.created, false);
  assert.equal(replay.job.id, first.job.id);
  await pool.query("UPDATE certops_agents SET capabilities_updated_at=NOW() WHERE id=$1", [agentId]);
  const approvedOptions = { ...options, idempotencyKey: randomUUID(), requiresApproval: true };
  const approved = await (async () => { const client = await pool.connect(); try { await client.query("BEGIN");
    const result = await issue({ ...approvedOptions, client }); await client.query("COMMIT"); return result;
  } catch (error) { await client.query("ROLLBACK"); throw error; } finally { client.release(); } })();
  const approver = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'Approver','x','local',true) RETURNING id", [randomUUID() + "@example.test"])).rows[0].id;
  await require("../../apps/api/services/certops/jobApprovals").approveJob({ workspaceId, jobId: approved.job.id, approverUserId: approver });
  assert.equal((await pool.query("SELECT status FROM certificate_jobs WHERE id=$1", [approved.job.id])).rows[0].status, "pending");
  const raw = randomBytes(32).toString("hex");
  const agentPublic = (await pool.query(`UPDATE certops_agents SET credential_hash=$2,declared_command_profile_names=$3::jsonb,
    supported_dns_providers=$4::jsonb WHERE id=$1 RETURNING agent_id`, [agentId, require("node:crypto").createHash("sha256").update(raw).digest("hex"),
    JSON.stringify(["certbot-csr"]), JSON.stringify(["provider"])])).rows[0].agent_id;
  const agent = require("../../apps/api/services/certops/agentCredentialFence").bindAuthenticatedCredential({ id: agentId, workspaceId,
    agentId: agentPublic, status: "active", platform: "win32", protocolVersion: "1.0.0", agentVersion: "0.18.1" }, raw);
  const claims = await require("../../apps/api/services/certops/agentDispatch").claimJobs({ dbPool: pool, agent,
    body: { maxJobs: 16, supportedActions: ["renew"], supportedDnsProviders: ["provider"] },
    deps: { enforceAgentSequence: async () => {}, signJobForDispatch: async ({ job }) => job } });
  assert.ok(claims.jobs.some(job => job.jobId === approved.job.id), "the approved frozen ACME enrollment is claimable");
  // Synthetic installed predecessor: this exercises server admission only.
  const target = options.payload.target;
  await pool.query("UPDATE certops_agents SET capabilities_updated_at=NOW() WHERE id=$1", [agentId]);
  await pool.query("UPDATE certificate_jobs SET status='succeeded' WHERE id=$1", [first.job.id]);
  await pool.query("UPDATE certops_acme_store_enrollments SET state='installed' WHERE original_job_id=$1", [first.job.id]);
  await pool.query("UPDATE managed_certificates SET status='active',fingerprint_sha256=$2,not_after=NOW()+interval '10 days' WHERE id=$1", [first.job.subjectId, randomBytes(32).toString("hex")]);
  const derived = await require("../../apps/api/services/certops/renewalProfileDerivation").ensureDerivedRenewalProfile({
    client: pool, workspaceId, certificateId: first.job.subjectId, jobId: first.job.id,
    payload: first.job.payload, certificate: { commonName: target.reference, subjectAltNames: [target.reference] }, operation: "issue" });
  assert.ok(derived.profileId, `ACME store profile must derive: ${derived.reason}`);
  const derivedRow = (await pool.query("SELECT key_mode,public_metadata FROM certificate_profiles WHERE id=$1", [derived.profileId])).rows[0];
  assert.equal(derivedRow.key_mode, "os-store-managed");
  assert.equal(derivedRow.public_metadata.renewalProfile.ca.accountRef, "account-main");
  assert.deepEqual(derivedRow.public_metadata.renewalProfile.deploymentTargets, []);
  assert.equal((await pool.query("SELECT automation_enabled FROM certops_management_periods WHERE managed_certificate_id=$1 AND ended_at IS NULL", [first.job.subjectId])).rows[0].automation_enabled, false);
  const renew = require("../../apps/api/services/certops/jobs").manualRenewalJobCreator({ certificateId: first.job.subjectId });
  const renewalOptions = { workspaceId, subjectId: first.job.subjectId, assignedAgentId: agentId, idempotencyKey: randomUUID(),
    operation: "renew", source: "api", mode: "real", requestedByUserId: user, transactionOwned: true, payload: {} };
  const runRenewal = async (changes = {}) => { const client = await pool.connect(); try { await client.query("BEGIN"); const result = await renew({ ...renewalOptions, ...changes, client }); await client.query("COMMIT"); return result; } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); } };
  await assert.rejects(runRenewal({ assignedAgentId: randomUUID() }), /owned by the selected agent/);
  await assert.rejects(runRenewal({ idempotencyKey: undefined }), {
    code: "CERTOPS_ACME_STORE_INVALID",
  });
  const renewed = await runRenewal();
  assert.equal(renewed.created, true);
  const binding = (await pool.query("SELECT request_bytes FROM certops_acme_store_enrollments WHERE original_job_id=$1", [renewed.job.id])).rows[0];
  assert.equal(JSON.parse(binding.request_bytes.toString("utf8")).predecessorFingerprintSha256.length, 64);
  assert.equal(JSON.parse(binding.request_bytes.toString("utf8")).eabAccountRef, "account-main");
  assert.equal((await runRenewal()).created, false);
  await pool.query("UPDATE certops_agents SET capabilities_updated_at=NOW()-interval '2 days' WHERE id=$1", [agentId]);
  await assert.rejects(runRenewal({ idempotencyKey: randomUUID() }), {
    code: "CERTOPS_ACME_STORE_ORDER_UNCERTAIN",
    message: /already open or uncertain/,
  });
});


async function createRecoveryFixture() {
  const user = (await pool.query("INSERT INTO users(email,email_original,display_name,password_hash,auth_method,email_verified) VALUES($1::text,$1::text,'ACME','x','local',true) RETURNING id", [randomUUID() + "@example.test"])).rows[0].id;
  const workspaceId = randomUUID(), agentId = randomUUID(), otherAgentId = randomUUID();
  await pool.query("INSERT INTO workspaces(id,name,created_by,plan) VALUES($1,'ACME',$2,'oss')", [workspaceId, user]);
  for (const agent of [agentId, otherAgentId]) await pool.query(`INSERT INTO certops_agents(id,workspace_id,agent_id,name,agent_version,protocol_version,credential_prefix,credential_hash,status,platform,declared_target_selectors,declared_capabilities,capabilities_updated_at)
    VALUES($1,$2,$3,'ACME','0.18.0','1.0.0',$4,$5,'active','win32',$6::jsonb,$7::jsonb,NOW())`,
    [agent, workspaceId, "agent-" + randomUUID(), "ttagent_" + randomBytes(8).toString("hex"), randomBytes(32).toString("hex"), JSON.stringify(["app.example.com"]), JSON.stringify(["windows-store-only-acme-v1", "evidence-claim-binding-v1"])]);
  const issue = require("../../apps/api/services/certops/acmeStoreIssuance").createAcmeStoreIssueTx;
  const tx = async fn => { const client = await pool.connect(); try { await client.query("BEGIN"); const value = await fn(client); await client.query("COMMIT"); return value; } catch(e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); } };
  const first = await tx(client => issue({ client, workspaceId, assignedAgentId: agentId, idempotencyKey: randomUUID(), operation: "issue", source: "api", mode: "real", requestedByUserId: user, transactionOwned: true,
    payload: { target: { type: "windows-cert-store", reference: "app.example.com", store: "My" }, caEndpoint: "https://acme.example.com/directory", commandRef: "certbot-csr", dnsProvider: "provider", dnsZone: "example.com", keyAlgorithm: "rsa", keySize: 2048 } }));
  const enrollment = (await pool.query("SELECT * FROM certops_acme_store_enrollments WHERE original_job_id=$1", [first.job.id])).rows[0];
  const options = { workspaceId, enrollmentId: enrollment.id, orphanedJobId: first.job.id, actorUserId: user, reason: "Inspect the original order", acknowledgeUnknownEffect: true };
  const recover = overrides => tx(client => persistence.continueAcmeStoreEnrollmentTx({ client, ...options, ...overrides }));
  return { workspaceId, agentId, otherAgentId, user, first, enrollment, tx, recover };
}

test("orphan continuation is acknowledged, atomic and pinned to the original owner", async () => {
  const { workspaceId, agentId, otherAgentId, first, enrollment, tx, recover } = await createRecoveryFixture();
  const originalClaim = randomUUID(), receiptId = randomUUID();
  await pool.query("UPDATE certificate_jobs SET status='running',claim_id=$2,claimed_by_agent_id=$3,lease_expires_at=NOW()+interval '5 minutes' WHERE id=$1", [first.job.id, originalClaim, agentId]);
  const evidence = { agentId, jobId: first.job.id, enrollmentId: enrollment.id, claimId: originalClaim, containerName: enrollment.container_name,
    requestSha256: enrollment.request_sha256, state: "prepared", csrSha256: "a".repeat(64), csrSpkiSha256: "b".repeat(64) };
  await tx(client => persistence.applyAcmeStoreReceiptTx({ client, workspaceId, enrollmentId: enrollment.id, authenticatedAgentRowId: agentId, claimId: originalClaim, receiptId, evidence }));
  const leaf = "c".repeat(64), installedReceiptId = randomUUID();
  const stage = async (state, extra, stageId = randomUUID()) => tx(client => persistence.applyAcmeStoreReceiptTx({
    client, workspaceId, enrollmentId: enrollment.id, authenticatedAgentRowId: agentId, claimId: originalClaim,
    receiptId: stageId, evidence: { ...evidence, state, ...extra },
  }));
  await stage("submitting", {});
  await stage("issued", { leafSpkiSha256: evidence.csrSpkiSha256, fingerprintSha256: leaf });
  await stage("installing", { fingerprintSha256: leaf });
  const installedProof = { fingerprintSha256: leaf, store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true };
  await stage("installed", installedProof, installedReceiptId);
  // Model the agent reporting uncertainty after the API received installation
  // evidence. This terminal result retains the original claim.
  await pool.query("UPDATE certificate_jobs SET status='orphaned_unknown_effect',needs_operator_reconciliation=true,lease_expires_at=NULL,completed_at=NOW() WHERE id=$1", [first.job.id]);
  await assert.rejects(recover({ acknowledgeUnknownEffect: false }), /acknowledgement/);
  await assert.rejects(recover({ audit: async () => { throw new Error("audit failed"); } }), /audit failed/);
  assert.equal((await pool.query("SELECT current_job_id FROM certops_acme_store_enrollments WHERE id=$1", [enrollment.id])).rows[0].current_job_id, first.job.id);
  const [one, two] = await Promise.all([recover(), recover()]);
  assert.equal(one.jobId, two.jobId); assert.equal(Number(one.created) + Number(two.created), 1);
  const continuation = (await pool.query("SELECT * FROM certificate_jobs WHERE id=$1", [one.jobId])).rows[0];
  assert.equal(continuation.operation, "continue-enrollment"); assert.equal(continuation.assigned_agent_id, agentId);
  const binding = await tx(client => persistence.loadAcmeStoreBindingTx({ client, workspaceId, jobId: one.jobId, agentId }));
  assert.equal(binding.originalJobId, first.job.id); assert.equal(binding.requestSha256, enrollment.request_sha256);
  await assert.rejects(tx(client => persistence.loadAcmeStoreBindingTx({ client, workspaceId, jobId: one.jobId, agentId: otherAgentId })));
  const rawCredential = randomBytes(32).toString("hex");
  const owner = (await pool.query(`UPDATE certops_agents SET credential_hash=$2,
    declared_command_profile_names=$3::jsonb,supported_dns_providers=$4::jsonb WHERE id=$1 RETURNING agent_id`,
  [agentId, require("node:crypto").createHash("sha256").update(rawCredential).digest("hex"), JSON.stringify(["certbot-csr"]), JSON.stringify(["provider"])] )).rows[0];
  const agent = require("../../apps/api/services/certops/agentCredentialFence").bindAuthenticatedCredential({ id: agentId,
    workspaceId, agentId: owner.agent_id, status: "active", platform: "win32", protocolVersion: "1.0.0", agentVersion: "0.18.1" }, rawCredential);
  const signingKey = await require("../../apps/api/services/certops/jobSigning").ensureActiveSigningKey({ client: pool });
  const canonicalize = require("../../packages/contracts/certops/canonical-json.cjs").canonicalizeJobPayload;
  const lockedJob = { ...continuation, acme_store_bound: true };
  const lockManaged = require("../../apps/api/services/certops/managementClaim").lockManagedJobForClaim;
  assert.equal(await tx(client => lockManaged({ client, workspaceId: randomUUID(), job: lockedJob })), false);
  assert.equal(await tx(client => lockManaged({ client, workspaceId, job: { ...lockedJob, assigned_agent_id: otherAgentId } })), false);
  const claimed = await require("../../apps/api/services/certops/agentDispatch").claimJobs({ dbPool: pool, agent,
    body: { maxJobs: 1, supportedActions: ["continue-enrollment"], supportedDnsProviders: ["provider"] }, env: { CERTOPS_ENABLED: "true" },
    deps: { enforceAgentSequence: async () => {} } });
  assert.equal(claimed.jobs.length, 1, "original agent claims the bound continuation");
  const signed = claimed.jobs[0], { signature, ...signedBody } = signed;
  assert.equal(require("node:crypto").verify(null, Buffer.from(canonicalize(signedBody)), signingKey.publicKeyPem, Buffer.from(signature, "base64")), true);
  const schemaResult = require("../../packages/contracts/certops/validate-signed-job.cjs").validateSignedJob(signed);
  assert.equal(schemaResult.valid, true, JSON.stringify(schemaResult.errors));
  const verification = require("../../packages/agent/src/signing").verifyJobEnvelope({ claimed: signed,
    publicKeyPem: signingKey.publicKeyPem, pinnedSigningKeyId: signingKey.signingKeyId });
  assert.equal(verification.allowed, true, verification.detail);
  assert.equal(signed.acmeStoreEnrollment.originalJobId, first.job.id);
  const runtime = require("../../packages/agent/src/issuers/acme-store-journal");
  const decoded = runtime.decodeAcmeStoreDispatch(signed);
  assert.equal(decoded.enrollmentId, enrollment.id);
  let durable = null, mutations = 0;
  const storage = { read: () => durable && structuredClone(durable), write: value => { durable = structuredClone(value); } };
  const lock = { assertHeld() {}, run: fn => fn(new AbortController().signal), release() {} };
  const recoveryArgs = { stateDir: "unused", jobId: decoded.originalJobId, enrollmentId: decoded.enrollmentId,
    agentId: signed.agentId, domains: decoded.snapshot.dnsNames, requestSha256: decoded.requestSha256, storage,
    acquireLock: () => lock, recordContainer: async () => { mutations++; }, generateCsr: async () => { mutations++; },
    submit: async () => { mutations++; }, install: async () => { mutations++; }, reportReceipt: async () => {}, reportIssuance: async () => {}, recoveryOnly: true };
  runtime.prepareStoreEnrollment({ ...recoveryArgs, assertLock() {} });
  const recovered = await runtime.runAcmeStoreOperation(recoveryArgs);
  assert.equal(recovered.outcome, "uncertain");
  assert.equal(mutations, 0, "uncertain continuation never creates a key or submits an order");
  const newClaim = randomUUID();
  await pool.query("UPDATE certificate_jobs SET status='running',claim_id=$2,claimed_by_agent_id=$3,lease_expires_at=NOW()+interval '5 minutes' WHERE id=$1", [one.jobId, newClaim, agentId]);
  const replay = await tx(client => persistence.applyAcmeStoreReceiptTx({ client, workspaceId, enrollmentId: enrollment.id, authenticatedAgentRowId: agentId, claimId: newClaim, receiptId, evidence: { ...evidence, jobId: one.jobId, claimId: newClaim } }));
  assert.equal(replay.replayed, true);
  const installedReplay = await tx(client => persistence.applyAcmeStoreReceiptTx({ client, workspaceId, enrollmentId: enrollment.id,
    authenticatedAgentRowId: agentId, claimId: newClaim, receiptId: installedReceiptId,
    evidence: { ...evidence, state: "installed", ...installedProof, jobId: one.jobId, claimId: newClaim } }));
  assert.equal(installedReplay.replayed, true);
  await pool.query("UPDATE certificate_jobs SET payload=jsonb_set(payload,'{dnsZone}', '\"changed.example\"'::jsonb) WHERE id=$1", [one.jobId]);
  await assert.rejects(tx(client => persistence.loadAcmeStoreBindingTx({ client, workspaceId, jobId: one.jobId, agentId })));
  await pool.query("UPDATE certops_agents SET status='retired',retired_at=NOW() WHERE id=$1", [agentId]);
  await assert.rejects(tx(client => persistence.loadAcmeStoreBindingTx({ client, workspaceId, jobId: one.jobId, agentId })));
}, { timeout: 120000 });

test("concurrent operator requests continue a reaped ACME job only once", async t => {
  const { workspaceId, agentId, user, first, enrollment } = await createRecoveryFixture();
  const jobId = first.job.id;
  const lookup = () => persistence.lookupAcmeStoreRecoveryByJob({ client: pool, workspaceId, jobId });
  // Age only this fixture's lease. The worker performs the terminal transition and records its own job log.
  await pool.query(`UPDATE certificate_jobs SET status='running',claim_id=$3,claimed_by_agent_id=$4,attempt_count=1,
    started_at=NOW()-interval '3 hours',lease_renewed_at=NOW()-interval '3 hours',lease_expires_at=NOW()-interval '2 hours'
    WHERE workspace_id=$1 AND id=$2`, [workspaceId, jobId, randomUUID(), agentId]);
  assert.deepEqual(await lookup(), { enrollmentId: enrollment.id, state: "keygen_intent", outcomeUncertain: false, recoveryAvailable: false });
  const { reapExpiredLeases } = await import("../../apps/worker/src/certops-worker.js");
  const client = await pool.connect();
  try {
    assert.deepEqual(await reapExpiredLeases({ client, batchSize: 1 }), { scanned: 1, requeued: 0, failed: 1, deferred: 0 });
  } finally {
    client.release();
  }
  const orphan = await pool.query(`SELECT status,claim_id,claimed_by_agent_id,needs_operator_reconciliation
    FROM certificate_jobs WHERE workspace_id=$1 AND id=$2`, [workspaceId, jobId]);
  assert.deepEqual(orphan.rows, [{ status: "orphaned_unknown_effect", claim_id: null, claimed_by_agent_id: null, needs_operator_reconciliation: true }]);
  assert.deepEqual(await lookup(), { enrollmentId: enrollment.id, state: "keygen_intent", outcomeUncertain: true, recoveryAvailable: true });
  const express = require("../../apps/api/node_modules/express");
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.user = { id: user };
    req.authz = { workspaceRole: "workspace_manager" };
    req.workspace = { id: workspaceId };
    req.isAuthenticated = () => true;
    next();
  });
  app.use(require("../../apps/api/routes/certops-enrollments"));
  const server = await new Promise(resolve => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/api/v1/workspaces/${workspaceId}/certops/acme-store-enrollments/${enrollment.id}/recover`;
  const request = async () => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ orphanedJobId: jobId, reason: "Inspect the original order", acknowledgeUnknownEffect: true }),
    });
    return { status: res.status, body: await res.json() };
  };

  // Hold the workspace lock until both POSTs are waiting in the real route.
  // A shared agent lock followed by an upgrade deadlocks after this release.
  const gate = await pool.connect();
  let requests;
  try {
    await gate.query("BEGIN");
    await gate.query("SELECT id FROM workspaces WHERE id=$1 FOR UPDATE", [workspaceId]);
    requests = Promise.all([request(), request()]);
    const deadline = Date.now() + 10000;
    while (true) {
      const { rows: [{ blocked }] } = await pool.query(`SELECT count(*)::int AS blocked FROM pg_stat_activity
        WHERE datname=current_database() AND wait_event_type='Lock'
          AND (query LIKE '%certops_require_approval_always%' OR query LIKE '%SELECT a.id FROM certops_agents a JOIN certops_acme_store_enrollments e%')`);
      if (blocked === 2) break;
      assert.ok(Date.now() < deadline, "both recovery requests reached PostgreSQL");
      await new Promise(resolve => setTimeout(resolve, 25));
    }
  } finally {
    await gate.query("ROLLBACK");
    gate.release();
  }
  const [replay, created] = (await requests).sort((left, right) => left.status - right.status);
  assert.deepEqual([replay.status, created.status], [200, 201], JSON.stringify([replay, created]));
  assert.equal(created.body.created, true);
  assert.deepEqual(replay.body, { jobId: created.body.jobId, created: false });
  assert.deepEqual(await lookup(), { enrollmentId: enrollment.id, state: "keygen_intent", outcomeUncertain: true, recoveryAvailable: false });
  const continuations = await pool.query("SELECT id,assigned_agent_id FROM certificate_jobs WHERE workspace_id=$1 AND operation='continue-enrollment'", [workspaceId]);
  assert.deepEqual(continuations.rows, [{ id: created.body.jobId, assigned_agent_id: agentId }]);
});

test("a verified terminal ACME continuation resolves only its historical chain and replays once", async () => {
  const { workspaceId, agentId, first, enrollment, recover, tx } = await createRecoveryFixture();
  const orphan = jobId => pool.query(`UPDATE certificate_jobs SET status='orphaned_unknown_effect',
    claim_id=$2,claimed_by_agent_id=$3,completed_at=NOW(),attempt_count=1,
    needs_operator_reconciliation=TRUE,error_code='effects_unknown' WHERE id=$1`, [jobId, randomUUID(), agentId]);
  await orphan(first.job.id);
  const intermediate = await recover();
  await orphan(intermediate.jobId);
  const continuation = await recover({ orphanedJobId: intermediate.jobId });
  const unrelated = randomUUID();
  await pool.query(`INSERT INTO certificate_jobs(id,workspace_id,subject_type,subject_id,operation,status,
    assigned_agent_id,needs_operator_reconciliation) VALUES($1,$2,'managed_certificate',$3,'renew','orphaned_unknown_effect',$4,TRUE)`,
  [unrelated, workspaceId, first.job.subjectId, agentId]);

  const claimId = randomUUID();
  await pool.query(`UPDATE certificate_jobs SET status='running',claim_id=$2,claimed_by_agent_id=$3,
    attempt_count=1,lease_expires_at=NOW()+interval '5 minutes' WHERE id=$1`, [continuation.jobId, claimId, agentId]);
  const boundEvidence = {
    enrollmentId: enrollment.id, requestSha256: enrollment.request_sha256, containerName: enrollment.container_name,
    csrSha256: "a".repeat(64), csrSpkiSha256: "b".repeat(64),
  };
  const proof = {
    ...boundEvidence, fingerprintSha256: "c".repeat(64),
    store: "LocalMachine\\My", keyPossessionVerified: true, machineKey: true, nonExportable: true,
    validTo: "2029-01-01T00:00:00Z",
  };
  for (const [state, detail] of [
    ["prepared", {}],
    ["submitting", {}],
    ["issued", { fingerprintSha256: proof.fingerprintSha256, leafSpkiSha256: proof.csrSpkiSha256 }],
    ["installing", { fingerprintSha256: proof.fingerprintSha256 }],
    ["installed", { ...proof }],
  ]) {
    await tx(client => persistence.applyAcmeStoreReceiptTx({ client, workspaceId, enrollmentId: enrollment.id,
      authenticatedAgentRowId: agentId, claimId, receiptId: randomUUID(),
      evidence: { ...boundEvidence, agentId, jobId: continuation.jobId, claimId, state, ...detail },
    }));
  }
  await pool.query(`INSERT INTO certificate_evidence(workspace_id,job_id,evidence_type,claim_id,attempt_count,created_by_agent_id,metadata)
    VALUES($1,$2,'validation.passed',$3,1,$4,$5::jsonb)`, [workspaceId, continuation.jobId, claimId, agentId,
    JSON.stringify({ ...proof, step: "acme-store-receipt", state: "installed" })]);

  const rawCredential = randomBytes(32).toString("hex");
  const { rows: [owner] } = await pool.query("UPDATE certops_agents SET credential_hash=$2 WHERE id=$1 RETURNING agent_id",
    [agentId, require("node:crypto").createHash("sha256").update(rawCredential).digest("hex")]);
  const agent = require("../../apps/api/services/certops/agentCredentialFence").bindAuthenticatedCredential({
    id: agentId, agentId: owner.agent_id, workspaceId, status: "active", platform: "win32", protocolVersion: "1.0.0", agentVersion: "0.18.1",
  }, rawCredential);
  const dispatch = require("../../apps/api/services/certops/agentDispatch");
  let duplicate = false;
  const submit = () => dispatch.ingestResult({ dbPool: pool, agent,
    body: { jobId: continuation.jobId, claimId, status: "succeeded", nonce: randomUUID() },
    deps: { enforceAgentSequence: async () => {}, consumeNonce: async () => duplicate
      ? { consumed: false, code: "CERTOPS_NONCE_REPLAYED" } : { consumed: true } },
  });
  await submit();
  const { rows: [certificate] } = await pool.query("SELECT status,fingerprint_sha256 FROM managed_certificates WHERE id=$1", [first.job.subjectId]);
  assert.deepEqual(certificate, { status: "active", fingerprint_sha256: proof.fingerprintSha256 });
  const { rows: historical } = await pool.query(`SELECT id,status,error_code,needs_operator_reconciliation,reconciliation_reason,
    result_metadata->>'reconciliationJobId' AS reconciliation_job_id FROM certificate_jobs WHERE id=ANY($1::uuid[])`,
  [[first.job.id, intermediate.jobId]]);
  assert.equal(historical.length, 2);
  for (const row of historical) {
    assert.equal(row.status, "orphaned_unknown_effect");
    assert.equal(row.error_code, "effects_unknown");
    assert.equal(row.needs_operator_reconciliation, false);
    assert.equal(row.reconciliation_reason, "installation_verified_by_acme_continuation");
    assert.equal(row.reconciliation_job_id, continuation.jobId);
  }
  assert.equal((await pool.query("SELECT needs_operator_reconciliation FROM certificate_jobs WHERE id=$1", [unrelated])).rows[0].needs_operator_reconciliation, true);
  assert.deepEqual(await persistence.lookupAcmeStoreRecoveryByJob({ client: pool, workspaceId, jobId: first.job.id }),
    { enrollmentId: enrollment.id, state: "installed", outcomeUncertain: false, recoveryAvailable: false });
  assert.deepEqual(await recover(), { jobId: intermediate.jobId, created: false });
  assert.deepEqual(await recover({ orphanedJobId: intermediate.jobId }), { jobId: continuation.jobId, created: false });
  duplicate = true;
  assert.equal((await submit()).duplicate, true);
  const { rows: audit } = await pool.query(`SELECT metadata FROM audit_events WHERE workspace_id=$1 AND action='CERTOPS_ACME_STORE_RECOVERY_RECONCILED'`, [workspaceId]);
  assert.deepEqual(audit, [{ metadata: { enrollmentId: enrollment.id, originalJobId: first.job.id, reconciliationJobId: continuation.jobId } }]);
});
