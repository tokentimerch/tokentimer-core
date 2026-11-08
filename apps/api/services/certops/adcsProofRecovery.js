"use strict";

// Transaction-owned recovery primitives. An intent cannot execute CA work;
// dispatch remains dependent on a separately qualified agent capability.
const crypto = require("node:crypto");
const { assertCurrentAgentCredential } = require("./agentCredentialFence");
const { writeAudit } = require("../audit");
const { redactGenericSecrets } = require("../../utils/secretMaterial");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX = /^[a-f0-9]{64}$/;
function fail(message, code = "CERTOPS_ADCS_PROOF_INVALID") { const error = new Error(message); error.code = code; throw error; }
function tx(client) {
  if (!client || typeof client.query !== "function" || (typeof client.connect === "function" && typeof client.idleCount === "number")) fail("transaction client required");
}
function uuid(value) { if (typeof value !== "string" || !UUID.test(value)) fail("invalid proof identity"); }

/** Call only after the same transaction persisted the job-bound evidence. */
async function recordAdcsExpectedIdentityTx({ client, agent, jobId, evidenceId }) {
  tx(client); uuid(jobId); uuid(evidenceId);
  await assertCurrentAgentCredential({ client, agent });
  const job = (await client.query(`SELECT id,enrollment_id,subject_id,subject_type,assigned_agent_id,claimed_by_agent_id,
      claim_id,attempt_count,status,(lease_expires_at > clock_timestamp()) AS claim_live
    FROM certificate_jobs WHERE workspace_id=$1 AND id=$2::uuid FOR UPDATE`, [agent.workspaceId, jobId])).rows[0];
  if (!job || !job.enrollment_id || job.subject_type !== "managed_certificate" ||
      String(job.assigned_agent_id) !== String(agent.id) || String(job.claimed_by_agent_id) !== String(agent.id) ||
      !job.claim_id || !Number.isInteger(job.attempt_count) || job.attempt_count < 1 ||
      !["claimed", "running"].includes(job.status) || job.claim_live !== true) {
    fail("the original agent claim is no longer admissible");
  }
  const enrollment = (await client.query(`SELECT id,agent_id,certificate_id,current_job_id,snapshot_bytes,snapshot_sha256,deploy_target
    FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2::uuid FOR SHARE SKIP LOCKED`, [agent.workspaceId, job.enrollment_id])).rows[0];
  if (!enrollment || String(enrollment.agent_id) !== String(agent.id) || String(enrollment.certificate_id) !== String(job.subject_id) ||
      String(enrollment.current_job_id) !== String(job.id)) fail("enrollment is busy or does not match the claim");
  const bytes = Buffer.from(enrollment.snapshot_bytes);
  const snapshotSha256 = crypto.createHash("sha256").update(bytes).digest("hex");
  if (snapshotSha256 !== enrollment.snapshot_sha256) fail("issuer snapshot digest changed");
  let snapshot;
  try { snapshot = JSON.parse(bytes.toString("utf8")); } catch { fail("issuer snapshot is invalid"); }
  const target = enrollment.deploy_target;
  if (!target || target.type !== "windows-cert-store" || target.store !== "My" ||
      Object.keys(target).some(key => !["type", "reference", "store"].includes(key))) fail("invalid machine-store destination");
  const destinationSha256 = crypto.createHash("sha256").update(JSON.stringify({ type: "windows-cert-store", reference: target.reference, store: "My" })).digest("hex");
  if (snapshot.destinationType !== target.type || snapshot.destinationSha256 !== destinationSha256) fail("destination does not match the frozen snapshot");
  const evidence = (await client.query(`SELECT id,job_id,claim_id,attempt_count,created_by_agent_id,evidence_type,metadata
    FROM certificate_evidence WHERE workspace_id=$1 AND id=$2::uuid`, [agent.workspaceId, evidenceId])).rows[0];
  const metadata = evidence?.metadata || {};
  if (!evidence || String(evidence.job_id) !== String(job.id) || String(evidence.claim_id) !== String(job.claim_id) ||
      evidence.attempt_count !== job.attempt_count || String(evidence.created_by_agent_id) !== String(agent.id) ||
      evidence.evidence_type !== "validation.passed" || metadata.step !== "adcs.expected-identity" ||
      metadata.enrollmentId !== String(enrollment.id) || metadata.destinationSha256 !== destinationSha256 ||
      !HEX.test(metadata.fingerprintSha256 || "") || !HEX.test(metadata.csrSpkiSha256 || "") ||
      metadata.leafSpkiSha256 !== metadata.csrSpkiSha256) fail("evidence does not prove the expected leaf and CSR identity");
  const stillLive = await client.query(`SELECT 1 FROM certificate_jobs WHERE workspace_id=$1 AND id=$2::uuid
    AND claim_id=$3::uuid AND attempt_count=$4 AND status IN ('claimed','running') AND lease_expires_at > clock_timestamp()`,
    [agent.workspaceId, job.id, job.claim_id, job.attempt_count]);
  if (!stillLive.rows[0]) fail("the original agent claim is no longer admissible");
  const params = [agent.workspaceId, enrollment.id, agent.id, job.id, job.claim_id, job.attempt_count, evidence.id,
    snapshotSha256, destinationSha256, metadata.fingerprintSha256, metadata.csrSpkiSha256];
  const inserted = await client.query(`INSERT INTO certops_adcs_expected_identity_receipts
    (workspace_id,enrollment_id,agent_id,original_job_id,original_claim_id,original_attempt,evidence_id,snapshot_sha256,destination_sha256,fingerprint_sha256,csr_spki_sha256)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    ON CONFLICT (workspace_id,enrollment_id,original_job_id,original_claim_id,original_attempt) DO NOTHING RETURNING id`, params);
  if (inserted.rows[0]) return { receiptId: inserted.rows[0].id, created: true };
  const prior = (await client.query(`SELECT id,evidence_id,snapshot_sha256,destination_sha256,fingerprint_sha256,csr_spki_sha256
    FROM certops_adcs_expected_identity_receipts WHERE workspace_id=$1 AND enrollment_id=$2 AND original_job_id=$3 AND original_claim_id=$4 AND original_attempt=$5`, params.slice(0, 2).concat([job.id, job.claim_id, job.attempt_count]))).rows[0];
  if (!prior || String(prior.evidence_id) !== String(evidence.id) || prior.snapshot_sha256 !== snapshotSha256 || prior.destination_sha256 !== destinationSha256 ||
      prior.fingerprint_sha256 !== metadata.fingerprintSha256 || prior.csr_spki_sha256 !== metadata.csrSpkiSha256) fail("receipt replay differs from the committed identity");
  return { receiptId: prior.id, created: false };
}

/** Records a non-executable recovery intent; never dispatches CA work. */
async function prepareAdcsProofRecoveryTx({ client, workspaceId, enrollmentId, originalJobId, actorUserId, reason, audit = writeAudit }) {
  tx(client); uuid(workspaceId); uuid(enrollmentId); uuid(originalJobId);
  if (!Number.isInteger(actorUserId) || actorUserId <= 0 || typeof reason !== "string" || !reason.trim() || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) fail("operator and printable recovery reason required");
  // Keep the same lock order as authenticated receipt and dispatch paths.
  const owner = (await client.query(`SELECT agent_id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2::uuid`, [workspaceId, enrollmentId])).rows[0];
  if (!owner) fail("enrollment not found");
  await client.query(`SELECT id FROM certops_agents WHERE workspace_id=$1 AND id=$2::uuid FOR SHARE`, [workspaceId, owner.agent_id]);
  const enrollment = (await client.query(`SELECT e.id,e.agent_id,e.certificate_id,e.current_job_id,e.snapshot_bytes,e.snapshot_sha256,e.deploy_target,j.status AS original_status,
      j.claim_id AS original_claim_id,j.attempt_count AS original_attempt,j.needs_operator_reconciliation
    FROM certificate_enrollments e JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.enrollment_id=e.id AND j.id=$3::uuid
    WHERE e.workspace_id=$1 AND e.id=$2::uuid AND e.state NOT IN ('cancelled','expired','abandoned') FOR UPDATE OF e`, [workspaceId, enrollmentId, originalJobId])).rows[0];
  if (!enrollment || String(enrollment.agent_id) !== String(owner.agent_id) || enrollment.original_status !== "orphaned_unknown_effect" || enrollment.needs_operator_reconciliation !== true || !enrollment.original_claim_id) fail("the exact orphaned enrollment job is required");
  if (String(enrollment.current_job_id) !== originalJobId) fail("another enrollment attempt already superseded this job");
  const receipt = (await client.query(`SELECT id,snapshot_sha256,destination_sha256 FROM certops_adcs_expected_identity_receipts WHERE workspace_id=$1 AND enrollment_id=$2::uuid
    AND original_job_id=$3::uuid AND original_claim_id=$4::uuid AND original_attempt=$5 AND agent_id=$6::uuid`,
    [workspaceId, enrollmentId, originalJobId, enrollment.original_claim_id, enrollment.original_attempt, enrollment.agent_id])).rows[0];
  if (!receipt) {
    await client.query(`UPDATE managed_certificates SET reconciliation_reason='expected_identity_unavailable',updated_at=NOW()
      WHERE workspace_id=$1 AND id=$2::uuid`, [workspaceId, enrollment.certificate_id]);
    await audit({ client, workspaceId, actorUserId, subjectUserId: actorUserId, action: "CERTOPS_ADCS_PROOF_RECOVERY_UNAVAILABLE",
      targetType: "certificate_enrollment", targetId: null, metadata: { enrollmentId, originalJobId, reason: redactGenericSecrets(reason.trim()) } });
    return { state: "expected_identity_unavailable", created: false };
  }
  const target = enrollment.deploy_target;
  const snapshotDigest = crypto.createHash("sha256").update(Buffer.from(enrollment.snapshot_bytes)).digest("hex");
  const destinationDigest = target?.type === "windows-cert-store" && target.store === "My"
    ? crypto.createHash("sha256").update(JSON.stringify({ type: "windows-cert-store", reference: target.reference, store: "My" })).digest("hex") : null;
  if (snapshotDigest !== enrollment.snapshot_sha256 || snapshotDigest !== receipt.snapshot_sha256 || destinationDigest !== receipt.destination_sha256) fail("enrollment identity changed after the receipt");
  const inserted = await client.query(`INSERT INTO certops_adcs_proof_recovery_intents(workspace_id,enrollment_id,receipt_id,agent_id)
    VALUES($1,$2,$3,$4) ON CONFLICT(workspace_id,receipt_id) DO NOTHING RETURNING id`, [workspaceId, enrollmentId, receipt.id, enrollment.agent_id]);
  if (!inserted.rows[0]) {
    const existing = (await client.query("SELECT id,state FROM certops_adcs_proof_recovery_intents WHERE workspace_id=$1 AND receipt_id=$2", [workspaceId, receipt.id])).rows[0];
    return { intentId: existing.id, state: existing.state, created: false };
  }
  await audit({ client, workspaceId, actorUserId, subjectUserId: actorUserId, action: "CERTOPS_ADCS_PROOF_RECOVERY_PREPARED",
    targetType: "certificate_enrollment", targetId: null, metadata: { enrollmentId, originalJobId, reason: redactGenericSecrets(reason.trim()) } });
  return { intentId: inserted.rows[0].id, state: "transport_unavailable", created: true };
}

// Called only by a trusted operator admission path after prepare. The
// capability is withheld until native and edition qualification succeeds.
async function queueAdcsProofRecoveryTx({ client, workspaceId, intentId, actorUserId, env = process.env }) {
  tx(client); uuid(workspaceId); uuid(intentId);
  if (!Number.isInteger(actorUserId) || actorUserId <= 0) fail("operator required");
  const candidate = (await client.query(`SELECT agent_id,proof_job_id,enrollment_id FROM certops_adcs_proof_recovery_intents WHERE workspace_id=$1 AND id=$2::uuid`, [workspaceId, intentId])).rows[0];
  if (!candidate) fail("proof recovery intent not found");
  if (candidate.proof_job_id) {
    const eligible = await client.query(`SELECT id FROM certificate_enrollments WHERE workspace_id=$1 AND id=$2::uuid
      AND state NOT IN ('cancelled','expired','abandoned') FOR SHARE`, [workspaceId, candidate.enrollment_id]);
    if (!eligible.rows[0]) fail("proof enrollment is terminal or unavailable");
    const job = await require("./jobs").getCertificateJobById({ client, workspaceId, jobId: candidate.proof_job_id, env });
    return { job, created: false };
  }
  const agent = (await client.query(`SELECT status,platform,declared_capabilities,capabilities_updated_at FROM certops_agents
    WHERE workspace_id=$1 AND id=$2::uuid FOR SHARE`, [workspaceId, candidate.agent_id])).rows[0];
  const { hasFreshCapability } = require("./agentJobEligibility");
  if (!agent || agent.status !== "active" || agent.platform !== "win32" ||
      ["adcs-store-proof-only-v1", "windows-store-only-adcs-v1", "adcs-enroll-v1", "evidence-claim-binding-v1"].some(capability =>
        !hasFreshCapability({ declaredCapabilities: agent.declared_capabilities, capabilitiesUpdatedAt: agent.capabilities_updated_at, capability, env }))) {
    fail("original agent does not declare the qualified proof capability", "CERTOPS_ADCS_PROOF_AGENT_UNAVAILABLE");
  }
  const intent = (await client.query(`SELECT i.id,i.agent_id,i.enrollment_id,i.receipt_id,i.state,i.proof_job_id,e.certificate_id,e.deploy_target,e.snapshot_bytes,
      e.snapshot_sha256 AS current_snapshot_sha256,r.snapshot_sha256,r.destination_sha256
    FROM certops_adcs_proof_recovery_intents i JOIN certificate_enrollments e ON e.workspace_id=i.workspace_id AND e.id=i.enrollment_id
    JOIN certops_adcs_expected_identity_receipts r ON r.workspace_id=i.workspace_id AND r.id=i.receipt_id AND r.enrollment_id=e.id AND r.agent_id=i.agent_id
    JOIN certificate_jobs original ON original.workspace_id=r.workspace_id AND original.id=r.original_job_id
    WHERE i.workspace_id=$1 AND i.id=$2::uuid AND e.current_job_id=original.id AND original.enrollment_id=e.id
      AND e.state NOT IN ('cancelled','expired','abandoned')
      AND original.status='orphaned_unknown_effect' AND original.needs_operator_reconciliation=TRUE
      AND original.claim_id=r.original_claim_id AND original.attempt_count=r.original_attempt
    FOR UPDATE OF i,e SKIP LOCKED`, [workspaceId, intentId])).rows[0];
  if (!intent || String(intent.agent_id) !== String(candidate.agent_id)) fail("proof intent is busy or changed");
  if (intent.proof_job_id) {
    const job = await require("./jobs").getCertificateJobById({ client, workspaceId, jobId: intent.proof_job_id, env });
    return { job, created: false };
  }
  const target = intent.deploy_target;
  const digest = crypto.createHash("sha256").update(Buffer.from(intent.snapshot_bytes)).digest("hex");
  const destination = target?.type === "windows-cert-store" && target.store === "My"
    ? crypto.createHash("sha256").update(JSON.stringify({ type: "windows-cert-store", reference: target.reference, store: "My" })).digest("hex") : null;
  if (digest !== intent.current_snapshot_sha256 || digest !== intent.snapshot_sha256 || destination !== intent.destination_sha256) fail("enrollment identity changed after the receipt");
  const outcome = await require("./jobs").createCertificateJob({ client, transactionOwned: true, workspaceId,
    operation: "adcs-installation-proof", allowAdcsProofOnly: true, adcsProofIntentId: intent.id,
    enrollmentId: intent.enrollment_id, assignedAgentId: intent.agent_id, subjectType: "managed_certificate",
    subjectId: String(intent.certificate_id), source: "api", mode: "real", requestedByUserId: actorUserId,
    idempotencyKey: `adcs-proof:${intent.receipt_id}`, returnOutcome: true,
    payload: { schemaVersion: 1, certificateId: String(intent.certificate_id), target: intent.deploy_target, keyMode: "os-store-managed" } });
  await client.query(`UPDATE certops_adcs_proof_recovery_intents SET state='queued',proof_job_id=$3
    WHERE workspace_id=$1 AND id=$2::uuid AND proof_job_id IS NULL`, [workspaceId, intentId, outcome.job.id]);
  return outcome;
}

// Shared by Core and edition claim gates. A missing or locked binding means
// skip, never treat the job as a generic enrollment continuation.
async function loadAdcsProofJobBindingTx({ client, workspaceId, jobId, agentId }) {
  tx(client); uuid(workspaceId); uuid(jobId); uuid(agentId);
  const row = (await client.query(`SELECT i.receipt_id,i.enrollment_id,i.agent_id,r.original_job_id,r.original_claim_id,r.original_attempt,
      r.snapshot_sha256,r.destination_sha256,r.fingerprint_sha256,r.csr_spki_sha256,e.snapshot_bytes,e.snapshot_sha256 AS current_snapshot_sha256,e.deploy_target,
      j.subject_id,j.assigned_agent_id,j.enrollment_id AS job_enrollment_id,j.payload
    FROM certops_adcs_proof_recovery_intents i
    JOIN certops_adcs_expected_identity_receipts r ON r.workspace_id=i.workspace_id AND r.id=i.receipt_id
    JOIN certificate_enrollments e ON e.workspace_id=i.workspace_id AND e.id=i.enrollment_id
    JOIN certificate_jobs j ON j.workspace_id=i.workspace_id AND j.id=i.proof_job_id
    JOIN certificate_jobs original ON original.workspace_id=r.workspace_id AND original.id=r.original_job_id
    JOIN managed_certificates mc ON mc.workspace_id=e.workspace_id AND mc.id=e.certificate_id
    WHERE i.workspace_id=$1 AND i.proof_job_id=$2::uuid AND i.agent_id=$3::uuid AND i.state='queued'
      AND e.state NOT IN ('cancelled','expired','abandoned')
      AND j.operation='adcs-installation-proof' AND j.assigned_agent_id=i.agent_id AND j.enrollment_id=e.id
      AND j.subject_type='managed_certificate' AND j.subject_id=e.certificate_id::text AND mc.deployed_agent_id=i.agent_id
      AND r.enrollment_id=e.id AND r.agent_id=i.agent_id
      AND e.current_job_id=original.id AND original.enrollment_id=e.id AND original.status='orphaned_unknown_effect'
      AND original.needs_operator_reconciliation=TRUE AND original.claim_id=r.original_claim_id AND original.attempt_count=r.original_attempt
    FOR SHARE OF i,r,e SKIP LOCKED`, [workspaceId, jobId, agentId])).rows[0];
  if (!row) return null;
  const target = row.deploy_target;
  if (!target || target.type !== "windows-cert-store" || target.store !== "My" ||
      JSON.stringify(row.payload?.target) !== JSON.stringify(target)) return null;
  const snapshotDigest = crypto.createHash("sha256").update(Buffer.from(row.snapshot_bytes)).digest("hex");
  const destinationDigest = crypto.createHash("sha256").update(JSON.stringify({ type: "windows-cert-store", reference: target.reference, store: "My" })).digest("hex");
  if (snapshotDigest !== row.current_snapshot_sha256 || snapshotDigest !== row.snapshot_sha256 || destinationDigest !== row.destination_sha256) return null;
  return { receiptId: String(row.receipt_id), enrollmentId: String(row.enrollment_id), agentId: String(row.agent_id),
    originalJobId: String(row.original_job_id), originalClaimId: String(row.original_claim_id), originalAttempt: row.original_attempt,
    snapshotSha256: row.snapshot_sha256, destinationSha256: row.destination_sha256,
    fingerprintSha256: row.fingerprint_sha256, csrSpkiSha256: row.csr_spki_sha256 };
}

module.exports = { recordAdcsExpectedIdentityTx, prepareAdcsProofRecoveryTx, queueAdcsProofRecoveryTx, loadAdcsProofJobBindingTx };
