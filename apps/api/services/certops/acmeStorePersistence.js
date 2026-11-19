"use strict";

// Transaction-owned primitives only: callers must supply an authenticated
// agent and a real transaction client. There is intentionally no public route.
const crypto = require("node:crypto");
const { freezeAcmeStoreRequest, applyAcmeStoreEvidence, containerForJob } = require("./acmeStoreContract");
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
function fail(message) { const error = new Error(message); error.code = "CERTOPS_ACME_STORE_INVALID"; throw error; }
function transaction(client) {
  if (!client || typeof client.query !== "function" || (typeof client.connect === "function" && typeof client.idleCount === "number")) fail("transaction client required");
}
const RECOVERY_FIELDS = ["target", "sans", "caEndpoint", "commandRef", "dnsProvider", "dnsZone", "keyAlgorithm", "keySize", "acmeKind", "preferredChain", "eabRef", "accountRef", "keyRotation", "keyMode"];
function recoveryPayload(payload) { return Object.fromEntries(RECOVERY_FIELDS.filter(key => Object.hasOwn(payload, key)).map(key => [key, payload[key]])); }
function id(value) { if (typeof value !== "string" || !UUID.test(value)) fail("invalid identity"); return value; }

async function createAcmeStoreEnrollmentTx({ client, enrollmentId, request }) {
  transaction(client); id(enrollmentId);
  if (request.issuanceMode === "renew") {
    const iisConsumers = await require("./windowsIisConsent").snapshotWindowsIisConsumers({ client,
      workspaceId: request.workspaceId, certificateId: request.certificateId, agentId: request.agentId });
    request = { ...request, ...(iisConsumers.length ? { iisConsumers } : {}) };
  }
  const frozen = freezeAcmeStoreRequest(request);
  const r = frozen.request;
  const agent = (await client.query(`SELECT agent_id,status FROM certops_agents
    WHERE workspace_id=$1::uuid AND id=$2::uuid FOR UPDATE`, [r.workspaceId, r.agentId])).rows[0];
  if (!agent || agent.status !== "active" || agent.agent_id !== r.agentPublicId) fail("public agent identity does not match owner");
  const certificate = (await client.query(`SELECT status,source,key_mode,deployed_agent_id,fingerprint_sha256 FROM managed_certificates
    WHERE workspace_id=$1::uuid AND id=$2::uuid FOR UPDATE`, [r.workspaceId, r.certificateId])).rows[0];
  const predecessor = typeof certificate?.fingerprint_sha256 === "string" ? certificate.fingerprint_sha256.replace(/:/g, "").toLowerCase() : null;
  if (!certificate || certificate.key_mode !== "os-store-managed" || String(certificate.deployed_agent_id || "") !== r.agentId ||
      (r.issuanceMode === "issue" && (certificate.source !== "agent_issuance" || certificate.status !== "provisioning" || predecessor !== null)) ||
      (r.issuanceMode === "renew" && (certificate.status !== "active" || predecessor !== r.predecessorFingerprintSha256))) {
    fail("certificate owner or predecessor does not match frozen ACME enrollment");
  }
  const open = await client.query(`SELECT id,state FROM certops_acme_store_enrollments
    WHERE workspace_id=$1::uuid AND certificate_id=$2::uuid AND state <> 'installed' FOR UPDATE`, [r.workspaceId, r.certificateId]);
  if (open.rows.length) {
    const error = new Error("An earlier ACME order may still have effects; reconcile it before issuing again");
    error.code = "CERTOPS_ACME_STORE_ORDER_UNCERTAIN";
    throw error;
  }
  const job = (await client.query(`SELECT operation, subject_type, subject_id, assigned_agent_id, payload
    FROM certificate_jobs WHERE workspace_id=$1 AND id=$2::uuid FOR UPDATE`, [r.workspaceId, r.jobId])).rows[0];
  if (!job || job.operation !== r.issuanceMode || job.subject_type !== "managed_certificate" ||
      String(job.subject_id) !== r.certificateId || String(job.assigned_agent_id) !== r.agentId ||
      job.payload?.target?.type !== "windows-cert-store" || job.payload.target.store !== "My" ||
      job.payload.target.reference !== r.target.reference ||
      Object.keys(job.payload.target).some(key => !["type", "store", "reference"].includes(key))) fail("job does not match frozen ACME enrollment");
  const payload = job.payload;
  const keyName = payload.keyAlgorithm === "rsa" ? `rsa-${payload.keySize}` : payload.keyAlgorithm === "ecdsa" ? `ec-p${payload.keySize}` : null;
  let endpoint;
  try { endpoint = new URL(payload.caEndpoint).href; } catch { fail("job ACME endpoint is invalid"); }
  const names = Array.isArray(payload.sans) ? [...new Set(payload.sans)].sort() : null;
  if (endpoint !== r.caEndpoint || payload.commandRef !== r.commandRef || payload.dnsProvider !== r.dnsProvider ||
      payload.dnsZone !== r.dnsZone || keyName !== r.keyAlgorithm || (payload.acmeKind || "certbot") !== r.acmeKind ||
      (payload.preferredChain || null) !== r.preferredChain || (payload.eabRef || payload.accountRef || null) !== r.eabAccountRef ||
      payload.keyRotation === false || !names || JSON.stringify(names) !== JSON.stringify(r.dnsNames)) {
    fail("job issuance parameters do not match frozen ACME enrollment");
  }
  const inserted = await client.query(`INSERT INTO certops_acme_store_enrollments
    (id,workspace_id,certificate_id,agent_id,original_job_id,current_job_id,container_name,request_bytes,request_sha256,state)
    VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$5::uuid,$6,$7,$8,'keygen_intent') RETURNING id`,
  [enrollmentId, r.workspaceId, r.certificateId, r.agentId, r.jobId, containerForJob(r.jobId), frozen.requestBytes, frozen.requestSha256]);
  if (inserted.rows.length !== 1) fail("could not persist ACME enrollment");
  return { enrollmentId, requestSha256: frozen.requestSha256 };
}

async function applyAcmeStoreReceiptTx({ client, workspaceId, enrollmentId, authenticatedAgentRowId, claimId, receiptId, evidence }) {
  transaction(client); [workspaceId, enrollmentId, authenticatedAgentRowId, claimId, receiptId].forEach(id);
  const row = (await client.query(`SELECT * FROM certops_acme_store_enrollments
    WHERE workspace_id=$1::uuid AND id=$2::uuid FOR UPDATE`, [workspaceId, enrollmentId])).rows[0];
  if (!row) fail("ACME store enrollment does not exist");
  const job = (await client.query(`SELECT j.claim_id,j.claimed_by_agent_id,j.assigned_agent_id,j.status,
      (j.lease_expires_at > NOW()) AS lease_valid, a.status AS agent_status, a.agent_id AS agent_public_id
    FROM certificate_jobs j JOIN certops_agents a ON a.workspace_id=j.workspace_id AND a.id=j.claimed_by_agent_id
    WHERE j.workspace_id=$1::uuid AND j.id=$2::uuid FOR UPDATE OF j,a`, [workspaceId, row.current_job_id])).rows[0];
  if (!job || String(row.agent_id) !== authenticatedAgentRowId || String(job.assigned_agent_id) !== authenticatedAgentRowId ||
      String(job.claimed_by_agent_id) !== authenticatedAgentRowId || String(job.claim_id) !== claimId ||
      job.agent_status !== "active" || !["claimed", "running"].includes(job.status) || job.lease_valid !== true) {
    fail("ACME receipt is not bound to an active owner claim");
  }
  const bytes = Buffer.from(row.request_bytes);
  if (crypto.createHash("sha256").update(bytes).digest("hex") !== row.request_sha256) fail("ACME frozen request is corrupt");
  let request;
  try { request = JSON.parse(bytes.toString("utf8")); } catch { fail("ACME frozen request is corrupt"); }
  if (request.workspaceId !== workspaceId || request.certificateId !== String(row.certificate_id) ||
      request.agentId !== authenticatedAgentRowId || request.agentPublicId !== job.agent_public_id || request.jobId !== String(row.original_job_id)) fail("ACME frozen owner identity changed");
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) fail("invalid ACME evidence");
  if (evidence.agentId !== authenticatedAgentRowId || evidence.claimId !== claimId ||
      evidence.jobId !== String(row.current_job_id) || evidence.enrollmentId !== enrollmentId ||
      evidence.requestSha256 !== row.request_sha256 || evidence.containerName !== row.container_name) {
    fail("ACME receipt identity does not match the current claim");
  }
  // A new claim for the same original job can safely replay an identical
  // stage receipt after an acknowledgement was lost. Claim ownership is
  // checked above; it is not part of the durable receipt's content identity.
  const { claimId: _claimId, jobId: _jobId, ...stableEvidence } = evidence;
  const evidenceSha256 = crypto.createHash("sha256").update(JSON.stringify(stableEvidence), "utf8").digest("hex");
  const old = (await client.query(`SELECT evidence_sha256,resulting_state FROM certops_acme_store_receipts
    WHERE workspace_id=$1::uuid AND enrollment_id=$2::uuid AND receipt_id=$3::uuid`, [workspaceId, enrollmentId, receiptId])).rows[0];
  if (old) {
    if (old.evidence_sha256 !== evidenceSha256) fail("receipt identity was reused with different evidence");
    return { replayed: true, state: old.resulting_state };
  }
  const record = { workspaceId, enrollmentId, certificateId: String(row.certificate_id), agentId: String(row.agent_id),
    jobId: String(row.original_job_id), currentJobId: String(row.current_job_id), containerName: row.container_name, requestSha256: row.request_sha256,
    state: row.state, csrSha256: row.csr_sha256, csrSpkiSha256: row.csr_spki_sha256,
    fingerprintSha256: row.fingerprint_sha256, orderReferenceSha256: row.order_reference_sha256 };
  const next = applyAcmeStoreEvidence({ record, evidence, agentId: authenticatedAgentRowId, claimId });
  await client.query(`UPDATE certops_acme_store_enrollments SET state=$3,csr_sha256=$4,csr_spki_sha256=$5,
      fingerprint_sha256=$6,order_reference_sha256=$7,updated_at=NOW() WHERE workspace_id=$1::uuid AND id=$2::uuid`,
  [workspaceId, enrollmentId, next.state, next.csrSha256 || null, next.csrSpkiSha256 || null,
    next.fingerprintSha256 || null, next.orderReferenceSha256 || null]);
  await client.query(`INSERT INTO certops_acme_store_receipts (workspace_id,enrollment_id,receipt_id,evidence_sha256,resulting_state)
    VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5)`, [workspaceId, enrollmentId, receiptId, evidenceSha256, next.state]);
  return { replayed: false, state: next.state };
}

// Build the server-owned signed binding only for the persisted current owner.
// A continuation is accepted only when the transaction-owned recovery primitive
// has attached it to this enrollment; the original request remains authoritative.
async function loadAcmeStoreBindingTx({ client, workspaceId, jobId, agentId }) {
  transaction(client); [workspaceId, jobId, agentId].forEach(id);
  const row = (await client.query(`SELECT e.id,e.agent_id,e.original_job_id,e.current_job_id,e.request_bytes,e.request_sha256,
      a.agent_id AS agent_public_id,a.status AS agent_status,j.assigned_agent_id,j.operation,
      j.subject_id,j.subject_type,j.payload,original.payload AS original_payload
    FROM certops_acme_store_enrollments e
    JOIN certops_agents a ON a.workspace_id=e.workspace_id AND a.id=e.agent_id
    JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id
    JOIN certificate_jobs original ON original.workspace_id=e.workspace_id AND original.id=e.original_job_id
    WHERE e.workspace_id=$1::uuid AND e.current_job_id=$2::uuid FOR UPDATE OF e,j,a`, [workspaceId, jobId])).rows[0];
  if (!row || String(row.agent_id) !== agentId || String(row.assigned_agent_id) !== agentId || row.agent_status !== "active" ||
      row.subject_type !== "managed_certificate" ||
      (String(row.original_job_id) === jobId ? !["issue", "renew"].includes(row.operation) :
        row.operation !== "continue-enrollment" || JSON.stringify(recoveryPayload(row.payload)) !== JSON.stringify(recoveryPayload(row.original_payload)))) fail("ACME store dispatch owner or original job does not match");
  const bytes = Buffer.from(row.request_bytes);
  if (crypto.createHash("sha256").update(bytes).digest("hex") !== row.request_sha256) fail("ACME frozen request is corrupt");
  let request;
  try { request = JSON.parse(bytes.toString("utf8")); } catch { fail("ACME frozen request is corrupt"); }
  if (request.workspaceId !== workspaceId || request.agentId !== agentId || request.agentPublicId !== row.agent_public_id || request.jobId !== String(row.original_job_id) || request.certificateId !== String(row.subject_id)) fail("ACME frozen dispatch identity changed");
  return { enrollmentId: String(row.id), originalJobId: String(row.original_job_id), requestB64: bytes.toString("base64"), requestSha256: row.request_sha256 };
}

// This primitive is deliberately not exposed by a route. The future caller must
// authorize the operator and hold the enclosing transaction through audit commit.
async function continueAcmeStoreEnrollmentTx({ client, workspaceId, enrollmentId, orphanedJobId, actorUserId, reason, acknowledgeUnknownEffect, audit }) {
  transaction(client); [workspaceId, enrollmentId, orphanedJobId].forEach(id);
  if (acknowledgeUnknownEffect !== true || !Number.isInteger(actorUserId) || actorUserId <= 0 ||
      typeof reason !== "string" || !reason.trim() || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) fail("explicit acknowledgement, operator and printable reason required");
  const row = (await client.query(`SELECT e.*,j.status AS orphan_status,j.needs_operator_reconciliation,
      j.claim_id AS orphan_claim_id,j.assigned_agent_id AS orphan_agent_id,
      original.operation AS original_operation,original.payload AS original_payload,
      original.subject_id AS original_subject_id,a.status AS agent_status
    FROM certops_acme_store_enrollments e
    JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=$3::uuid
    JOIN certificate_jobs original ON original.workspace_id=e.workspace_id AND original.id=e.original_job_id
    JOIN certops_agents a ON a.workspace_id=e.workspace_id AND a.id=e.agent_id
    WHERE e.workspace_id=$1::uuid AND e.id=$2::uuid FOR UPDATE OF e,j,original,a`,
  [workspaceId, enrollmentId, orphanedJobId])).rows[0];
  if (!row || row.orphan_status !== "orphaned_unknown_effect" || row.needs_operator_reconciliation !== true ||
      !row.orphan_claim_id || String(row.orphan_agent_id) !== String(row.agent_id) || row.agent_status !== "active" ||
      !["issue", "renew"].includes(row.original_operation) || String(row.original_subject_id) !== String(row.certificate_id)) fail("the exact uncertain owner enrollment is required");
  const recoveryKey = `acme-recovery:${enrollmentId}:${orphanedJobId}`;
  if (String(row.current_job_id) !== orphanedJobId) {
    const prior = (await client.query(`SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND id=$2 AND idempotency_key=$3
      AND assigned_agent_id=$4 AND operation='continue-enrollment'`, [workspaceId, row.current_job_id, recoveryKey, row.agent_id])).rows[0];
    if (!prior) fail("another enrollment attempt already superseded this job");
    return { jobId: String(prior.id), created: false };
  }
  // Validate original frozen identity before any executable job is created.
  await loadAcmeStoreBindingTx({ client, workspaceId, jobId: orphanedJobId, agentId: String(row.agent_id) });
  const { createCertificateJob } = require("./jobs");
  const outcome = await createCertificateJob({ client, transactionOwned: true, returnOutcome: true,
    workspaceId, subjectType: "managed_certificate", subjectId: String(row.certificate_id),
    operation: "continue-enrollment", allowEnrollmentContinuation: true, acmeStoreRecoveryEnrollmentId: enrollmentId,
    mode: "real", source: "api", requestedByUserId: actorUserId, assignedAgentId: String(row.agent_id),
    idempotencyKey: recoveryKey, payload: recoveryPayload(row.original_payload) });
  if (!outcome.created) fail("recovery job identity is already in use");
  await client.query("UPDATE certops_acme_store_enrollments SET current_job_id=$3::uuid,updated_at=NOW() WHERE workspace_id=$1 AND id=$2::uuid", [workspaceId, enrollmentId, outcome.job.id]);
  const write = audit || require("../audit").writeAudit;
  await write({ client, workspaceId, actorUserId, subjectUserId: actorUserId, action: "CERTOPS_ACME_STORE_RECOVERY_REQUESTED",
    targetType: "certificate_job", targetId: null, metadata: { enrollmentId, orphanedJobId, continuationJobId: outcome.job.id, reason: require("../../utils/secretMaterial").redactGenericSecrets(reason.trim()) } });
  return { jobId: outcome.job.id, created: true };
}

module.exports = { createAcmeStoreEnrollmentTx, applyAcmeStoreReceiptTx, loadAcmeStoreBindingTx, continueAcmeStoreEnrollmentTx };
