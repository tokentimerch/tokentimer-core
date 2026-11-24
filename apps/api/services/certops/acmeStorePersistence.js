"use strict";

// Receipt and recovery writes require a transaction owned by the authenticated caller.
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
    WHERE workspace_id=$1::uuid AND certificate_id=$2::uuid AND state NOT IN ('installed', 'cancelled_no_effect') FOR UPDATE`, [r.workspaceId, r.certificateId]);
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

function isAcmeStoreEnrollmentJob(job) {
  return !job.enrollmentId && job.payload?.target?.type === "windows-cert-store" &&
    ["issue", "renew", "continue-enrollment"].includes(job.operation);
}

// The caller owns the job row and has recorded a pre-execution terminal
// decision. Keep the frozen request for idempotent replay and audit history.
async function cancelUnstartedAcmeStoreEnrollmentTx({ client, workspaceId, jobId }) {
  transaction(client);
  const result = await client.query(`WITH unstarted AS (
    SELECT e.id FROM certops_acme_store_enrollments e
    JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.original_job_id
    WHERE e.workspace_id=$1::uuid AND e.current_job_id=$2::uuid
      AND e.current_job_id=e.original_job_id AND e.state='keygen_intent'
      AND j.operation IN ('issue','renew') AND j.enrollment_id IS NULL AND j.mode='real'
      AND j.payload->'target'->>'type'='windows-cert-store'
      AND j.subject_type='managed_certificate' AND j.subject_id=e.certificate_id::text
      AND j.assigned_agent_id=e.agent_id AND j.status IN ('cancelled','rejected')
      AND j.lease_renewed_at IS NULL AND j.needs_operator_reconciliation IS NOT TRUE
      AND e.csr_sha256 IS NULL AND e.csr_spki_sha256 IS NULL
      AND e.fingerprint_sha256 IS NULL AND e.order_reference_sha256 IS NULL
      AND NOT EXISTS (SELECT 1 FROM certificate_evidence ev
        WHERE (ev.workspace_id,ev.job_id)=(j.workspace_id,j.id))
      AND NOT EXISTS (SELECT 1 FROM certops_acme_store_receipts r
        WHERE (r.workspace_id,r.enrollment_id)=(e.workspace_id,e.id))
    FOR UPDATE OF e SKIP LOCKED
  )
  UPDATE certops_acme_store_enrollments e SET state='cancelled_no_effect',updated_at=NOW()
  FROM unstarted WHERE e.id=unstarted.id`, [workspaceId, jobId]);
  return result.rowCount === 1;
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
    WHERE e.workspace_id=$1::uuid AND e.current_job_id=$2::uuid AND e.state<>'cancelled_no_effect' FOR UPDATE OF e,j,a`, [workspaceId, jobId])).rows[0];
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

async function readAcmeStoreRecoveryBinding({ client, workspaceId, jobId, enrollmentId }) {
  const scope = enrollmentId
    ? "e.id=$3::uuid FOR UPDATE OF e,j,original,a"
    : "(e.current_job_id=j.id OR e.original_job_id=j.id)";
  const parameters = enrollmentId ? [workspaceId, jobId, enrollmentId] : [workspaceId, jobId];
  return (await client.query(`SELECT e.id,e.state,e.agent_id,e.certificate_id,e.original_job_id,e.current_job_id,
      j.id AS job_id,j.status,j.needs_operator_reconciliation,j.claim_id,j.claimed_by_agent_id,
      j.assigned_agent_id,j.operation,j.mode,j.executor_kind,j.subject_id,j.subject_type,
      original.operation AS original_operation,original.payload AS original_payload,
      original.subject_id AS original_subject_id,a.status AS agent_status,
      CASE WHEN j.claim_id IS NULL AND j.claimed_by_agent_id IS NULL AND j.lease_expires_at IS NULL
        AND j.completed_at IS NOT NULL
        AND j.error_code='effects_unknown'
        AND j.reconciliation_reason='lease_expired_after_side_effect_window_agent_unresponsive'
      THEN EXISTS (
        SELECT 1 FROM certificate_job_log l
        WHERE l.workspace_id=j.workspace_id AND l.job_id=j.id AND l.event_type='job.failed'
          AND l.status='orphaned_unknown_effect' AND l.metadata->>'sweep'='lease-reaper'
          AND l.metadata->>'outcome'=j.status AND l.metadata->>'errorCode'=j.error_code
          AND l.metadata->>'reconciliationReason'=j.reconciliation_reason
      ) ELSE FALSE END AS lease_reaped
    FROM certops_acme_store_enrollments e
    JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=$2::uuid
    JOIN certificate_jobs original ON original.workspace_id=e.workspace_id AND original.id=e.original_job_id
    JOIN certops_agents a ON a.workspace_id=e.workspace_id AND a.id=e.agent_id
    WHERE e.workspace_id=$1::uuid AND ${scope}`, parameters)).rows[0];
}

function hasUncertainAcmeStoreOutcome(row) {
  return row?.status === "orphaned_unknown_effect" && row.needs_operator_reconciliation === true;
}

function matchesAcmeStoreRecoveryOwner(row) {
  if (row?.status !== "orphaned_unknown_effect" || row.agent_status !== "active" ||
      row.assigned_agent_id !== row.agent_id || row.mode !== "real" || row.executor_kind !== "agent" ||
      row.subject_type !== "managed_certificate" || row.subject_id !== row.certificate_id ||
      !["issue", "renew"].includes(row.original_operation) || row.original_subject_id !== row.certificate_id) {
    return false;
  }
  const expectedOperation = row.job_id === row.original_job_id ? row.original_operation : "continue-enrollment";
  return row.operation === expectedOperation;
}

function isRecoverableAcmeStoreOrphan(row) {
  if (!matchesAcmeStoreRecoveryOwner(row) || !hasUncertainAcmeStoreOutcome(row)) return false;
  // The worker clears the expired claim and records its own terminal event in the same transaction.
  const ownerClaim = Boolean(row.claim_id && row.claimed_by_agent_id === row.agent_id);
  return ownerClaim || row.lease_reaped === true;
}

async function lookupAcmeStoreRecoveryByJob({ client, workspaceId, jobId }) {
  const row = await readAcmeStoreRecoveryBinding({ client, workspaceId, jobId });
  if (!row) return null;
  return { enrollmentId: String(row.id), state: row.state,
    outcomeUncertain: hasUncertainAcmeStoreOutcome(row),
    recoveryAvailable: row.current_job_id === row.job_id && isRecoverableAcmeStoreOrphan(row) };
}

// The recovery route authorizes the operator and holds its transaction through audit commit.
async function continueAcmeStoreEnrollmentTx({ client, workspaceId, enrollmentId, orphanedJobId, actorUserId, reason, acknowledgeUnknownEffect, audit }) {
  transaction(client); [workspaceId, enrollmentId, orphanedJobId].forEach(id);
  if (acknowledgeUnknownEffect !== true || !Number.isInteger(actorUserId) || actorUserId <= 0 ||
      typeof reason !== "string" || !reason.trim() || reason.length > 500 || /[\u0000-\u001f\u007f]/.test(reason)) fail("explicit acknowledgement, operator and printable reason required");
  const row = await readAcmeStoreRecoveryBinding({ client, workspaceId, jobId: orphanedJobId, enrollmentId });
  if (!matchesAcmeStoreRecoveryOwner(row)) fail("the exact uncertain owner enrollment is required");
  const recoveryKey = `acme-recovery:${enrollmentId}:${orphanedJobId}`;
  if (String(row.current_job_id) !== orphanedJobId) {
    const prior = (await client.query(`SELECT id FROM certificate_jobs WHERE workspace_id=$1 AND idempotency_key=$2
      AND assigned_agent_id=$3 AND subject_type='managed_certificate' AND subject_id=$4
      AND operation='continue-enrollment' AND mode='real' AND executor_kind='agent' AND enrollment_id IS NULL`,
    [workspaceId, recoveryKey, row.agent_id, row.certificate_id])).rows[0];
    if (!prior) fail("another enrollment attempt already superseded this job");
    return { jobId: String(prior.id), created: false };
  }
  if (!isRecoverableAcmeStoreOrphan(row)) fail("the exact uncertain owner enrollment is required");
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

async function reconcileAcmeStoreRecoveryTx({ client, workspaceId, jobId, agentId, audit }) {
  transaction(client); [workspaceId, jobId, agentId].forEach(id);
  // Each server-created continuation records its exact predecessor in its idempotency key.
  const { rows } = await client.query(`WITH RECURSIVE installed AS (
    SELECT e.id AS enrollment_id,e.original_job_id,e.certificate_id,e.agent_id,j.id,j.idempotency_key,j.operation
    FROM certops_acme_store_enrollments e
    JOIN certificate_jobs j ON j.workspace_id=e.workspace_id AND j.id=e.current_job_id
    WHERE e.workspace_id=$1 AND e.current_job_id=$2::uuid AND e.agent_id=$3::uuid AND e.state='installed'
      AND j.operation='continue-enrollment' AND j.status='succeeded' AND j.mode='real' AND j.executor_kind='agent'
      AND j.enrollment_id IS NULL AND j.assigned_agent_id=e.agent_id
      AND j.subject_type='managed_certificate' AND j.subject_id=e.certificate_id::text
  ), attempts AS (
    SELECT id,idempotency_key,operation FROM installed
    UNION
    SELECT previous.id,previous.idempotency_key,previous.operation
    FROM attempts next CROSS JOIN installed e
    JOIN certificate_jobs previous ON previous.workspace_id=$1 AND previous.assigned_agent_id=e.agent_id
      AND previous.subject_type='managed_certificate' AND previous.subject_id=e.certificate_id::text
      AND previous.mode='real' AND previous.executor_kind='agent' AND previous.enrollment_id IS NULL
    WHERE next.operation='continue-enrollment'
      AND next.idempotency_key='acme-recovery:' || e.enrollment_id::text || ':' || previous.id::text
      AND (previous.operation='continue-enrollment' OR
        (previous.id=e.original_job_id AND previous.operation IN ('issue','renew')))
  )
  UPDATE certificate_jobs j SET needs_operator_reconciliation=FALSE,
    reconciliation_reason='installation_verified_by_acme_continuation',
    result_metadata=COALESCE(j.result_metadata,'{}'::jsonb) || jsonb_build_object('reconciliationJobId',$2::text),
    updated_at=NOW()
  FROM installed e
  WHERE j.workspace_id=$1 AND j.id<>$2::uuid AND j.status='orphaned_unknown_effect'
    AND j.needs_operator_reconciliation=TRUE AND j.id IN (SELECT id FROM attempts)
    AND e.original_job_id IN (SELECT id FROM attempts)
  RETURNING e.enrollment_id,e.original_job_id`, [workspaceId, jobId, agentId]);
  if (!rows.length) return;
  const write = audit || require("../audit").writeAudit;
  await write({ client, workspaceId, actorUserId: null, subjectUserId: null, action: "CERTOPS_ACME_STORE_RECOVERY_RECONCILED",
    targetType: "certificate_job", targetId: null,
    metadata: { enrollmentId: rows[0].enrollment_id, originalJobId: rows[0].original_job_id, reconciliationJobId: jobId } });
}

module.exports = { createAcmeStoreEnrollmentTx, isAcmeStoreEnrollmentJob, cancelUnstartedAcmeStoreEnrollmentTx, applyAcmeStoreReceiptTx, loadAcmeStoreBindingTx, lookupAcmeStoreRecoveryByJob, continueAcmeStoreEnrollmentTx, reconcileAcmeStoreRecoveryTx };
