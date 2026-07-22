"use strict";

/**
 * M5 CertOps human approval gates (plan control-plane orchestration).
 *
 * A certificate job created with requiresApproval starts at
 * pending_approval and is invisible to the agent claim path (which only
 * selects status = 'pending'). Three invariants are enforced here:
 *
 * 1. Non-requester rule: the user recorded as requested_by_user_id cannot
 *    approve their own job. Jobs requested via API token carry a null
 *    requested_by_user_id and may be approved by any authorized member,
 *    unless the token maps to the same session user (both ids present and
 *    equal).
 * 2. Payload-hash binding: every approval records a SHA256 hash of the
 *    canonical job payload at approval time, using the exact same
 *    canonical-JSON module the job-signing service uses
 *    (packages/contracts/certops/canonical-json.cjs), so the bound bytes
 *    can never drift from what the agent would be dispatched.
 * 3. Invalidation on edit: no human route mutates certificate_jobs.payload
 *    after creation today (the only writer is the controller-provisioning
 *    intent service, pre-dispatch, inside its own creation transaction),
 *    but the guard is enforced defensively anyway: the agent claim path
 *    re-hashes the current payload and, on mismatch with the stored
 *    approved_payload_hash, flips the job back to pending_approval and
 *    records an 'invalidated' ledger row instead of dispatching it.
 *
 * Decision history lives in the append-only certops_job_approvals table;
 * the current binding is denormalized onto certificate_jobs
 * (approved_by_user_id / approved_at / approved_payload_hash) so the claim
 * guard needs no join. Zero-custody: only hashes, ids, decisions, and
 * bounded public reasons are stored, never key material.
 */

const crypto = require("node:crypto");
const { pool } = require("../../db/database");
const {
  canonicalizeJobPayload,
} = require("../../../../packages/contracts/certops/canonical-json.cjs");
const {
  CERTOPS_JOB_NOT_FOUND,
  appendCertificateJobLog,
  jobFromRow,
  normalizeRequiredId,
  normalizeWorkspaceId,
  serviceError,
} = require("./jobs");

// --- Frozen error codes ---
// 403-shaped: the requester may not approve their own job.
const CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN =
  "CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN";
// 409-shaped: the job is not awaiting approval (already approved/rejected/
// running/terminal). Double-approve is a conflict, not an idempotent no-op,
// because the second decision may bind a different payload hash.
const CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL =
  "CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL";
// 400-shaped input errors.
const CERTOPS_APPROVAL_APPROVER_REQUIRED =
  "CERTOPS_APPROVAL_APPROVER_REQUIRED";
const CERTOPS_APPROVAL_REASON_INVALID = "CERTOPS_APPROVAL_REASON_INVALID";

const MAX_APPROVAL_REASON_LENGTH = 1024;

const SAFE_APPROVAL_SELECT_FIELDS = `
  id,
  workspace_id,
  job_id,
  decision,
  approved_by_user_id,
  payload_hash,
  reason,
  created_at
`;

function dateToIso(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function approvalFromRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    jobId: row.job_id,
    decision: row.decision,
    approvedByUserId: row.approved_by_user_id ?? null,
    payloadHash: row.payload_hash ?? null,
    reason: row.reason ?? null,
    createdAt: dateToIso(row.created_at),
  };
}

/**
 * SHA256 hex of the canonical serialization of a job payload. This is the
 * exact byte contract the job signer uses (canonical-json.cjs), so the
 * approval binds precisely the bytes an agent would receive.
 */
function computeJobPayloadApprovalHash(payload) {
  const canonical = canonicalizeJobPayload(
    payload && typeof payload === "object" && !Array.isArray(payload)
      ? payload
      : {},
  );
  return crypto.createHash("sha256").update(canonical, "utf8").digest("hex");
}

function normalizeApproverUserId(value) {
  if (value === undefined || value === null || value === "") {
    throw serviceError(
      "An authenticated approver user is required",
      CERTOPS_APPROVAL_APPROVER_REQUIRED,
    );
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value <= 0) {
      throw serviceError(
        "An authenticated approver user is required",
        CERTOPS_APPROVAL_APPROVER_REQUIRED,
      );
    }
    return value;
  }
  const parsed = Number.parseInt(String(value).trim(), 10);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw serviceError(
      "An authenticated approver user is required",
      CERTOPS_APPROVAL_APPROVER_REQUIRED,
    );
  }
  return parsed;
}

function normalizeReason(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw serviceError(
      "Approval reason is invalid",
      CERTOPS_APPROVAL_REASON_INVALID,
    );
  }
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.length > MAX_APPROVAL_REASON_LENGTH) {
    throw serviceError(
      "Approval reason is invalid",
      CERTOPS_APPROVAL_REASON_INVALID,
    );
  }
  return trimmed;
}

/**
 * Non-requester rule. requested_by_user_id is the authority: when it is set
 * and equals the approver, the approval is forbidden. Jobs requested via an
 * API token have requested_by_user_id = null and may be approved by any
 * authorized member (the token does not map to a session user in this
 * schema; if a caller resolves such a mapping it must pass the resolved id
 * as requestedByUserId at creation time to get self-approval protection).
 */
function assertNonRequester(job, approverUserId) {
  if (
    job.requestedByUserId !== null &&
    job.requestedByUserId !== undefined &&
    String(job.requestedByUserId) === String(approverUserId)
  ) {
    throw serviceError(
      "The user who requested a CertOps job cannot approve it",
      CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN,
    );
  }
}

async function loadJobForApproval(db, workspaceId, jobId) {
  const result = await db.query(
    `SELECT id, workspace_id, status, payload, requested_by_user_id,
            requested_by_api_token_id, approved_by_user_id, approved_at,
            approved_payload_hash
       FROM certificate_jobs
      WHERE workspace_id = $1
        AND id = $2
      LIMIT 1`,
    [workspaceId, jobId],
  );
  const row = result.rows[0];
  if (!row) {
    throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  }
  return jobFromRow(row);
}

async function insertApprovalDecision(db, {
  workspaceId,
  jobId,
  decision,
  approvedByUserId = null,
  payloadHash = null,
  reason = null,
}) {
  const result = await db.query(
    `INSERT INTO certops_job_approvals (
       workspace_id,
       job_id,
       decision,
       approved_by_user_id,
       payload_hash,
       reason
     )
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING ${SAFE_APPROVAL_SELECT_FIELDS}`,
    [workspaceId, jobId, decision, approvedByUserId, payloadHash, reason],
  );
  return approvalFromRow(result.rows[0]);
}

/**
 * Read model for the approval gate of one job: current status, whether the
 * job is awaiting approval, the current binding, and whether that binding
 * still matches the live payload (invalid = void, will be flipped back by
 * the claim guard).
 */
async function requestApprovalState(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId);

  const job = await loadJobForApproval(db, workspaceId, jobId);
  const currentPayloadHash = computeJobPayloadApprovalHash(job.payload);
  const approvalValid =
    job.approvedPayloadHash !== null &&
    job.approvedPayloadHash === currentPayloadHash;

  const history = await db.query(
    `SELECT ${SAFE_APPROVAL_SELECT_FIELDS}
       FROM certops_job_approvals
      WHERE workspace_id = $1
        AND job_id = $2
      ORDER BY created_at DESC, id ASC
      LIMIT 50`,
    [workspaceId, jobId],
  );

  return {
    jobId: job.id,
    workspaceId: job.workspaceId,
    status: job.status,
    awaitingApproval: job.status === "pending_approval",
    approvedByUserId: job.approvedByUserId,
    approvedAt: job.approvedAt,
    approvedPayloadHash: job.approvedPayloadHash,
    currentPayloadHash,
    approvalValid,
    decisions: history.rows.map(approvalFromRow),
  };
}

/**
 * Approve a pending_approval job: enforce the non-requester rule, bind the
 * canonical payload hash, move the job to the claimable 'pending' status,
 * persist the decision ledger row, and append the approval.granted job-log
 * event. The status write is a compare-and-swap on pending_approval so a
 * concurrent approve/reject/cancel loses cleanly with a conflict.
 *
 * The pending_approval -> approved -> pending hops are both legal in
 * JOB_STATUS_TRANSITIONS; approval applies them as one atomic composite
 * because an approved-but-not-yet-claimable intermediate state has no
 * separate meaning in this per-job gate.
 */
async function approveJob(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId);
  const approverUserId = normalizeApproverUserId(options.approverUserId);
  const reason = normalizeReason(options.reason);
  const logAppender = options.logAppender || appendCertificateJobLog;

  const job = await loadJobForApproval(db, workspaceId, jobId);
  if (job.status !== "pending_approval") {
    throw serviceError(
      "Certificate job is not awaiting approval",
      CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  }
  assertNonRequester(job, approverUserId);

  const payloadHash = computeJobPayloadApprovalHash(job.payload);

  const updated = await db.query(
    `UPDATE certificate_jobs
        SET status = 'pending',
            approved_by_user_id = $3,
            approved_at = NOW(),
            approved_payload_hash = $4,
            queued_at = COALESCE(queued_at, NOW()),
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2
        AND status = 'pending_approval'
      RETURNING id, status, approved_by_user_id, approved_at,
                approved_payload_hash`,
    [workspaceId, jobId, approverUserId, payloadHash],
  );
  const row = updated.rows[0];
  if (!row) {
    // Lost the compare-and-swap race: someone else decided first.
    throw serviceError(
      "Certificate job is not awaiting approval",
      CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  }

  const approval = await insertApprovalDecision(db, {
    workspaceId,
    jobId,
    decision: "approved",
    approvedByUserId: approverUserId,
    payloadHash,
    reason,
  });

  await logAppender({
    client: db,
    workspaceId,
    jobId,
    eventType: "approval.granted",
    status: "pending",
    message: reason,
    metadata: { payloadHash, approvedByUserId: String(approverUserId) },
    createdByUserId: approverUserId,
  });

  return {
    jobId: String(row.id),
    status: row.status,
    approvedByUserId: row.approved_by_user_id,
    approvedAt: dateToIso(row.approved_at),
    payloadHash: row.approved_payload_hash,
    approval,
  };
}

/**
 * Reject a pending_approval job: same non-requester-independent guards
 * (any authorized member including the requester may withdraw/reject),
 * terminal 'rejected' status, ledger row, approval.rejected log event.
 */
async function rejectJob(options) {
  const db = options.client || pool;
  const workspaceId = normalizeWorkspaceId(options.workspaceId);
  const jobId = normalizeRequiredId(options.jobId);
  const approverUserId = normalizeApproverUserId(options.approverUserId);
  const reason = normalizeReason(options.reason);
  const logAppender = options.logAppender || appendCertificateJobLog;

  const job = await loadJobForApproval(db, workspaceId, jobId);
  if (job.status !== "pending_approval") {
    throw serviceError(
      "Certificate job is not awaiting approval",
      CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  }

  const updated = await db.query(
    `UPDATE certificate_jobs
        SET status = 'rejected',
            error_code = 'CERTOPS_APPROVAL_REJECTED',
            error_message = $3,
            completed_at = COALESCE(completed_at, NOW()),
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2
        AND status = 'pending_approval'
      RETURNING id, status`,
    [workspaceId, jobId, reason],
  );
  const row = updated.rows[0];
  if (!row) {
    throw serviceError(
      "Certificate job is not awaiting approval",
      CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
    );
  }

  const approval = await insertApprovalDecision(db, {
    workspaceId,
    jobId,
    decision: "rejected",
    approvedByUserId: approverUserId,
    payloadHash: null,
    reason,
  });

  await logAppender({
    client: db,
    workspaceId,
    jobId,
    eventType: "approval.rejected",
    status: "rejected",
    message: reason,
    metadata: { rejectedByUserId: String(approverUserId) },
    createdByUserId: approverUserId,
  });

  return {
    jobId: String(row.id),
    status: row.status,
    approval,
  };
}

/**
 * Claim-side invalidation (called by agentDispatch inside the claim
 * transaction, on the same client). The caller already holds the row lock
 * (FOR UPDATE SKIP LOCKED) and has detected that the stored
 * approved_payload_hash no longer matches the current payload: void the
 * approval, flip the job back to pending_approval, record the ledger row
 * and the approval.invalidated log event. Never throws job-not-found; the
 * caller proved the row exists under lock.
 */
async function invalidateApprovalForClaim({
  client,
  workspaceId,
  jobId,
  staleHash,
  currentHash,
  logAppender = appendCertificateJobLog,
}) {
  await client.query(
    `UPDATE certificate_jobs
        SET status = 'pending_approval',
            approved_by_user_id = NULL,
            approved_at = NULL,
            approved_payload_hash = NULL,
            updated_at = NOW()
      WHERE workspace_id = $1
        AND id = $2`,
    [workspaceId, jobId],
  );

  const approval = await insertApprovalDecision(client, {
    workspaceId,
    jobId,
    decision: "invalidated",
    approvedByUserId: null,
    payloadHash: currentHash,
    reason:
      "Job payload changed after approval; the approval hash no longer matches",
  });

  await logAppender({
    client,
    workspaceId,
    jobId,
    eventType: "approval.invalidated",
    status: "pending_approval",
    message:
      "Approval voided: payload hash mismatch detected at claim time",
    metadata: {
      staleApprovedPayloadHash: staleHash || null,
      currentPayloadHash: currentHash,
    },
  });

  return approval;
}

module.exports = {
  CERTOPS_APPROVAL_APPROVER_REQUIRED,
  CERTOPS_APPROVAL_JOB_NOT_PENDING_APPROVAL,
  CERTOPS_APPROVAL_REASON_INVALID,
  CERTOPS_APPROVAL_SELF_APPROVAL_FORBIDDEN,
  MAX_APPROVAL_REASON_LENGTH,
  approveJob,
  computeJobPayloadApprovalHash,
  invalidateApprovalForClaim,
  rejectJob,
  requestApprovalState,
  _test: {
    approvalFromRow,
    assertNonRequester,
    normalizeApproverUserId,
    normalizeReason,
  },
};
