"use strict";

// Preview, submit, read and withdraw a renew request. See actionRequests.js
// for the ordering rules every function here follows.

const { randomUUID } = require("node:crypto");
const base = require("./actionRequests");
const { CODES, fail, snake, authorize } = base;
const { crypto: _c, reads, hashPlan, renewEffect, lockWorkspaceForCertOpsSideEffect, loadManagedCertificateForRenewal, manualRenewalJobCreator, preflightManualRenewalJob } = base._deps;
const { PLAN_TTL_MS, APPROVAL_TTL_MS, MAX_PENDING_PER_CONNECTION } = base;
const { untrustedText } = require("./projections");
const { resolveRenewalPerCaCap } = require("../certops/renewalCapacity");

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Resolve the caller's handle (an identity id) to the managed certificate a
// renewal acts on, refusing anything that cannot be renewed.
async function resolveRenewable({ workspaceId, identityId }) {
  if (!UUID.test(String(identityId || ""))) throw fail(CODES.NOT_FOUND, "Not found");
  const record = await reads.loadIdentity({ workspaceId, identityId });
  if (!record) throw fail(CODES.NOT_FOUND, "Not found");
  if (record.lifecycleStatus && record.lifecycleStatus !== "active") {
    throw fail(CODES.RETIRED, "The certificate is retired, so it cannot be renewed");
  }
  if (!record.managedCertificateId) {
    throw fail(CODES.NOT_MANAGED, "TokenTimer is not managing this certificate, so it cannot be renewed");
  }
  return record;
}

async function createRenewPlan({ client, operator, identityId, now = new Date() }) {
  await authorize({ client, operator });
  const record = await resolveRenewable({ workspaceId: operator.workspaceId, identityId });

  const certificate = await loadManagedCertificateForRenewal({
    db: client,
    workspaceId: operator.workspaceId,
    certificateId: record.managedCertificateId,
  });
  if (!certificate) throw fail(CODES.NOT_FOUND, "Not found");

  // The same validation a real renewal runs, writing nothing. If it would be
  // refused, the preview says so now instead of after someone approves it.
  try {
    await preflightManualRenewalJob({
      client,
      workspaceId: operator.workspaceId,
      certificateId: record.managedCertificateId,
      payload: {},
    });
  } catch (error) {
    throw fail(CODES.NOT_POSSIBLE, "A renewal cannot be requested for this certificate", {
      reason: snake(error.code),
    });
  }

  const ws = await client.query(
    "SELECT certops_paused, certops_require_approval_always FROM workspaces WHERE id = $1",
    [operator.workspaceId],
  );
  const effect = renewEffect({
    certificate,
    workspacePaused: ws.rows[0]?.certops_paused === true,
    requireApprovalAlways: ws.rows[0]?.certops_require_approval_always === true,
  });
  const fingerprint = (record.fingerprintSha256 || "").toLowerCase() || null;
  const planHash = hashPlan({
    operation: "renew",
    workspaceId: operator.workspaceId,
    connectionId: operator.connectionId,
    subjectId: record.managedCertificateId,
    boundFingerprint: fingerprint,
    boundProfileId: certificate.profile_id || null,
    effect,
  });
  const expiresAt = new Date(now.getTime() + PLAN_TTL_MS);
  const inserted = await client.query(
    `INSERT INTO operator_action_plans
       (workspace_id, connection_id, operation, identity_id, subject_id,
        bound_fingerprint_sha256, bound_profile_id, plan_hash, effect, created_at, expires_at)
     VALUES ($1, $2, 'renew', $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
     RETURNING id`,
    [
      operator.workspaceId,
      operator.connectionId,
      identityId,
      record.managedCertificateId,
      fingerprint,
      certificate.profile_id || null,
      planHash,
      JSON.stringify(effect),
      now,
      expiresAt,
    ],
  );
  return { planId: inserted.rows[0].id, planHash, expiresAt: expiresAt.toISOString(), effect };
}

// The request as the caller sees it. State comes from the job where the job can
// say it, so there is never a second copy of "approved" or "running" to drift.
const JOB_STATE = Object.freeze({
  pending_approval: "pending_approval",
  approved: "approved",
  pending: "approved",
  claimed: "executing",
  running: "executing",
  succeeded: "succeeded",
  failed: "failed",
  rejected: "rejected",
  cancelled: "cancelled",
  blocked: "failed",
  dry_run_complete: "succeeded",
  orphaned_unknown_effect: "failed",
  awaiting_issuer: "executing",
});

function requestView(row, job, { replayed = false } = {}) {
  let state;
  let reason = row.state_reason || null;
  if (row.state_override) {
    state = row.state_override;
  } else if (job) {
    state = JOB_STATE[job.status] || "failed";
    if (job.status === "pending_approval" && new Date(row.approval_expires_at) <= new Date()) {
      state = "expired";
      reason = reason || "approval_window_ended";
    }
    if (!reason && job.error_code) reason = snake(job.error_code);
  } else {
    state = "failed";
  }
  return {
    requestRecordId: row.id,
    requestId: row.request_id,
    state,
    stateReason: reason,
    jobId: job ? job.id : null,
    replayed,
    approvalExpiresAt: row.approval_expires_at ? new Date(row.approval_expires_at).toISOString() : null,
  };
}

async function loadRequestRow(client, { connectionId, requestId }) {
  const found = await client.query(
    "SELECT * FROM operator_action_requests WHERE connection_id = $1 AND request_id = $2",
    [connectionId, requestId],
  );
  return found.rows[0] || null;
}

async function loadJob(client, workspaceId, jobId) {
  if (!jobId) return null;
  const found = await client.query(
    "SELECT id, status, error_code FROM certificate_jobs WHERE workspace_id = $1 AND id = $2",
    [workspaceId, jobId],
  );
  return found.rows[0] || null;
}

async function submitRenewRequest({ client, operator, planId, planHash, requestId, now = new Date() }) {
  await authorize({ client, operator });
  if (!UUID.test(String(requestId || "")) || !UUID.test(String(planId || ""))) {
    throw fail(CODES.PLAN_MISMATCH, "The plan does not match");
  }

  // 1. Replay comes first. A lost response must never be answered with
  // "preview expired", and replay never re-executes anything.
  //
  // Two submissions of the same request id can arrive together. Taking a lock
  // keyed on (connection, request id) makes the second one wait for the first
  // to commit, so it then finds the committed request and replays it, instead
  // of both passing the lookup and one failing on the unique constraint.
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
    `operator-request:${operator.connectionId}:${requestId}`,
  ]);
  const existing = await loadRequestRow(client, { connectionId: operator.connectionId, requestId });
  if (existing) {
    if (existing.plan_id !== planId || existing.plan_hash !== planHash) {
      throw fail(CODES.CONFLICT, "This request id was already used for something different");
    }
    const job = await loadJob(client, operator.workspaceId, existing.job_id);
    return requestView(existing, job, { replayed: true });
  }

  // 2. A new submission must match a live plan that belongs to this connection.
  const planRow = await client.query(
    "SELECT * FROM operator_action_plans WHERE workspace_id = $1 AND id = $2 AND connection_id = $3 FOR UPDATE",
    [operator.workspaceId, planId, operator.connectionId],
  );
  const plan = planRow.rows[0];
  // Another connection's plan and a missing one are indistinguishable.
  if (!plan || plan.plan_hash !== planHash) throw fail(CODES.PLAN_MISMATCH, "The plan does not match");
  if (new Date(plan.expires_at) <= now) throw fail(CODES.PLAN_EXPIRED, "The preview has expired; preview again");

  // 3. Bounded bookkeeping: unapproved requests are not free. They count
  // against the same per-CA capacity that real and scheduled renewals use, so
  // one connection that is never approved could otherwise fill it and block
  // everyone else. Assistant requests that are still waiting are therefore
  // limited per connection and, more tightly, across the whole workspace to
  // half the shared cap, which always leaves room for people and the scheduler.
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [
    `operator-pending:${operator.workspaceId}`,
  ]);
  const waiting = await client.query(
    `SELECT COUNT(*)::int AS workspace_total,
            COUNT(*) FILTER (WHERE requested_by_connection_id = $2)::int AS mine
       FROM certificate_jobs
      WHERE workspace_id = $1 AND status = 'pending_approval'
        AND requested_by_connection_id IS NOT NULL`,
    [operator.workspaceId, operator.connectionId],
  );
  const workspaceLimit = Math.max(1, Math.floor(resolveRenewalPerCaCap() / 2));
  if (waiting.rows[0].mine >= MAX_PENDING_PER_CONNECTION || waiting.rows[0].workspace_total >= workspaceLimit) {
    throw fail(CODES.PENDING_LIMIT, "Too many assistant requests are waiting for approval");
  }

  // 4. The workspace must still allow new work. Taking this lock is what makes
  // a pause that commits first visible here.
  await lockWorkspaceForCertOpsSideEffect({ client, workspaceId: operator.workspaceId });

  // 5. The world must still be what was previewed.
  const record = await reads.loadIdentity({ workspaceId: operator.workspaceId, identityId: plan.identity_id });
  const certificate = record
    ? await loadManagedCertificateForRenewal({ db: client, workspaceId: operator.workspaceId, certificateId: plan.subject_id })
    : null;
  const stillSame =
    record &&
    certificate &&
    record.managedCertificateId === plan.subject_id &&
    (record.fingerprintSha256 || "").toLowerCase() === (plan.bound_fingerprint_sha256 || "") &&
    (certificate.profile_id || null) === (plan.bound_profile_id || null) &&
    (!record.lifecycleStatus || record.lifecycleStatus === "active");
  if (!stillSame) throw fail(CODES.INTENT_STALE, "The certificate changed since the preview; preview again");

  // 6. The job goes through the existing path, so approval, per-CA caps, the
  // lifecycle checks and the dispatch guards all apply unchanged. It always
  // requires approval, and the requester is the connection's person.
  const requestRecordId = randomUUID();
  const created = await manualRenewalJobCreator({ certificateId: plan.subject_id })({
    client,
    workspaceId: operator.workspaceId,
    subjectType: "managed_certificate",
    subjectId: plan.subject_id,
    payload: {},
    source: "api",
    requestedByUserId: operator.userId,
    requestedByConnectionId: operator.connectionId,
    requiresApproval: true,
    idempotencyKey: `mcp-renew:${requestRecordId}`,
    returnOutcome: true,
  });
  const job = created.job || created;

  const approvalExpiresAt = new Date(now.getTime() + APPROVAL_TTL_MS);
  const inserted = await client.query(
    `INSERT INTO operator_action_requests
       (id, workspace_id, connection_id, user_id, request_id, plan_id, plan_hash,
        operation, identity_id, subject_id, job_id, approval_expires_at, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, 'renew', $8, $9, $10, $11, $12, $12)
     RETURNING *`,
    [requestRecordId, operator.workspaceId, operator.connectionId, operator.userId, requestId, planId, planHash, plan.identity_id, plan.subject_id, job.id, approvalExpiresAt, now],
  );
  return requestView(inserted.rows[0], { id: job.id, status: job.status, error_code: null });
}

// Only a connection's own requests are visible to it. Another connection's
// request and a missing one are the same 404.
async function getRequest({ client, operator, requestRecordId }) {
  if (!UUID.test(String(requestRecordId || ""))) throw fail(CODES.NOT_FOUND, "Not found");
  const found = await client.query(
    "SELECT * FROM operator_action_requests WHERE id = $1 AND connection_id = $2 AND workspace_id = $3",
    [requestRecordId, operator.connectionId, operator.workspaceId],
  );
  const row = found.rows[0];
  if (!row) throw fail(CODES.NOT_FOUND, "Not found");
  return requestView(row, await loadJob(client, operator.workspaceId, row.job_id));
}

async function listRequests({ client, operator, limit = 25, offset = 0 }) {
  const rows = await client.query(
    `SELECT * FROM operator_action_requests
      WHERE connection_id = $1 AND workspace_id = $2
      ORDER BY created_at DESC, id ASC LIMIT $3 OFFSET $4`,
    [operator.connectionId, operator.workspaceId, limit, offset],
  );
  const total = await client.query(
    "SELECT COUNT(*)::int AS n FROM operator_action_requests WHERE connection_id = $1 AND workspace_id = $2",
    [operator.connectionId, operator.workspaceId],
  );
  const items = [];
  for (const row of rows.rows) {
    items.push(requestView(row, await loadJob(client, operator.workspaceId, row.job_id)));
  }
  return { items, total: total.rows[0].n };
}

// Withdraw a request that is still waiting for approval (ADR-0015 section 11).
// Authentication, scope and ownership still apply, but the write gates and the
// workspace pause do not: being able to take a request back must not depend on
// new work being allowed. Withdrawal and approval race on the job row, and
// exactly one wins.
async function cancelRequest({ client, operator, requestRecordId }) {
  await authorize({ client, operator, requireGates: false });
  if (!UUID.test(String(requestRecordId || ""))) throw fail(CODES.NOT_FOUND, "Not found");
  const found = await client.query(
    `SELECT * FROM operator_action_requests
      WHERE id = $1 AND connection_id = $2 AND workspace_id = $3 FOR UPDATE`,
    [requestRecordId, operator.connectionId, operator.workspaceId],
  );
  const row = found.rows[0];
  if (!row) throw fail(CODES.NOT_FOUND, "Not found");
  if (row.state_override === "cancelled") {
    return requestView(row, await loadJob(client, operator.workspaceId, row.job_id), { replayed: true });
  }
  const cancelled = await client.query(
    `UPDATE certificate_jobs
        SET status = 'cancelled', canceled_at = NOW(), updated_at = NOW(),
            error_code = 'withdrawn_by_requester'
      WHERE workspace_id = $1 AND id = $2 AND status = 'pending_approval'
      RETURNING id`,
    [operator.workspaceId, row.job_id],
  );
  if (!cancelled.rows[0]) {
    // Approval got there first (or the job moved on). Say so; do not claim
    // that anything was prevented.
    throw fail(CODES.NOT_CANCELLABLE, "The request is no longer waiting for approval");
  }
  const updated = await client.query(
    `UPDATE operator_action_requests
        SET state_override = 'cancelled', state_reason = 'withdrawn_by_requester', updated_at = NOW()
      WHERE id = $1 RETURNING *`,
    [row.id],
  );
  return requestView(updated.rows[0], { id: row.job_id, status: "cancelled", error_code: null });
}

module.exports = {
  createRenewPlan,
  submitRenewRequest,
  getRequest,
  listRequests,
  cancelRequest,
  requestView,
  resolveRenewable,
  _shared: { UUID, randomUUID, untrustedText, lockWorkspaceForCertOpsSideEffect, manualRenewalJobCreator, loadManagedCertificateForRenewal, APPROVAL_TTL_MS, MAX_PENDING_PER_CONNECTION, hashPlan },
};
