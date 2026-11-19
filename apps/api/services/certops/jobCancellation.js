"use strict";

const { writeAudit } = require("../audit");
const { closeClaimStreamSafely } = require("./agentJobLogs");
const { isMarkedAdcsJob } = require("./jobPendingReason");
const {
  CERTOPS_JOB_NOT_FOUND,
  appendCertificateJobLog,
  isTerminalJobStatus,
  isTrustAnchorOperation,
  serviceError,
  updateCertificateJobStatus,
} = require("./jobs");
const { onTrustJobTerminalTransition } = require("./trustAnchors");

const CERTOPS_JOB_CANCELLATION_UNAVAILABLE = "CERTOPS_JOB_CANCELLATION_UNAVAILABLE";
const CERTOPS_JOB_CANCELLATION_UNSUPPORTED = "CERTOPS_JOB_CANCELLATION_UNSUPPORTED";
const CERTOPS_JOB_CANCELLATION_FORBIDDEN = "CERTOPS_JOB_CANCELLATION_FORBIDDEN";
const UNKNOWN_EFFECT_REASON = "operator_cancelled_after_execution_started";
const READ_ONLY_OPERATIONS = new Set(["noop", "adcs-preflight"]);

const MATERIAL_JOB_FIELDS = [
  "publication", "materialDeployment", "materialCleanup", "materialReconciliation",
  "distributionRollout",
];
const NO_AGENT_DISPATCH = "Only agent jobs waiting for approval or bound to an agent can be cancelled here";

function cancellationBlockReason(job) {
  // A restarted job can still carry unresolved effects from its last attempt.
  if (job.needsOperatorReconciliation) return "Reconcile the previous attempt before cancelling this job";
  if (job.enrollmentId || isMarkedAdcsJob(job)) {
    return "Use the AD CS enrollment controls to cancel or recover this job";
  }
  if (MATERIAL_JOB_FIELDS.some(field => job.payload?.[field])) {
    return "Use the distribution lifecycle controls to manage this job";
  }
  if (job.executorKind !== "agent" || ["executor", "external", "controller_provisioning"].includes(job.source)) {
    return NO_AGENT_DISPATCH;
  }
  if (job.status === "pending_approval") return null;
  if ((job.status === "pending" || job.status === "approved") && job.assignedAgentId) return null;
  if ((job.status === "claimed" || job.status === "running") && job.claimedByAgentId && job.claimId) {
    return null;
  }
  return NO_AGENT_DISPATCH;
}

function canCancelCertOpsJob(job, { canManageTrustAnchors = false } = {}) {
  return (!isTrustAnchorOperation(job.operation) || canManageTrustAnchors) &&
    cancellationBlockReason(job) === null;
}

async function cancelCertificateJob({ client, workspaceId, jobId, actorUserId, canManageTrustAnchors = false }) {
  if (!actorUserId) throw new TypeError("Certificate job cancellation requires an actor");
  // The row lock orders cancellation with lease confirmation and result ingest.
  const { rows: [job] } = await client.query(
    `SELECT id, status, mode, operation, source, payload, enrollment_id AS "enrollmentId",
            COALESCE(executor_kind, 'agent') AS "executorKind", assigned_agent_id AS "assignedAgentId",
            claimed_by_agent_id AS "claimedByAgentId", claim_id AS "claimId", lease_renewed_at,
            needs_operator_reconciliation AS "needsOperatorReconciliation"
       FROM certificate_jobs
      WHERE workspace_id = $1 AND id = $2
      FOR UPDATE`,
    [workspaceId, jobId],
  );
  if (!job) throw serviceError("Certificate job not found", CERTOPS_JOB_NOT_FOUND);
  if (isTrustAnchorOperation(job.operation) && !canManageTrustAnchors) {
    throw serviceError("Only workspace administrators can cancel trust anchor jobs", CERTOPS_JOB_CANCELLATION_FORBIDDEN);
  }
  if (isTerminalJobStatus(job.status)) {
    throw serviceError("Certificate job has already finished", CERTOPS_JOB_CANCELLATION_UNAVAILABLE);
  }
  const blocked = cancellationBlockReason(job);
  if (blocked) {
    throw serviceError(blocked, CERTOPS_JOB_CANCELLATION_UNSUPPORTED);
  }

  // Dispatched agents must confirm their initial lease before they execute.
  // The confirmation sets running and lease_renewed_at under the same lock.
  const needsOperatorReconciliation = job.mode !== "dry_run" && !READ_ONLY_OPERATIONS.has(job.operation) &&
    (job.status === "running" || (job.status === "claimed" && job.lease_renewed_at != null));
  const status = needsOperatorReconciliation ? "orphaned_unknown_effect" : "cancelled";
  const message = needsOperatorReconciliation
    ? "Operator cancelled control-plane execution after work may have started. Verify the host before retrying."
    : "Operator cancelled this job.";
  const outcome = await updateCertificateJobStatus({
    client, workspaceId, jobId, status,
    ...(needsOperatorReconciliation ? { errorCode: "effects_unknown", errorMessage: message } : {}),
  });
  if (!outcome.statusTransitionApplied) {
    throw serviceError("Certificate job has already finished", CERTOPS_JOB_CANCELLATION_UNAVAILABLE);
  }

  await client.query(
    `UPDATE certificate_jobs
        SET completed_at = COALESCE(completed_at, NOW()),
            lease_expires_at = CASE WHEN lease_expires_at IS NULL THEN NULL ELSE NOW() END,
            needs_operator_reconciliation = needs_operator_reconciliation OR $3::boolean,
            reconciliation_reason = COALESCE($4, reconciliation_reason)
      WHERE workspace_id = $1 AND id = $2`,
    [workspaceId, jobId, needsOperatorReconciliation,
      needsOperatorReconciliation ? UNKNOWN_EFFECT_REASON : null],
  );
  await closeClaimStreamSafely(client, { workspaceId, jobId, claimId: job.claimId });
  if (!needsOperatorReconciliation) {
    await onTrustJobTerminalTransition({ client, job: { ...job, workspaceId, status } });
  }
  const metadata = { previousStatus: job.status, needsOperatorReconciliation };
  await appendCertificateJobLog({
    client, workspaceId, jobId, eventType: "job.cancelled", status, message, metadata,
    createdByUserId: actorUserId,
  });
  await writeAudit({
    client, workspaceId, actorUserId, subjectUserId: actorUserId,
    action: "CERTOPS_JOB_CANCELLED", targetType: "certificate_job", targetId: jobId,
    metadata: { jobId, status, ...metadata },
  });
  return { jobId, status, needsOperatorReconciliation };
}

module.exports = {
  CERTOPS_JOB_CANCELLATION_FORBIDDEN,
  CERTOPS_JOB_CANCELLATION_UNAVAILABLE,
  CERTOPS_JOB_CANCELLATION_UNSUPPORTED,
  canCancelCertOpsJob,
  cancelCertificateJob,
};
