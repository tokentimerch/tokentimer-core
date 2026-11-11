"use strict";

function stale() {
  const error = new Error("Rollout authority changed; request a new rollout");
  error.code = "CERTOPS_DISTRIBUTION_AUTHORIZATION_STALE";
  error.statusCode = 409;
  throw error;
}

// Call inside the same transaction as expansion, claim, lease renewal or
// retry. The workspace row lock also fences membership updates: their trigger
// cannot commit until it can advance the workspace revision.
async function assertManualRolloutAuthority(client, workspaceId, groupId, approvalJobId) {
  const workspace = (await client.query(`SELECT created_by,certops_paused,
    certops_require_approval_always,certops_manual_rollout_revision
    FROM workspaces WHERE id=$1 FOR SHARE`, [workspaceId])).rows[0];
  const job = (await client.query(`SELECT * FROM certificate_jobs
    WHERE workspace_id=$1 AND id=$2 FOR SHARE`, [workspaceId, approvalJobId])).rows[0];
  const intent = job?.payload?.distributionRollout;
  if (!workspace || workspace.certops_paused || !intent || intent.groupId !== groupId ||
      !["pending", "succeeded"].includes(job.status) ||
      intent.manualRolloutAuthorizationRevision !== String(workspace.certops_manual_rollout_revision)) stale();
  const members = (await client.query(`SELECT user_id FROM workspace_memberships
    WHERE workspace_id=$1 AND role IN ('admin','workspace_manager')`, [workspaceId])).rows;
  const authorized = new Set([workspace.created_by, ...members.map(row => row.user_id)].map(String));
  if (job.requested_by_user_id == null || !authorized.has(String(job.requested_by_user_id))) stale();
  if (job.approved_payload_hash) {
    const approvals = require("./jobApprovals");
    if (!job.approved_at || job.approved_by_user_id == null ||
        !authorized.has(String(job.approved_by_user_id)) ||
        String(job.approved_by_user_id) === String(job.requested_by_user_id) ||
        approvals.computeJobPayloadApprovalHash(job.payload) !== job.approved_payload_hash ||
        approvals.computeCanonicalIntentHash({ operation: job.operation, subjectType: job.subject_type,
          subjectId: job.subject_id, payload: job.payload }) !== job.approved_canonical_intent_hash) stale();
  } else if (workspace.certops_require_approval_always) stale();
}

module.exports = { assertManualRolloutAuthority };
