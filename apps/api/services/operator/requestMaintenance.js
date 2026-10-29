"use strict";

// Housekeeping for operator requests (ADR-0015 sections 8, 9 and 16).
//
// A request is only as good as the authority behind it. These functions end
// requests that can no longer be approved or run, so a request nobody acted on
// stops holding a capacity slot, blocking the scheduler or counting against the
// assistant's limits. They run in two places: inside the submit transaction, so
// limits never depend on a background job having run, and in the maintenance
// worker, so nothing lingers.
//
// Lock order matches the withdrawal path: the request row first, then the job
// row. Rows another transaction already holds are skipped, not waited for, so a
// sweep can never deadlock with an approval or a withdrawal; it simply gets
// them next time.

const REASONS = Object.freeze({
  WINDOW: "approval_window_ended",
  CONNECTION: "connection_expired",
  REQUESTER: "requester_lost_access",
  WRITES_OFF: "writes_disabled",
});

// Ends the job and marks its request in one statement. `where` is appended to a
// query that selects (request id, job id) pairs it has already locked.
async function endRequests(client, { selectSql, params, override, reason, statuses }) {
  const result = await client.query(
    `WITH locked AS (
       ${selectSql}
     ),
     ended AS (
       UPDATE certificate_jobs j
          SET status = 'cancelled', canceled_at = NOW(), updated_at = NOW(), error_code = $${params.length + 1}
         FROM locked
        WHERE j.id = locked.job_id AND j.status = ANY($${params.length + 2}::text[])
        RETURNING j.id
     )
     UPDATE operator_action_requests r
        SET state_override = $${params.length + 3}, state_reason = $${params.length + 1}, updated_at = NOW()
       FROM ended
      WHERE r.job_id = ended.id
      RETURNING r.id`,
    [...params, reason, statuses, override],
  );
  return result.rowCount || 0;
}

const WAITING = ["pending_approval"];
const UNCLAIMED = ["pending_approval", "approved", "pending"];

// Requests whose 24 hour approval window closed while nobody approved them.
function endLapsedWindows(client, workspaceId = null) {
  return endRequests(client, {
    selectSql: `SELECT r.id AS request_id, r.job_id
                  FROM operator_action_requests r
                  JOIN certificate_jobs j ON j.id = r.job_id AND j.workspace_id = r.workspace_id
                 WHERE r.state_override IS NULL
                   AND r.approval_expires_at <= NOW()
                   AND j.status = 'pending_approval'
                   AND ($1::uuid IS NULL OR r.workspace_id = $1::uuid)
                 FOR UPDATE OF r SKIP LOCKED`,
    params: [workspaceId],
    override: "expired",
    reason: REASONS.WINDOW,
    statuses: WAITING,
  });
}

// Work that was asked for by a connection that has since expired, or by a
// person who no longer holds the manager role the request needed. Revocation
// already ends a connection's work at the moment it happens; expiry and a
// demotion are just the passing of time or a change elsewhere, so they are
// found here. Only work nothing has picked up is touched: a job an agent has
// claimed runs on, to be handled by the existing reconciliation.
async function endOrphanedRequests(client, workspaceId = null) {
  const connectionEnded = await endRequests(client, {
    selectSql: `SELECT r.id AS request_id, r.job_id
                  FROM operator_action_requests r
                  JOIN certificate_jobs j ON j.id = r.job_id AND j.workspace_id = r.workspace_id
                  JOIN operator_connections c ON c.id = r.connection_id
                 WHERE r.state_override IS NULL
                   AND j.status IN ('pending_approval', 'approved', 'pending')
                   AND (c.status <> 'active' OR c.expires_at <= NOW())
                   AND ($1::uuid IS NULL OR r.workspace_id = $1::uuid)
                 FOR UPDATE OF r SKIP LOCKED`,
    params: [workspaceId],
    override: "cancelled",
    reason: REASONS.CONNECTION,
    statuses: UNCLAIMED,
  });
  const requesterLost = await endRequests(client, {
    selectSql: `SELECT r.id AS request_id, r.job_id
                  FROM operator_action_requests r
                  JOIN certificate_jobs j ON j.id = r.job_id AND j.workspace_id = r.workspace_id
                  JOIN workspaces w ON w.id = r.workspace_id
                  LEFT JOIN workspace_memberships m ON m.user_id = r.user_id AND m.workspace_id = r.workspace_id
                 WHERE r.state_override IS NULL
                   AND j.status IN ('pending_approval', 'approved', 'pending')
                   -- A membership row decides; with none, the workspace creator is an admin.
                   -- No role at all, or a role below manager, means the request has lost its basis.
                   AND COALESCE(m.role, CASE WHEN w.created_by = r.user_id THEN 'admin' END, 'none')
                       NOT IN ('workspace_manager', 'admin')
                   AND ($1::uuid IS NULL OR r.workspace_id = $1::uuid)
                 FOR UPDATE OF r SKIP LOCKED`,
    params: [workspaceId],
    override: "cancelled",
    reason: REASONS.REQUESTER,
    statuses: UNCLAIMED,
  });
  return connectionEnded + requesterLost;
}

// An admin switched assistant writes off: end waiting approvals and jobs queued
// without approval. Preserve jobs a person already approved.
function endWaitingForWorkspace(client, workspaceId) {
  return endRequests(client, {
    selectSql: `SELECT r.id AS request_id, r.job_id
                  FROM operator_action_requests r
                  JOIN certificate_jobs j ON j.id = r.job_id AND j.workspace_id = r.workspace_id
                 WHERE r.state_override IS NULL
                   AND (j.status = 'pending_approval'
                     OR (j.status = 'pending' AND j.approved_at IS NULL))
                   AND r.workspace_id = $1::uuid
                 FOR UPDATE OF r SKIP LOCKED`,
    params: [workspaceId],
    override: "cancelled",
    reason: REASONS.WRITES_OFF,
    statuses: ["pending_approval", "pending"],
  });
}

// One pass for the maintenance worker.
async function sweepOperatorRequests({ client }) {
  const lapsed = await endLapsedWindows(client);
  const orphaned = await endOrphanedRequests(client);
  return { lapsed, orphaned };
}

module.exports = { REASONS, endLapsedWindows, endOrphanedRequests, endWaitingForWorkspace, sweepOperatorRequests };
