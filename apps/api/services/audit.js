const { pool } = require("../db/database");

/**
 * Write an audit event to the database
 * @param {Object} params - Audit event parameters
 * @param {number|null} [params.actorUserId=null] - ID of the user performing the action
 * @param {number} params.subjectUserId - ID of the user the action relates to
 * @param {string} params.action - Action name (e.g., "USER_LOGIN", "TOKEN_CREATED")
 * @param {string|null} [params.targetType=null] - Type of target entity (e.g., "token", "workspace")
 * @param {number|string|null} [params.targetId=null] - ID of the target entity (must be integer, UUIDs stored as NULL)
 * @param {string|null} [params.channel=null] - Notification channel if applicable
 * @param {number|null} [params.workspaceId=null] - Workspace ID if applicable
 * @param {Object} [params.metadata={}] - Additional metadata object
 * @returns {Promise<void>}
 */

async function writeAudit({
  actorUserId = null,
  subjectUserId,
  action,
  targetType = null,
  targetId = null,
  channel = null,
  workspaceId = null,
  metadata = {},
}) {
  // Ensure target_id matches schema (INTEGER). If a UUID or non-integer is passed, store NULL.
  let safeTargetId = null;
  try {
    if (
      targetId !== null &&
      targetId !== undefined &&
      Number.isFinite(Number(targetId)) &&
      String(Number(targetId)) === String(targetId).trim()
    ) {
      safeTargetId = Number(targetId);
    }
  } catch (_) {
    /* noop */
  }
  await pool.query(
    `INSERT INTO audit_events (actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata, workspace_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      actorUserId,
      subjectUserId,
      action,
      targetType,
      safeTargetId,
      channel,
      metadata,
      workspaceId,
    ],
  );
}

module.exports = { writeAudit };
