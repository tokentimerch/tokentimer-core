const { pool } = require("../db/database");
const { resolveOperationalNotification } = require("./operationalNotifications");

/**
 * Requeue failed/blocked alerts for a user or a specific workspace.
 *
 * @param {Object} params
 * @param {string} params.userId - The user's ID
 * @param {string} [params.workspaceId] - Optional workspace to scope the requeue to
 * @param {boolean} [params.includePlanLimitBlocked] - Whether to include PLAN_LIMIT blocked alerts
 * @returns {Promise<number>} Number of alerts requeued
 */
async function requeueAlertsCore({
  userId,
  workspaceId = null,
  includePlanLimitBlocked = false,
}) {
  if (!userId) return 0;
  if (workspaceId) {
    const blockedCondition = includePlanLimitBlocked
      ? `aq.status = 'blocked'`
      : `(aq.status = 'blocked' AND aq.error_message IS NOT NULL AND aq.error_message <> 'PLAN_LIMIT' AND aq.error_message NOT ILIKE '%PLAN_LIMIT%')`;
    const r = await pool.query(
      `UPDATE alert_queue aq
       SET status = 'pending', attempts = 0, attempts_email = 0, attempts_webhooks = 0, attempts_whatsapp = 0,
           error_message = NULL, next_attempt_at = NOW(), updated_at = NOW()
       FROM tokens t
       WHERE aq.token_id = t.id AND t.workspace_id = $1 AND aq.user_id = $2 AND (
         aq.status IN ('failed','limit_exceeded') OR
         (aq.status = 'partial' AND (aq.error_message IS NULL OR aq.error_message NOT ILIKE '%PLAN_LIMIT%')) OR
         ${blockedCondition}
       )
       RETURNING aq.id`,
      [workspaceId, userId],
    );
    await resolveRequeuedNotifications(r.rows, workspaceId);
    return r.rowCount || 0;
  }
  const blockedCondition = includePlanLimitBlocked
    ? `status = 'blocked'`
    : `(status = 'blocked' AND error_message IS NOT NULL AND error_message <> 'PLAN_LIMIT' AND error_message NOT ILIKE '%PLAN_LIMIT%')`;
  const r = await pool.query(
    `UPDATE alert_queue
     SET status = 'pending', attempts = 0, attempts_email = 0, attempts_webhooks = 0, attempts_whatsapp = 0,
         error_message = NULL, next_attempt_at = NOW(), updated_at = NOW()
     WHERE user_id = $1 AND (
       status IN ('failed','limit_exceeded') OR
       (status = 'partial' AND (error_message IS NULL OR error_message NOT ILIKE '%PLAN_LIMIT%')) OR
       ${blockedCondition}
     )
     RETURNING id, (SELECT workspace_id FROM tokens WHERE tokens.id = alert_queue.token_id) AS workspace_id`,
    [userId],
  );
  await resolveRequeuedNotifications(r.rows);
  return r.rowCount || 0;
}

/**
 * Clear any open delivery_blocked/delivery_degraded bell notification for
 * each alert row that was just moved back to 'pending'. Requeuing resets
 * attempts to 0, so the prior incident is no longer accurate; the delivery
 * worker will raise a fresh notification if the retry fails again.
 *
 * @param {Array<{id: number|string, workspace_id?: string}>} rows
 * @param {string} [fixedWorkspaceId] - Use this workspace id for every row
 *   instead of reading it off the row (workspace-scoped call site already
 *   knows it).
 */
async function resolveRequeuedNotifications(rows, fixedWorkspaceId = null) {
  if (!Array.isArray(rows) || rows.length === 0) return;
  await Promise.all(
    rows.map(async (row) => {
      const wsId = fixedWorkspaceId || row.workspace_id;
      if (!wsId) return;
      await resolveOperationalNotification(
        pool,
        wsId,
        `delivery_blocked:${row.id}`,
      );
      await resolveOperationalNotification(
        pool,
        wsId,
        `delivery_degraded:${row.id}`,
      );
    }),
  );
}

module.exports = { requeueAlertsCore };
