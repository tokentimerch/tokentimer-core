/**
 * Operational failure notifications (API side, CJS).
 *
 * Mirrors apps/worker/src/shared/opNotifications.js. Producers raise/resolve
 * rows in operational_notifications keyed by a stable dedupe_key scoped to
 * the still-open incident. The partial unique index
 * uq_operational_notifications_open_dedupe (workspace_id, dedupe_key WHERE
 * resolved_at IS NULL) means a second raise for the same open incident
 * upserts in place (e.g. warning -> critical escalation) instead of creating
 * a duplicate row, while a new row is created once the prior incident of the
 * same key has resolved.
 */
const { pool } = require("../db/database");

const VALID_SEVERITIES = new Set(["info", "warning", "critical"]);
const VALID_CATEGORIES = new Set(["delivery", "auto_sync"]);

/**
 * Raise (or escalate/update) an open operational notification.
 *
 * @param {import('pg').PoolClient|import('pg').Pool} client
 * @param {Object} params
 * @param {string} params.workspaceId
 * @param {number|null} [params.tokenId]
 * @param {'delivery'|'auto_sync'} params.category
 * @param {string} params.type
 * @param {'info'|'warning'|'critical'} params.severity
 * @param {string} params.dedupeKey
 * @param {string} params.title
 * @param {string|null} [params.message]
 * @param {Object} [params.metadata]
 * @returns {Promise<string|null>} the notification id, or null on failure
 */
async function raiseOperationalNotification(
  client,
  {
    workspaceId,
    tokenId = null,
    category,
    type,
    severity,
    dedupeKey,
    title,
    message = null,
    metadata = {},
  },
) {
  const db = client || pool;
  if (!workspaceId || !category || !type || !severity || !dedupeKey || !title) {
    console.warn("raiseOperationalNotification: missing required fields", {
      workspaceId,
      category,
      type,
    });
    return null;
  }
  if (!VALID_CATEGORIES.has(category) || !VALID_SEVERITIES.has(severity)) {
    console.warn("raiseOperationalNotification: invalid category/severity", {
      category,
      severity,
    });
    return null;
  }
  try {
    const res = await db.query(
      `INSERT INTO operational_notifications
         (workspace_id, token_id, category, type, severity, dedupe_key, title, message, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (workspace_id, dedupe_key) WHERE resolved_at IS NULL
       DO UPDATE SET
         token_id = EXCLUDED.token_id,
         category = EXCLUDED.category,
         type = EXCLUDED.type,
         severity = EXCLUDED.severity,
         title = EXCLUDED.title,
         message = EXCLUDED.message,
         metadata = EXCLUDED.metadata,
         updated_at = NOW()
       RETURNING id`,
      [
        workspaceId,
        tokenId,
        category,
        type,
        severity,
        dedupeKey,
        title,
        message,
        JSON.stringify(metadata || {}),
      ],
    );
    return res.rows[0]?.id || null;
  } catch (err) {
    console.warn("raiseOperationalNotification failed", {
      error: err.message,
      dedupeKey,
    });
    return null;
  }
}

/**
 * Resolve the open operational notification (if any) for a dedupe key.
 * Safe to call even when no open notification exists.
 */
async function resolveOperationalNotification(client, workspaceId, dedupeKey) {
  const db = client || pool;
  if (!workspaceId || !dedupeKey) return;
  try {
    await db.query(
      `UPDATE operational_notifications
          SET resolved_at = NOW(), updated_at = NOW()
        WHERE workspace_id = $1 AND dedupe_key = $2 AND resolved_at IS NULL`,
      [workspaceId, dedupeKey],
    );
  } catch (err) {
    console.warn("resolveOperationalNotification failed", {
      error: err.message,
      dedupeKey,
    });
  }
}

module.exports = {
  raiseOperationalNotification,
  resolveOperationalNotification,
};
