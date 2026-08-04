/**
 * Operational failure notifications (worker side, ESM).
 *
 * Producers (delivery-worker, auto-sync-worker, ...) raise/resolve rows in
 * operational_notifications keyed by a stable dedupe_key scoped to the still
 * open incident. The partial unique index
 * uq_operational_notifications_open_dedupe (workspace_id, dedupe_key WHERE
 * resolved_at IS NULL) means a second raise for the same open incident
 * upserts in place (e.g. warning -> critical escalation) instead of creating
 * a duplicate row, while a new row is created once the prior incident of the
 * same key has resolved.
 */
import { logger } from "../logger.js";
import {
  sendEmailNotification,
  buildOperationalIncidentEmail,
} from "../notify/email.js";

const VALID_SEVERITIES = new Set(["info", "warning", "critical"]);
const VALID_CATEGORIES = new Set(["delivery", "auto_sync"]);

// Safety valve so a storm of incidents cannot flood a workspace's admins.
// Bell items are still created/updated above this cap; only the email send
// is skipped.
const DAILY_EMAIL_CAP = Number.isFinite(
  Number(process.env.OP_NOTIFICATION_EMAIL_DAILY_CAP),
)
  ? Number(process.env.OP_NOTIFICATION_EMAIL_DAILY_CAP)
  : 10;

/**
 * Raise (or escalate/update) an open operational notification.
 *
 * @param {import('pg').PoolClient} client
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
export async function raiseOperationalNotification(
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
  if (!workspaceId || !category || !type || !severity || !dedupeKey || !title) {
    logger.warn("raiseOperationalNotification: missing required fields", {
      workspaceId,
      category,
      type,
    });
    return null;
  }
  if (!VALID_CATEGORIES.has(category) || !VALID_SEVERITIES.has(severity)) {
    logger.warn("raiseOperationalNotification: invalid category/severity", {
      category,
      severity,
    });
    return null;
  }
  try {
    const res = await client.query(
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
    logger.warn("raiseOperationalNotification failed", {
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
export async function resolveOperationalNotification(
  client,
  workspaceId,
  dedupeKey,
) {
  if (!workspaceId || !dedupeKey) return;
  try {
    await client.query(
      `UPDATE operational_notifications
          SET resolved_at = NOW(), updated_at = NOW()
        WHERE workspace_id = $1 AND dedupe_key = $2 AND resolved_at IS NULL`,
      [workspaceId, dedupeKey],
    );
  } catch (err) {
    logger.warn("resolveOperationalNotification failed", {
      error: err.message,
      dedupeKey,
    });
  }
}

// Recipients for a critical incident email: the token's owner (if any) plus
// every workspace admin, deduplicated. Auto-sync incidents have no token_id
// (workspace-level), so they go to admins only.
async function resolveIncidentRecipients(client, { workspaceId, tokenId }) {
  const emails = new Set();
  try {
    if (tokenId) {
      const ownerRes = await client.query(
        `SELECT u.email FROM tokens t
           JOIN users u ON u.id = t.user_id
          WHERE t.id = $1 AND u.email IS NOT NULL`,
        [tokenId],
      );
      for (const row of ownerRes.rows) {
        if (row.email) emails.add(String(row.email).toLowerCase().trim());
      }
    }
    const adminRes = await client.query(
      `SELECT u.email FROM workspace_memberships wm
         JOIN users u ON u.id = wm.user_id
        WHERE wm.workspace_id = $1 AND wm.role = 'admin' AND u.email IS NOT NULL`,
      [workspaceId],
    );
    for (const row of adminRes.rows) {
      if (row.email) emails.add(String(row.email).toLowerCase().trim());
    }
  } catch (err) {
    logger.warn("resolveIncidentRecipients failed", {
      error: err.message,
      workspaceId,
      tokenId,
    });
  }
  return Array.from(emails);
}

/**
 * Send the email escalation for a critical operational notification.
 *
 * Call this right after `raiseOperationalNotification` returns an id for a
 * critical-severity incident, outside of the row's own transaction (mirrors
 * the autocommit-per-alert pattern already used by delivery-worker.js): an
 * SMTP outage must not roll back the bell row that reports the incident.
 *
 * Safeguards:
 * - Claims the row (`email_sent_at IS NULL`) before sending so concurrent
 *   workers or a re-raised escalation cannot double-send.
 * - Skips silently if the incident's own failing channel is email (recursion
 *   guard: a broken SMTP config would otherwise try to email about itself).
 * - Skips (but keeps the bell item) once the workspace has hit
 *   DAILY_EMAIL_CAP incident emails in the last 24h.
 *
 * @param {import('pg').PoolClient|import('pg').Pool} client
 * @param {Object} params
 * @param {string} params.notificationId
 * @param {string} params.workspaceId
 * @param {number|null} [params.tokenId]
 * @param {'delivery'|'auto_sync'} params.category
 * @param {string} params.title
 * @param {string|null} [params.message]
 * @param {Object} [params.metadata] - `metadata.channel === 'email'` triggers the recursion guard.
 */
export async function sendOperationalIncidentEmail(
  client,
  { notificationId, workspaceId, tokenId = null, category, title, message = null, metadata = {} },
) {
  if (!notificationId || !workspaceId || !category || !title) return;
  if (String(metadata?.channel || "").toLowerCase() === "email") {
    // Recursion guard: don't email about an incident whose failing channel
    // is email itself.
    return;
  }
  try {
    const claim = await client.query(
      `UPDATE operational_notifications
          SET email_sent_at = NOW()
        WHERE id = $1 AND email_sent_at IS NULL
      RETURNING id`,
      [notificationId],
    );
    if (claim.rows.length === 0) return; // already sent or resolved by another worker

    const capRes = await client.query(
      `SELECT COUNT(*)::int AS c
         FROM operational_notifications
        WHERE workspace_id = $1 AND email_sent_at > NOW() - INTERVAL '24 hours'`,
      [workspaceId],
    );
    if ((capRes.rows[0]?.c || 0) > DAILY_EMAIL_CAP) {
      logger.warn("Operational incident email skipped: daily cap reached", {
        workspaceId,
        notificationId,
      });
      return;
    }

    const recipients = await resolveIncidentRecipients(client, {
      workspaceId,
      tokenId,
    });
    if (recipients.length === 0) return;

    const { subject, html, text } = buildOperationalIncidentEmail({
      category,
      title,
      message,
      metadata,
    });

    for (const to of recipients) {
      const res = await sendEmailNotification({ to, subject, html, text });
      if (!res.success) {
        logger.warn("Operational incident email send failed", {
          error: res.error,
          workspaceId,
          notificationId,
          to,
        });
      }
    }
  } catch (err) {
    logger.warn("sendOperationalIncidentEmail failed", {
      error: err.message,
      notificationId,
      workspaceId,
    });
  }
}
