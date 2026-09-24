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
import { randomUUID } from "node:crypto";
import {
  sendEmailNotification,
  buildOperationalIncidentEmail,
} from "../notify/email.js";

const VALID_SEVERITIES = new Set(["info", "warning", "critical"]);
const VALID_CATEGORIES = new Set(["delivery", "auto_sync"]);
const EMAIL_RETRY_INTERVAL_MINUTES = 15;
const EMAIL_RETRY_BATCH_SIZE = 50;

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
          WHERE t.id = $1 AND t.workspace_id = $2 AND u.email IS NOT NULL`,
        [tokenId, workspaceId],
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
 * - Uses a separate expiring claim so concurrent workers cannot send twice,
 *   while failures remain retryable and email_sent_at records delivery only.
 * - Serializes each workspace's cap check and send with a PostgreSQL lock.
 * - Skips silently if the incident's own failing channel is email (recursion
 *   guard: a broken SMTP config would otherwise try to email about itself).
 * - Skips (but keeps the bell item) once the workspace has hit
 *   DAILY_EMAIL_CAP incident emails in the last 24h.
 *
 * @param {import('pg').PoolClient|import('pg').Client} client - Dedicated connection required for the workspace lock.
 * @param {Object} params
 * @param {string} params.notificationId
 * @param {string} params.workspaceId
 * @param {number|null} [params.tokenId]
 * @param {'delivery'|'auto_sync'} params.category
 * @param {string} params.title
 * @param {string|null} [params.message]
 * @param {Object} [params.metadata] - `failed_channels` or `channel` identifies email failures.
 */
export async function sendOperationalIncidentEmail(
  client,
  {
    notificationId,
    workspaceId,
    tokenId = null,
    category,
    title,
    message = null,
    metadata = {},
  },
  sendEmail = sendEmailNotification,
) {
  if (!notificationId || !workspaceId || !category || !title) return;
  const failedChannels = [
    ...(Array.isArray(metadata?.failed_channels)
      ? metadata.failed_channels
      : []),
    metadata?.channel,
  ];
  if (
    failedChannels.some(
      (channel) => String(channel || "").toLowerCase() === "email",
    )
  )
    return;
  const claimId = randomUUID();
  let claimed = false;
  let workspaceLocked = false;
  let delivered = false;
  try {
    // Serialize the cap check and final sent timestamp for this workspace.
    // Lock before claiming so waiting cannot consume the claim timeout.
    await client.query(
      "SELECT pg_advisory_lock(hashtextextended($1::text, 140))",
      [workspaceId],
    );
    workspaceLocked = true;

    const claim = await client.query(
      `UPDATE operational_notifications
          SET email_claim_id = $2, email_claimed_at = NOW()
        WHERE id = $1 AND workspace_id = $3 AND severity = 'critical'
          AND resolved_at IS NULL AND email_sent_at IS NULL
          AND LOWER(COALESCE(metadata->>'channel', '')) <> 'email'
          AND NOT EXISTS (
            SELECT 1
              FROM jsonb_array_elements_text(
                CASE WHEN jsonb_typeof(metadata->'failed_channels') = 'array'
                  THEN metadata->'failed_channels' ELSE '[]'::jsonb END
              ) AS failed(channel)
             WHERE LOWER(failed.channel) = 'email'
          )
          AND (email_claim_id IS NULL OR email_claimed_at < NOW() - INTERVAL '10 minutes')
      RETURNING id`,
      [notificationId, claimId, workspaceId],
    );
    if (claim.rows.length === 0) return;
    claimed = true;

    const capRes = await client.query(
      `SELECT COUNT(*)::int AS c
         FROM operational_notifications
        WHERE workspace_id = $1 AND email_sent_at > NOW() - INTERVAL '24 hours'`,
      [workspaceId],
    );
    if ((capRes.rows[0]?.c || 0) >= DAILY_EMAIL_CAP) {
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
      const res = await sendEmail({ to, subject, html, text });
      if (res.success) {
        delivered = true;
      } else {
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
  } finally {
    if (claimed) {
      try {
        // Keep the last attempt time after failure to pace retry sweeps;
        // clearing claim_id still makes the incident retryable.
        await client.query(
          `UPDATE operational_notifications
              SET email_sent_at = CASE WHEN $3 THEN NOW() ELSE email_sent_at END,
                  email_claim_id = NULL,
                  email_claimed_at = CASE WHEN $3 THEN NULL ELSE NOW() END
            WHERE id = $1 AND email_claim_id = $2`,
          [notificationId, claimId, delivered],
        );
      } catch (err) {
        logger.warn("Operational incident email claim release failed", {
          error: err.message,
          notificationId,
        });
      }
    }
    if (workspaceLocked) {
      try {
        await client.query(
          "SELECT pg_advisory_unlock(hashtextextended($1::text, 140))",
          [workspaceId],
        );
      } catch (err) {
        logger.warn("Operational incident email workspace unlock failed", {
          error: err.message,
          workspaceId,
        });
      }
    }
  }
}

/** Retry unsent critical incidents, including terminal delivery alerts. */
export async function retryPendingOperationalIncidentEmails(
  client,
  sendEmail = sendEmailNotification,
) {
  const pending = await client.query(
    `SELECT id, workspace_id, token_id, category, title, message, metadata
       FROM operational_notifications
      WHERE severity = 'critical'
        AND resolved_at IS NULL
        AND email_sent_at IS NULL
        AND (email_claimed_at IS NULL OR email_claimed_at < NOW() - ($1 * INTERVAL '1 minute'))
        AND LOWER(COALESCE(metadata->>'channel', '')) <> 'email'
        AND NOT EXISTS (
          SELECT 1
            FROM jsonb_array_elements_text(
              CASE WHEN jsonb_typeof(metadata->'failed_channels') = 'array'
                THEN metadata->'failed_channels' ELSE '[]'::jsonb END
            ) AS failed(channel)
           WHERE LOWER(failed.channel) = 'email'
        )
      -- Move attempted incidents behind untouched ones so failures cannot monopolize the batch.
      ORDER BY COALESCE(email_claimed_at, created_at) ASC, created_at ASC
      LIMIT $2`,
    [EMAIL_RETRY_INTERVAL_MINUTES, EMAIL_RETRY_BATCH_SIZE],
  );

  for (const row of pending.rows) {
    await sendOperationalIncidentEmail(
      client,
      {
        notificationId: row.id,
        workspaceId: row.workspace_id,
        tokenId: row.token_id,
        category: row.category,
        title: row.title,
        message: row.message,
        metadata: row.metadata,
      },
      sendEmail,
    );
  }
}
