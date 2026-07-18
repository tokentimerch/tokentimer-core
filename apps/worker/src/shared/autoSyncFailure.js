import { logger } from "../logger.js";
import {
  raiseOperationalNotification,
  resolveOperationalNotification,
  sendOperationalIncidentEmail,
} from "./opNotifications.js";

// Consecutive failed runs at/above which an auto-sync incident escalates
// from a bell-only warning to a critical (emailed) incident.
const AUTO_SYNC_CRITICAL_THRESHOLD = Number.isFinite(
  Number(process.env.AUTO_SYNC_CRITICAL_THRESHOLD),
)
  ? Number(process.env.AUTO_SYNC_CRITICAL_THRESHOLD)
  : 3;

/**
 * Prefer API error body over generic Axios message for last_sync_error / audit.
 */
export function formatAutoSyncError(err) {
  const body = err?.response?.data;
  if (body && typeof body.error === "string" && body.error.trim()) {
    return body.error.trim().substring(0, 1000);
  }
  if (body && typeof body.message === "string" && body.message.trim()) {
    return body.message.trim().substring(0, 1000);
  }
  return String(err?.message || err).substring(0, 1000);
}

async function resolveAuditSubjectUserId(client, workspaceId, createdBy) {
  if (createdBy) return createdBy;
  const adminRes = await client.query(
    `SELECT user_id FROM workspace_memberships
     WHERE workspace_id = $1 AND role = 'admin'
     ORDER BY user_id ASC LIMIT 1`,
    [workspaceId],
  );
  if (adminRes.rows[0]?.user_id) return adminRes.rows[0].user_id;
  const mgrRes = await client.query(
    `SELECT user_id FROM workspace_memberships
     WHERE workspace_id = $1 AND role = 'workspace_manager'
     ORDER BY user_id ASC LIMIT 1`,
    [workspaceId],
  );
  return mgrRes.rows[0]?.user_id || null;
}

async function writeAutoSyncAudit(
  client,
  { workspaceId, subjectUserId, action, metadata },
) {
  if (!subjectUserId) return;
  await client.query(
    `INSERT INTO audit_events
       (actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata, workspace_id)
     VALUES (NULL, $1, $2, 'auto_sync_config', NULL, NULL, $3, $4)`,
    [subjectUserId, action, metadata, workspaceId],
  );
}

/**
 * Persist auto-sync failure and emit AUTO_SYNC_FAILED audit on first transition
 * into failed state (avoids hourly duplicate audit rows). Also tracks a
 * consecutive_failures counter and raises a bell notification: warning on the
 * first failure, escalating to critical once AUTO_SYNC_CRITICAL_THRESHOLD
 * consecutive failures are reached.
 */
export async function recordAutoSyncFailure(
  client,
  {
    configId,
    workspaceId,
    provider,
    createdBy = null,
    previousStatus = null,
    errorMessage,
    httpStatus = null,
    nextSync,
  },
) {
  const updateRes = await client.query(
    `UPDATE auto_sync_configs
     SET last_sync_at = NOW(), last_sync_status = 'failed',
         last_sync_error = $1, next_sync_at = $2, updated_at = NOW(),
         consecutive_failures = consecutive_failures + 1
     WHERE id = $3
     RETURNING consecutive_failures`,
    [errorMessage, nextSync, configId],
  );
  const consecutiveFailures = updateRes.rows[0]?.consecutive_failures || 1;

  if (workspaceId) {
    const critical = consecutiveFailures >= AUTO_SYNC_CRITICAL_THRESHOLD;
    const notifId = await raiseOperationalNotification(client, {
      workspaceId,
      tokenId: null,
      category: "auto_sync",
      type: "auto_sync_failed",
      severity: critical ? "critical" : "warning",
      dedupeKey: `auto_sync_failed:${configId}`,
      title: critical
        ? `Auto-sync failing repeatedly: ${provider}`
        : `Auto-sync failed: ${provider}`,
      message: errorMessage || "Auto-sync run failed",
      metadata: {
        config_id: configId,
        provider,
        http_status: httpStatus,
        consecutive_failures: consecutiveFailures,
      },
    });
    if (notifId && critical) {
      await sendOperationalIncidentEmail(client, {
        notificationId: notifId,
        workspaceId,
        tokenId: null,
        category: "auto_sync",
        title: `Auto-sync failing repeatedly: ${provider}`,
        message: errorMessage || "Auto-sync run failed",
        metadata: { provider, consecutive_failures: consecutiveFailures },
      });
    }
  }

  if (previousStatus === "failed") return;

  try {
    const subjectUserId = await resolveAuditSubjectUserId(
      client,
      workspaceId,
      createdBy,
    );
    await writeAutoSyncAudit(client, {
      workspaceId,
      subjectUserId,
      action: "AUTO_SYNC_FAILED",
      metadata: {
        provider,
        error: errorMessage,
        http_status: httpStatus,
        config_id: configId,
        consecutive_failures: consecutiveFailures,
      },
    });
  } catch (err) {
    logger.warn("Audit write failed (AUTO_SYNC_FAILED)", {
      error: err.message,
      workspace_id: workspaceId,
      provider,
    });
  }
}

/**
 * Reset the consecutive-failure counter and resolve any open auto-sync
 * notification for this config. Call on a successful (or partial-success)
 * sync run so that the bell incident clears once the integration recovers.
 */
export async function recordAutoSyncRecovery(client, { configId, workspaceId }) {
  try {
    await client.query(
      `UPDATE auto_sync_configs
       SET consecutive_failures = 0
       WHERE id = $1 AND consecutive_failures != 0`,
      [configId],
    );
    if (workspaceId) {
      await resolveOperationalNotification(
        client,
        workspaceId,
        `auto_sync_failed:${configId}`,
      );
    }
  } catch (err) {
    logger.warn("recordAutoSyncRecovery failed", {
      error: err.message,
      workspace_id: workspaceId,
      config_id: configId,
    });
  }
}

