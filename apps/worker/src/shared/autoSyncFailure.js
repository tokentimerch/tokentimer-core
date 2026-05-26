import { logger } from "../logger.js";

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
 * into failed state (avoids hourly duplicate audit rows).
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
  await client.query(
    `UPDATE auto_sync_configs
     SET last_sync_at = NOW(), last_sync_status = 'failed',
         last_sync_error = $1, next_sync_at = $2, updated_at = NOW()
     WHERE id = $3`,
    [errorMessage, nextSync, configId],
  );

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
