import { pool, withClient } from "./db.js";
import {
  gQueueDepth,
  gQueueDueNow,
  gRunnerUp,
  pushMetrics,
} from "./metrics.js";
import { logger } from "./logger.js";
import {
  computeDaysLeft,
  findThresholdWindow,
  isStaleImportThreshold,
} from "./shared/thresholds.js";
import {
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
} from "./shared/contactGroups.js";

const DEFAULT_THRESHOLDS = (process.env.ALERT_THRESHOLDS || "30,14,7,1,0")
  .split(",")
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => Number.isFinite(n));

async function writeAudit(
  client,
  {
    actorUserId = null,
    subjectUserId,
    action,
    targetType = "token",
    targetId,
    channel = null,
    metadata = {},
  },
) {
  await client.query(
    `INSERT INTO audit_events (actor_user_id, subject_user_id, action, target_type, target_id, channel, metadata)
     VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [
      actorUserId,
      subjectUserId,
      action,
      targetType,
      targetId,
      channel,
      metadata,
    ],
  );
}

// Graceful shutdown handler
let isShuttingDown = false;
const shutdown = async (signal) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  logger.info(
    JSON.stringify({
      level: "INFO",
      message: "queue-manager-shutdown",
      signal,
    }),
  );
  try {
    await pool.end();
  } catch (err) {
    logger.error(
      JSON.stringify({
        level: "ERROR",
        message: "queue-manager-shutdown-error",
        error: err.message,
      }),
    );
  }
  process.exit(0);
};

// Register signal handlers for graceful shutdown
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export async function queueDiscoveryJob() {
  const startedAt = Date.now();
  let scanned = 0,
    queued = 0,
    updated = 0,
    skipped = 0;

  await withClient(async (client) => {
    // Get all tokens with their workspace-scoped settings
    const tokensRes = await client.query(
      `SELECT 
         t.id AS token_id,
         t.user_id,
         t.created_by,
         t.created_at,
         t.imported_at,
         t.name AS token_name,
         COALESCE(t.workspace_id, wf.id, wj.id) AS workspace_id,
         COALESCE(w.name, wf.name, wj.name) AS workspace_name,
         t.expiration::date AS expiration,
         
         t.contact_group_id,
         COALESCE(w.created_by, wf.created_by, wj.created_by, t.user_id) AS owner_user_id,
         u.email AS owner_email,
         COALESCE(ws.alert_thresholds, wsf.alert_thresholds, wjj.alert_thresholds) AS alert_thresholds,
         COALESCE(ws.webhook_urls, wsf.webhook_urls, wjj.webhook_urls) AS webhook_urls,
         COALESCE(ws.contact_groups, wsf.contact_groups, wjj.contact_groups) AS contact_groups,
         COALESCE(ws.default_contact_group_id, wsf.default_contact_group_id, wjj.default_contact_group_id) AS default_contact_group_id,
         COALESCE(ws.email_alerts_enabled, wsf.email_alerts_enabled, wjj.email_alerts_enabled) AS ws_email_alerts_enabled,
         COALESCE(ws.webhooks_alerts_enabled, wsf.webhooks_alerts_enabled, wjj.webhooks_alerts_enabled, FALSE) AS webhooks_alerts_enabled,
         COALESCE(ws.delivery_window_start, wsf.delivery_window_start, wjj.delivery_window_start) AS delivery_window_start,
         COALESCE(ws.delivery_window_end, wsf.delivery_window_end, wjj.delivery_window_end) AS delivery_window_end,
         COALESCE(ws.delivery_window_tz, wsf.delivery_window_tz, wjj.delivery_window_tz) AS delivery_window_tz
       FROM tokens t
       LEFT JOIN workspaces w ON w.id = t.workspace_id
       LEFT JOIN LATERAL (
         SELECT w2.*
         FROM workspaces w2
         WHERE w2.created_by = t.user_id
         ORDER BY w2.created_at ASC
         LIMIT 1
       ) wf ON TRUE
       LEFT JOIN LATERAL (
         SELECT w3.*
         FROM workspaces w3
         JOIN workspace_memberships wm3 ON wm3.workspace_id = w3.id AND wm3.user_id = t.user_id
         WHERE wm3.role IN ('admin','workspace_manager')
         ORDER BY w3.created_at ASC
         LIMIT 1
       ) wj ON TRUE
       LEFT JOIN workspace_settings ws ON ws.workspace_id = w.id
       LEFT JOIN workspace_settings wsf ON wsf.workspace_id = wf.id
       LEFT JOIN workspace_settings wjj ON wjj.workspace_id = wj.id
       LEFT JOIN users u ON u.id = COALESCE(w.created_by, wf.created_by, wj.created_by, t.user_id)
       WHERE t.expiration IS NOT NULL`,
    );
    const tokens = tokensRes.rows;

    // Helper: current UTC day string, overridable for tests
    const getUtcDayString = () => {
      const override = process.env.ALERT_TEST_UTC_DAY;
      if (override && /^\d{4}-\d{2}-\d{2}$/.test(override)) return override;
      const now = new Date();
      const y = now.getUTCFullYear();
      const m = String(now.getUTCMonth() + 1).padStart(2, "0");
      const d = String(now.getUTCDate()).padStart(2, "0");
      return `${y}-${m}-${d}`;
    };

    for (const t of tokens) {
      scanned++;
      const days = computeDaysLeft(t.expiration);

      // Parse workspace-specific thresholds, with optional contact-group override
      let userThresholds = DEFAULT_THRESHOLDS;
      try {
        if (Array.isArray(t.alert_thresholds)) {
          userThresholds = t.alert_thresholds.filter((n) => Number.isFinite(n));
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }

      // Resolve contact group early and apply any thresholds override BEFORE selecting the threshold window
      const resolvedGroup = resolveContactGroup({
        contactGroups: t.contact_groups,
        contactGroupId: t.contact_group_id,
        defaultContactGroupId: t.default_contact_group_id,
      });

      try {
        if (
          resolvedGroup &&
          Array.isArray(resolvedGroup.thresholds) &&
          resolvedGroup.thresholds.length > 0
        ) {
          const norm = resolvedGroup.thresholds
            .map((n) => Number(n))
            .filter((n) => Number.isFinite(n) && n >= -365 && n <= 730);
          if (norm.length > 0) userThresholds = norm;
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }

      // Determine which threshold window has been reached using effective thresholds
      const thresholdResult = findThresholdWindow(days, userThresholds);
      if (!thresholdResult) {
        continue; // No threshold reached
      }
      const { thresholdReached, negativeWindow } = thresholdResult;

      // For imported tokens, we avoid "catch-up" alerts for thresholds already passed before the import.
      if (
        isStaleImportThreshold(
          t.imported_at,
          t.expiration,
          thresholdReached,
          negativeWindow,
        )
      ) {
        skipped++;
        logger.info(
          JSON.stringify({
            level: "INFO",
            message: "skipping-stale-import-alert",
            token_id: t.token_id,
            token_name: t.token_name,
            threshold: thresholdReached,
            type: negativeWindow ? "post-expiration" : "pre-expiration",
          }),
        );
        continue;
      }

      // Calculate due date (UTC day for current threshold); allow test override
      const dayStr = getUtcDayString();
      const dueDate = new Date(`${dayStr}T00:00:00.000Z`);

      // Generate alert key per threshold window ONLY (no daily suffix) so it triggers once per window
      const alertKey = negativeWindow
        ? `token_expiry:${t.token_id}:negwin:${thresholdReached}`
        : `token_expiry:${t.token_id}:poswin:${thresholdReached}`;

      // Determine available channels: resolve recipients via contact groups when available
      const channels = [];

      // Email eligibility: contact group must have email_contact_ids
      const wsEmailEnabled = t.ws_email_alerts_enabled !== false;
      if (wsEmailEnabled && hasEmailContacts(resolvedGroup)) {
        channels.push("email");
      }

      // Webhooks: when a contact group explicitly selects webhook name(s)
      {
        const webhooks = Array.isArray(t.webhook_urls) ? t.webhook_urls : [];
        let hasWebhook = false;
        if (resolvedGroup && hasWebhookNames(resolvedGroup)) {
          // Ensure at least one named webhook exists in workspace settings
          try {
            const names = getWebhookNames(resolvedGroup);
            const filtered = webhooks.filter((w) =>
              names.includes(String(w.name || "").trim()),
            );
            hasWebhook = filtered.length > 0;
          } catch (_) {
            hasWebhook = true;
          }
        }
        if (hasWebhook) channels.push("webhooks");
      }

      // WhatsApp eligibility: require selected group to have whatsapp_contact_ids
      if (hasWhatsAppContacts(resolvedGroup)) {
        channels.push("whatsapp");
      }

      // Check if alert already exists for this window
      const existingRes = await client.query(
        "SELECT id, status FROM alert_queue WHERE alert_key = $1",
        [alertKey],
      );

      if (existingRes.rows.length > 0) {
        const existing = existingRes.rows[0];
        // Update channels if they changed (added webhooks, contacts, etc.)
        if (existing.status === "pending" || existing.status === "failed") {
          // Respect remaining failed channels to avoid resending successes in a loop
          let nextChannels = channels;
          let stored = null;
          try {
            if (Array.isArray(existing.channels)) stored = existing.channels;
            else if (typeof existing.channels === "string") {
              try {
                const parsed = JSON.parse(existing.channels);
                if (Array.isArray(parsed)) stored = parsed;
              } catch (_) {
                // Fallback: comma/whitespace separated string like "email,webhooks"
                stored = String(existing.channels)
                  .split(/[,\s]+/)
                  .map((s) => s.trim())
                  .filter(Boolean);
              }
            }
            if (Array.isArray(stored) && stored.length > 0) {
              nextChannels = channels.filter((c) => stored.includes(c));
              if (nextChannels.length === 0) nextChannels = stored; // fallback to stored remaining
            }
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
          await client.query(
            `UPDATE alert_queue 
             SET channels = $1, updated_at = NOW()
             WHERE id = $2`,
            [JSON.stringify(nextChannels), existing.id],
          );
          try {
            const contactGroupId =
              t.contact_group_id || t.default_contact_group_id || null;
            const groups = Array.isArray(t.contact_groups)
              ? t.contact_groups
              : [];
            const contactGroupName = contactGroupId
              ? groups.find((g) => String(g.id) === String(contactGroupId))
                  ?.name || null
              : null;
            await writeAudit(client, {
              subjectUserId: t.user_id,
              action: "ALERT_CHANNELS_UPDATED",
              targetId: t.token_id,
              metadata: {
                alertKey,
                from: stored,
                to: nextChannels,
                workspace_name: t.workspace_name,
                token_name: t.token_name,
                contact_group_id: contactGroupId,
                contact_group_name: contactGroupName,
              },
            });
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
          updated++;
        } else if (existing.status === "sent") {
          // Alert was already sent successfully - skip to prevent duplicates
          skipped++;
          logger.info(`Skipping already sent alert: ${alertKey}`);
        } else {
          skipped++; // Already sent or limit exceeded
        }
        continue;
      }

      // Backward-compat & dedupe: if any alert exists for this token/threshold that was already sent,
      // skip creating a new one regardless of due_date or legacy key format (ensures once per threshold window).
      if (existingRes.rows.length === 0) {
        const alreadySentRes = await client.query(
          `SELECT id FROM alert_queue WHERE token_id = $1 AND threshold_days = $2 AND status = 'sent' LIMIT 1`,
          [t.token_id, thresholdReached],
        );
        if (alreadySentRes.rows.length > 0) {
          skipped++;
          logger.info(
            `Skipping already-sent window due to existing sent alert: token ${t.token_id}, threshold ${thresholdReached}`,
          );
          continue;
        }
      }

      // Do not queue if no channels are eligible
      if (!Array.isArray(channels) || channels.length === 0) {
        skipped++;
        // Optional: write an audit for visibility that alert was not queued
        try {
          const contactGroupId =
            t.contact_group_id || t.default_contact_group_id || null;
          const groups = Array.isArray(t.contact_groups)
            ? t.contact_groups
            : [];
          const contactGroupName = contactGroupId
            ? groups.find((g) => String(g.id) === String(contactGroupId))
                ?.name || null
            : null;
          await writeAudit(client, {
            subjectUserId: t.user_id,
            action: "ALERT_NOT_QUEUED_NO_CHANNEL",
            targetId: t.token_id,
            metadata: {
              reason: "NO_ELIGIBLE_CHANNEL",
              workspace_name: t.workspace_name,
              token_name: t.token_name,
              contact_group_id: contactGroupId,
              contact_group_name: contactGroupName,
            },
          });
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        continue;
      }

      // Insert new alert into queue
      // Resolve owner for alert context: subscription owner (workspace.created_by) -> token creator -> legacy token user
      const ownerUserId = t.owner_user_id || t.created_by || t.user_id;
      await client.query(
        `INSERT INTO alert_queue (user_id, token_id, alert_key, threshold_days, due_date, channels, status)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending')`,
        [
          ownerUserId,
          t.token_id,
          alertKey,
          thresholdReached,
          dueDate.toISOString().slice(0, 10),
          JSON.stringify(channels),
        ],
      );

      queued++;
      const contactGroupId =
        t.contact_group_id || t.default_contact_group_id || null;
      const groups = Array.isArray(t.contact_groups) ? t.contact_groups : [];
      const contactGroupName = contactGroupId
        ? groups.find((g) => String(g.id) === String(contactGroupId))?.name ||
          null
        : null;
      await writeAudit(client, {
        subjectUserId: ownerUserId,
        action: "ALERT_QUEUED",
        targetId: t.token_id,
        metadata: {
          daysUntil: days,
          threshold: thresholdReached,
          dueDate: dueDate.toISOString().slice(0, 10),
          workspace_name: t.workspace_name,
          token_name: t.token_name,
          contact_group_id: contactGroupId,
          contact_group_name: contactGroupName,
        },
      });
    }
  });

  const durationMs = Date.now() - startedAt;
  logger.info(
    JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "INFO",
      message: "alert-queue-discovery-finished",
      scanned,
      queued,
      updated,
      skipped,
      durationMs,
    }),
  );

  // Best-effort gauges for current depths
  try {
    await withClient(async (client) => {
      const pending = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE status='pending'`,
      );
      const failedQ = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE status='failed'`,
      );
      const blocked = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE status='blocked'`,
      );
      gQueueDepth.labels("pending").set(pending.rows[0].c || 0);
      gQueueDepth.labels("failed").set(failedQ.rows[0].c || 0);
      gQueueDepth.labels("blocked").set(blocked.rows[0].c || 0);
      const dueNow = await client.query(
        `SELECT COUNT(*)::int AS c FROM alert_queue WHERE (status IS NULL OR status IN ('pending','failed')) AND due_date <= CURRENT_DATE AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())`,
      );
      gQueueDueNow.set(dueNow.rows[0].c || 0);
      gRunnerUp.labels("queue-manager").set(1);
    });
  } catch (_err) {
    logger.warn("DB operation failed", { error: _err.message });
  }

  try {
    await pushMetrics("queue-manager");
  } catch (_err) {
    logger.warn("DB operation failed", { error: _err.message });
  }

  // Only close pool if not shutting down (shutdown handler will close it)
  if (!isShuttingDown) {
    try {
      await pool.end();
    } catch (err) {
      logger.error(
        JSON.stringify({
          level: "ERROR",
          message: "queue-manager-pool-end-error",
          error: err.message,
        }),
      );
    }
  }
}

// Run queue discovery if this file is executed directly
if (import.meta.url === new URL(process.argv[1], "file://").href) {
  queueDiscoveryJob().catch(async (e) => {
    logger.error(
      JSON.stringify({
        level: "ERROR",
        message: "queue-discovery-error",
        error: e.message,
        stack: e.stack,
      }),
    );
    try {
      if (!isShuttingDown) {
        await pool.end();
      }
    } catch (err) {
      logger.error(
        JSON.stringify({
          level: "ERROR",
          message: "queue-discovery-error-cleanup-failed",
          error: err.message,
        }),
      );
    }
    process.exit(1);
  });
}
