const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const systemSettings = require("../services/systemSettings");
const {
  loadWorkspace,
  requireWorkspaceMembership,
  authorize,
} = require("../services/rbac");
const { maskPhone } = require("../utils/sanitize");
const crypto = require("crypto");

const router = require("express").Router();

function verifyTwilioSignature(req, authToken) {
  try {
    const signature = req.get("X-Twilio-Signature") || "";
    const base = (
      process.env.PUBLIC_BASE_URL ||
      process.env.API_URL ||
      ""
    ).replace(/\/$/, "");
    const url = base
      ? base + req.originalUrl
      : req.protocol + "://" + req.get("host") + req.originalUrl;
    const params = req.body && typeof req.body === "object" ? req.body : {};
    const keys = Object.keys(params).sort();
    let data = url;
    for (const k of keys) data += k + params[k];
    const computed = crypto
      .createHmac("sha1", authToken || "")
      .update(Buffer.from(data, "utf-8"))
      .digest("base64");
    const a = Buffer.from(signature);
    const b = Buffer.from(computed);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

// Test WhatsApp message with per-phone cooldown
const whatsappTestCooldowns = new Map(); // phone -> timestamp
router.post(
  "/api/test-whatsapp",
  getApiLimiter(),
  requireAuth,
  // Allow workspace_id via body, and infer when possible if omitted
  async (req, res, next) => {
    try {
      let wsId = req.query?.workspace_id || req.params?.id || null;
      if (!wsId && req.body && req.body.workspace_id)
        wsId = req.body.workspace_id;
      if (!wsId && req.user && req.user.id) {
        try {
          // Prefer a non-personal admin/manager workspace if exactly one exists; otherwise if exactly one membership exists, pick it
          const r = await pool.query(
            `SELECT w.id, wm.role,
                      COALESCE(w.is_personal_default, FALSE) AS is_personal
                 FROM workspace_memberships wm
                 JOIN workspaces w ON w.id = wm.workspace_id
                WHERE wm.user_id = $1`,
            [req.user.id],
          );
          const rows = r.rows || [];
          const eligible = rows.filter(
            (x) =>
              x &&
              x.is_personal === false &&
              ["admin", "workspace_manager", "manager"].includes(
                String(x.role || "").toLowerCase(),
              ),
          );
          if (eligible.length === 1) wsId = eligible[0].id;
          else if (rows.length === 1) wsId = rows[0].id;
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
      }
      if (!wsId)
        return res
          .status(400)
          .json({ error: "workspace_id required", code: "WORKSPACE_REQUIRED" });
      // Ensure downstream loadWorkspace can read it
      if (!req.query) req.query = {};
      req.query.workspace_id = wsId;
      return next();
    } catch (e) {
      return next(e);
    }
  },
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("workspace.update"),
  async (req, res) => {
    try {
      const { phone_e164 } = req.body || {};
      if (!phone_e164) {
        return res
          .status(400)
          .json({ error: "phone_e164 required", code: "PHONE_REQUIRED" });
      }
      const phoneNorm = String(phone_e164).trim();
      if (!/^\+?[1-9]\d{6,14}$/.test(phoneNorm)) {
        return res.status(400).json({
          error: "Invalid phone format (E.164 required, e.g., +14155550100)",
          code: "INVALID_PHONE_FORMAT",
        });
      }
      const phoneE164 = phoneNorm.startsWith("+") ? phoneNorm : `+${phoneNorm}`;

      // Check cooldown (2 minutes per phone)
      const cooldownMs = 2 * 60 * 1000;
      const key = phoneE164;
      const lastSent = whatsappTestCooldowns.get(key) || 0;
      const remaining = lastSent + cooldownMs - Date.now();
      if (remaining > 0) {
        const seconds = Math.ceil(remaining / 1000);
        // Audit cooldown event
        try {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "WHATSAPP_TEST_RATE_LIMITED",
            targetType: "workspace",
            targetId: null,
            channel: "whatsapp",
            workspaceId: req.workspace?.id || null,
            metadata: {
              phone_masked: maskPhone(phoneE164),
              retry_after_seconds: seconds,
            },
          });
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        return res.status(429).json({
          error: `Please wait ${seconds}s before testing this number again`,
          code: "TEST_WHATSAPP_COOLDOWN",
          retryAfter: seconds,
        });
      }

      // Send test via local CommonJS notifier
      const { sendWhatsApp } = require("../services/twilioWhatsApp");
      const useTemplate =
        String(req.query?.use_template || "").toLowerCase() === "true";
      const configuredTestTemplateSid =
        process.env.TWILIO_WHATSAPP_TEST_CONTENT_SID ||
        (await systemSettings.getSettingValue(
          pool,
          "twilio_whatsapp_test_content_sid",
        )) ||
        null;
      const contentSid = useTemplate ? configuredTestTemplateSid : null;
      const contentVariables = useTemplate
        ? {
            recipient_name:
              req.user.display_name || req.user.first_name || "there",
            time: new Date().toISOString(),
          }
        : null;
      const body = useTemplate
        ? null
        : `TokenTimer test message sent at ${new Date().toISOString()}`;
      // If template requested but not configured, return error instead of falling back to freeform
      if (useTemplate && !contentSid) {
        return res.status(400).json({
          error:
            "WhatsApp template not configured. Set TWILIO_WHATSAPP_TEST_CONTENT_SID or configure the test template SID in System Settings.",
          code: "TEMPLATE_NOT_CONFIGURED",
        });
      }
      const result = await sendWhatsApp({
        to: phoneE164,
        body,
        contentSid,
        contentVariables,
        idempotencyKey: `test:${phoneE164}:${Date.now()}`,
      });

      if (result.success) {
        whatsappTestCooldowns.set(key, Date.now());
        // Clean up old entries after 5 minutes
        setTimeout(() => whatsappTestCooldowns.delete(key), 5 * 60 * 1000);
        // Audit success
        try {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "WHATSAPP_TEST_SENT",
            targetType: "workspace",
            targetId: null,
            channel: "whatsapp",
            workspaceId: req.workspace?.id || null,
            metadata: {
              phone_masked: maskPhone(phoneE164),
              message_sid: result.messageSid || null,
            },
          });
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        return res.json({ success: true, messageSid: result.messageSid });
      } else {
        // If outside 24h window (Twilio 63016) and we didn't try template, auto-retry with template when configured
        const codeStr = String(result.code || "").trim();
        const maybeOutsideWindow =
          codeStr === "63016" ||
          codeStr === "WABA_63016" ||
          /outside\s+the\s+allowed\s+window/i.test(String(result.error || ""));
        const retryTemplateSid = configuredTestTemplateSid;
        if (!useTemplate && maybeOutsideWindow && retryTemplateSid) {
          try {
            const retry = await sendWhatsApp({
              to: phoneE164,
              body: null,
              contentSid: retryTemplateSid,
              contentVariables: { time: new Date().toISOString() },
              idempotencyKey: `test:${phoneE164}:${Date.now()}:tpl`,
            });
            if (retry.success) {
              whatsappTestCooldowns.set(key, Date.now());
              setTimeout(
                () => whatsappTestCooldowns.delete(key),
                5 * 60 * 1000,
              );
              try {
                await writeAudit({
                  actorUserId: req.user.id,
                  subjectUserId: req.user.id,
                  action: "WHATSAPP_TEST_SENT_TEMPLATE",
                  targetType: "workspace",
                  targetId: null,
                  channel: "whatsapp",
                  workspaceId: req.workspace?.id || null,
                  metadata: {
                    phone_masked: maskPhone(phoneE164),
                    message_sid: retry.messageSid || null,
                  },
                });
              } catch (_err) {
                logger.debug("Non-critical operation failed", {
                  error: _err.message,
                });
              }
              return res.json({
                success: true,
                messageSid: retry.messageSid,
                usedTemplate: true,
              });
            }
            // Audit retry failure
            try {
              await writeAudit({
                actorUserId: req.user.id,
                subjectUserId: req.user.id,
                action: "WHATSAPP_TEST_FAILED_TEMPLATE",
                targetType: "workspace",
                targetId: null,
                channel: "whatsapp",
                workspaceId: req.workspace?.id || null,
                metadata: {
                  phone_masked: maskPhone(phoneE164),
                  code: retry.code || null,
                  error: retry.error || null,
                },
              });
            } catch (_err) {
              logger.debug("Non-critical operation failed", {
                error: _err.message,
              });
            }
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
        }
        // Audit failure
        try {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "WHATSAPP_TEST_FAILED",
            targetType: "workspace",
            targetId: null,
            channel: "whatsapp",
            workspaceId: req.workspace?.id || null,
            metadata: {
              phone_masked: maskPhone(phoneE164),
              code: result.code || null,
              error: result.error || null,
            },
          });
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        return res.status(400).json({
          error: result.error || "Failed to send test message",
          code: result.code || "WHATSAPP_SEND_FAILED",
        });
      }
    } catch (e) {
      logger.error("Test WhatsApp error", { error: e.message });
      // Audit unexpected error
      try {
        await writeAudit({
          actorUserId: req.user?.id || null,
          subjectUserId: req.user?.id || null,
          action: "WHATSAPP_TEST_ERROR",
          targetType: "workspace",
          targetId: null,
          channel: "whatsapp",
          workspaceId: req.workspace?.id || null,
          metadata: { error: e.message },
        });
      } catch (_err) {
        logger.warn("Audit write failed (WHATSAPP_TEST_ERROR)", {
          error: _err.message,
        });
      }
      return res.status(500).json({
        error: "Failed to send test message",
        code: "WHATSAPP_TEST_ERROR",
      });
    }
  },
);

// Twilio WhatsApp delivery status webhook
router.post("/webhooks/twilio/whatsapp/status", async (req, res) => {
  try {
    const token =
      process.env.TWILIO_AUTH_TOKEN ||
      (await systemSettings.getSettingValue(pool, "twilio_auth_token")) ||
      "";
    if (!token)
      return res
        .status(500)
        .json({ error: "Twilio not configured", code: "INTERNAL_ERROR" });
    if (!verifyTwilioSignature(req, token))
      return res
        .status(403)
        .json({ error: "Invalid signature", code: "FORBIDDEN" });

    const messageSid = String(
      req.body?.MessageSid || req.body?.SmsSid || "",
    ).trim();
    const messageStatus = String(req.body?.MessageStatus || "").trim();
    const errorCode =
      req.body?.ErrorCode != null ? String(req.body.ErrorCode) : null;
    if (!messageSid) return res.status(200).end();

    await pool.query(
      `UPDATE alert_delivery_log
         SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{status}', to_jsonb($2::text), true)
       WHERE id IN (
         SELECT id FROM alert_delivery_log
          WHERE channel='whatsapp' AND metadata->>'messageSid' = $1
          ORDER BY sent_at DESC
          LIMIT 1
       )`,
      [messageSid, messageStatus || "unknown"],
    );
    if (errorCode) {
      await pool.query(
        `UPDATE alert_delivery_log
           SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{errorCode}', to_jsonb($2::text), true)
         WHERE id IN (
           SELECT id FROM alert_delivery_log
            WHERE channel='whatsapp' AND metadata->>'messageSid' = $1
            ORDER BY sent_at DESC
            LIMIT 1
         )`,
        [messageSid, errorCode],
      );
    }
    return res.status(200).end();
  } catch (e) {
    logger.warn("twilio-whatsapp-status-webhook", { error: e.message });
    return res.status(200).end();
  }
});

// Enforce workspace membership and write restrictions for all workspace routes

// Reassign tokens from one contact group to another within a workspace
// POST /api/v1/workspaces/:id/tokens/reassign-contact-group
// Body: { from_group_id, to_group_id }
// Auth: admin or workspace_manager
router.post(
  "/api/v1/workspaces/:id/tokens/reassign-contact-group",
  loadWorkspace,
  requireWorkspaceMembership,
  authorize("workspace.update"),
  async (req, res) => {
    try {
      const workspaceId = req.params.id;
      const { from_group_id: fromId, to_group_id: toId } = req.body || {};
      if (!fromId || !toId) {
        return res.status(400).json({
          error: "from_group_id and to_group_id are required",
          code: "VALIDATION_ERROR",
        });
      }
      if (String(fromId) === String(toId)) {
        return res.status(400).json({
          error: "from_group_id and to_group_id must differ",
          code: "VALIDATION_ERROR",
        });
      }
      // Ensure both groups exist in current settings
      const ws = await pool.query(
        "SELECT contact_groups FROM workspace_settings WHERE workspace_id = $1",
        [workspaceId],
      );
      const groups = Array.isArray(ws.rows?.[0]?.contact_groups)
        ? ws.rows[0].contact_groups
        : [];
      const existsFrom = groups.some((g) => String(g.id) === String(fromId));
      const existsTo = groups.some((g) => String(g.id) === String(toId));
      if (!existsFrom)
        return res.status(400).json({
          error: "from_group_id not found in workspace",
          code: "VALIDATION_ERROR",
        });
      if (!existsTo)
        return res.status(400).json({
          error: "to_group_id not found in workspace",
          code: "VALIDATION_ERROR",
        });

      const r = await pool.query(
        `UPDATE tokens SET contact_group_id = $3, updated_at = NOW()
         WHERE workspace_id = $1 AND contact_group_id = $2`,
        [workspaceId, String(fromId), String(toId)],
      );
      try {
        await writeAudit({
          actorUserId: req.user?.id || null,
          subjectUserId: req.user?.id || null,
          action: "TOKENS_REASSIGNED_CONTACT_GROUP",
          targetType: "workspace",
          targetId: null,
          workspaceId: workspaceId,
          metadata: {
            from_group_id: String(fromId),
            to_group_id: String(toId),
            updated: r.rowCount,
          },
        });
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      return res.json({ updated: r.rowCount || 0 });
    } catch (_e) {
      return res.status(500).json({
        error: "failed to reassign contact group",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// JSON parsing error handler

module.exports = router;
