const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { requireAuth } = require("../middleware/auth");
const { getApiLimiter } = require("../middleware/rateLimit");
const {
  loadWorkspace,
  requireWorkspaceMembership,
} = require("../services/rbac");
const { testWebhookUrl } = require("../config/constants");
const systemSettings = require("../services/systemSettings");
const {
  sendEmail,
  isSMTPConfiguredAsync,
} = require("../services/emailService");

const router = require("express").Router();

function intEnv(name, fallback) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  const parsed = Number.parseInt(String(raw), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

// Middleware: require user to be a global deployment admin (users.is_admin)
async function requireAnyAdmin(req, res, next) {
  try {
    if (!req.user?.id)
      return res
        .status(401)
        .json({ error: "Unauthorized", code: "UNAUTHORIZED" });
    const { rows } = await pool.query(
      `SELECT is_admin
         FROM users
        WHERE id = $1
        LIMIT 1`,
      [req.user.id],
    );
    if (rows.length === 0 || rows[0].is_admin !== true)
      return res
        .status(403)
        .json({ error: "Admin access required", code: "FORBIDDEN" });
    next();
  } catch (_e) {
    logger.warn("Authorization check failed", {
      error: _e?.message,
      stack: _e?.stack,
      userId: req.user?.id,
    });
    res
      .status(500)
      .json({ error: "Authorization check failed", code: "INTERNAL_ERROR" });
  }
}

// GET /api/admin/system-settings
router.get(
  "/api/admin/system-settings",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  async (req, res) => {
    try {
      const all = await systemSettings.getAllSettings(pool);
      // Group into smtp and whatsapp sections
      const smtp = {
        host: all.smtp_host,
        port: all.smtp_port,
        user: all.smtp_user,
        pass: all.smtp_pass,
        from_email: all.smtp_from_email,
        from_name: all.smtp_from_name,
        secure: all.smtp_secure,
        require_tls: all.smtp_require_tls,
        configured: await systemSettings.isSmtpConfigured(pool),
      };
      const whatsapp = {
        account_sid: all.twilio_account_sid,
        auth_token: all.twilio_auth_token,
        whatsapp_from: all.twilio_whatsapp_from,
        test_content_sid: all.twilio_whatsapp_test_content_sid,
        alert_content_sid_expires:
          all.twilio_whatsapp_alert_content_sid_expires,
        alert_content_sid_expired:
          all.twilio_whatsapp_alert_content_sid_expired,
        alert_content_sid_endpoint_down:
          all.twilio_whatsapp_alert_content_sid_endpoint_down,
        alert_content_sid_endpoint_recovered:
          all.twilio_whatsapp_alert_content_sid_endpoint_recovered,
        weekly_digest_content_sid:
          all.twilio_whatsapp_weekly_digest_content_sid,
        configured: await systemSettings.isWhatsAppAvailable(pool),
      };
      res.json({ smtp, whatsapp });
    } catch (e) {
      logger.error("System settings fetch error", { error: e.message });
      res.status(500).json({
        error: "Failed to fetch system settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// PUT /api/admin/system-settings
router.put(
  "/api/admin/system-settings",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  async (req, res) => {
    try {
      const { smtp, whatsapp } = req.body || {};
      const updates = {};
      // Map frontend keys back to DB keys
      if (smtp) {
        if (smtp.host !== undefined) updates.smtp_host = smtp.host;
        if (smtp.port !== undefined) updates.smtp_port = smtp.port;
        if (smtp.user !== undefined) updates.smtp_user = smtp.user;
        if (smtp.pass !== undefined) updates.smtp_pass = smtp.pass;
        if (smtp.from_email !== undefined)
          updates.smtp_from_email = smtp.from_email;
        if (smtp.from_name !== undefined)
          updates.smtp_from_name = smtp.from_name;
        if (smtp.secure !== undefined) updates.smtp_secure = smtp.secure;
        if (smtp.require_tls !== undefined)
          updates.smtp_require_tls = smtp.require_tls;
      }
      if (whatsapp) {
        if (whatsapp.account_sid !== undefined)
          updates.twilio_account_sid = whatsapp.account_sid;
        if (whatsapp.auth_token !== undefined)
          updates.twilio_auth_token = whatsapp.auth_token;
        if (whatsapp.whatsapp_from !== undefined)
          updates.twilio_whatsapp_from = whatsapp.whatsapp_from;
        if (whatsapp.test_content_sid !== undefined)
          updates.twilio_whatsapp_test_content_sid = whatsapp.test_content_sid;
        if (whatsapp.alert_content_sid_expires !== undefined)
          updates.twilio_whatsapp_alert_content_sid_expires =
            whatsapp.alert_content_sid_expires;
        if (whatsapp.alert_content_sid_expired !== undefined)
          updates.twilio_whatsapp_alert_content_sid_expired =
            whatsapp.alert_content_sid_expired;
        if (whatsapp.alert_content_sid_endpoint_down !== undefined)
          updates.twilio_whatsapp_alert_content_sid_endpoint_down =
            whatsapp.alert_content_sid_endpoint_down;
        if (whatsapp.alert_content_sid_endpoint_recovered !== undefined)
          updates.twilio_whatsapp_alert_content_sid_endpoint_recovered =
            whatsapp.alert_content_sid_endpoint_recovered;
        if (whatsapp.weekly_digest_content_sid !== undefined)
          updates.twilio_whatsapp_weekly_digest_content_sid =
            whatsapp.weekly_digest_content_sid;
      }

      await systemSettings.saveSettings(pool, updates, req.user.id);

      const all = await systemSettings.getAllSettings(pool);
      const smtpResult = {
        host: all.smtp_host,
        port: all.smtp_port,
        user: all.smtp_user,
        pass: all.smtp_pass,
        from_email: all.smtp_from_email,
        from_name: all.smtp_from_name,
        secure: all.smtp_secure,
        require_tls: all.smtp_require_tls,
        configured: await systemSettings.isSmtpConfigured(pool),
      };
      const whatsappResult = {
        account_sid: all.twilio_account_sid,
        auth_token: all.twilio_auth_token,
        whatsapp_from: all.twilio_whatsapp_from,
        test_content_sid: all.twilio_whatsapp_test_content_sid,
        alert_content_sid_expires:
          all.twilio_whatsapp_alert_content_sid_expires,
        alert_content_sid_expired:
          all.twilio_whatsapp_alert_content_sid_expired,
        alert_content_sid_endpoint_down:
          all.twilio_whatsapp_alert_content_sid_endpoint_down,
        alert_content_sid_endpoint_recovered:
          all.twilio_whatsapp_alert_content_sid_endpoint_recovered,
        weekly_digest_content_sid:
          all.twilio_whatsapp_weekly_digest_content_sid,
        configured: await systemSettings.isWhatsAppAvailable(pool),
      };
      res.json({ smtp: smtpResult, whatsapp: whatsappResult });
    } catch (e) {
      logger.error("System settings save error", { error: e.message });
      res.status(500).json({
        error: "Failed to save system settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// POST /api/admin/test-smtp - send a test email
router.post(
  "/api/admin/test-smtp",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  async (req, res) => {
    try {
      const { email } = req.body || {};
      const recipient =
        email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim())
          ? String(email).trim()
          : req.user.email;
      if (!(await isSMTPConfiguredAsync())) {
        return res.status(400).json({
          error: "SMTP is not configured",
          code: "SMTP_NOT_CONFIGURED",
        });
      }
      const result = await sendEmail({
        to: recipient,
        subject: "TokenTimer SMTP Test",
        text: "This is a test email from TokenTimer. Your SMTP configuration is working correctly.",
        html: "<p>This is a test email from <strong>TokenTimer</strong>.</p><p>Your SMTP configuration is working correctly.</p>",
      });
      if (!result?.success) {
        return res.status(500).json({
          error: result?.error || "Failed to send test email",
          code: result?.code || "SMTP_TEST_FAILED",
        });
      }
      res.json({ success: true, message: `Test email sent to ${recipient}` });
    } catch (e) {
      logger.error("SMTP test error", { error: e.message });
      res.status(500).json({ error: e.message, code: "SMTP_TEST_FAILED" });
    }
  },
);

// POST /api/admin/test-whatsapp - send a test WhatsApp message
router.post(
  "/api/admin/test-whatsapp",
  getApiLimiter(),
  requireAuth,
  requireAnyAdmin,
  async (req, res) => {
    try {
      const { phone } = req.body || {};
      if (!phone || !/^\+?\d{6,15}$/.test(String(phone).trim())) {
        return res.status(400).json({
          error: "Valid phone number required (E.164 format)",
          code: "INVALID_PHONE_FORMAT",
        });
      }
      const sid = await systemSettings.getSettingValue(
        pool,
        "twilio_account_sid",
      );
      const token = await systemSettings.getSettingValue(
        pool,
        "twilio_auth_token",
      );
      const from = await systemSettings.getSettingValue(
        pool,
        "twilio_whatsapp_from",
      );
      if (!sid || !token || !from) {
        return res.status(400).json({
          error: "Twilio WhatsApp is not configured",
          code: "WHATSAPP_NOT_CONFIGURED",
        });
      }
      // Use the existing sendWhatsApp function
      const { sendWhatsApp } = require("../services/twilioWhatsApp");
      const configuredTestTemplateSid =
        process.env.TWILIO_WHATSAPP_TEST_CONTENT_SID ||
        (await systemSettings.getSettingValue(
          pool,
          "twilio_whatsapp_test_content_sid",
        )) ||
        null;
      const contentSid = configuredTestTemplateSid || null;
      const contentVariables = contentSid
        ? {
            recipient_name:
              req.user.display_name || req.user.first_name || "there",
            time: new Date().toISOString(),
          }
        : null;
      const body = contentSid
        ? null
        : "This is a test message from TokenTimer. Your WhatsApp configuration is working correctly.";
      const result = await sendWhatsApp({
        to: String(phone).trim(),
        body,
        contentSid,
        contentVariables,
        idempotencyKey: `admin-test:${req.user.id}:${Date.now()}`,
      });
      if (result.success) {
        res.json({ success: true, message: `Test message sent to ${phone}` });
      } else {
        res.status(500).json({
          error: result.error || "Send failed",
          code: "WHATSAPP_TEST_FAILED",
        });
      }
    } catch (e) {
      logger.error("WhatsApp test error", { error: e.message });
      res.status(500).json({ error: e.message, code: "WHATSAPP_TEST_FAILED" });
    }
  },
);

// Workspace-scoped alert settings
router.get(
  [
    "/api/workspaces/:id/alert-settings",
    "/api/v1/workspaces/:id/alert-settings",
  ],
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const { id } = req.workspace;
      const { rows } = await pool.query(
        `SELECT ws.alert_thresholds, ws.webhook_urls, ws.email_alerts_enabled, ws.slack_alerts_enabled, ws.webhooks_alerts_enabled,
                ws.whatsapp_alerts_enabled,
                ws.delivery_window_start, ws.delivery_window_end, ws.delivery_window_tz,
                ws.contact_groups, ws.default_contact_group_id, w.plan
           FROM workspace_settings ws
           JOIN workspaces w ON w.id = ws.workspace_id
          WHERE ws.workspace_id = $1`,
        [id],
      );
      const row = rows[0] || {};
      const thresholds = Array.isArray(row.alert_thresholds)
        ? row.alert_thresholds
        : [30, 14, 7, 1, 0];
      const webhookUrls = Array.isArray(row.webhook_urls)
        ? row.webhook_urls
        : [];
      // Check feature availability (env or DB configured)
      const whatsappAvailable = await systemSettings.isWhatsAppAvailable(pool);
      const smtpConfigured = await systemSettings.isSmtpConfigured(pool);

      res.json({
        alert_thresholds: thresholds,
        webhook_urls: webhookUrls,
        plan: row.plan || "oss",
        email_alerts_enabled: row.email_alerts_enabled !== false,
        slack_alerts_enabled: row.slack_alerts_enabled === true,
        webhooks_alerts_enabled: row.webhooks_alerts_enabled === true,
        whatsapp_alerts_enabled: row.whatsapp_alerts_enabled === true,
        whatsapp_available: whatsappAvailable,
        smtp_configured: smtpConfigured,
        delivery_window_start: row.delivery_window_start || null,
        delivery_window_end: row.delivery_window_end || null,
        delivery_window_tz: row.delivery_window_tz || null,
        contact_groups: Array.isArray(row.contact_groups)
          ? row.contact_groups.map((g) => {
              if (Array.isArray(g.webhook_names)) return g;
              if (g.webhook_name)
                return {
                  ...g,
                  webhook_names: [g.webhook_name],
                  webhook_name: undefined,
                };
              return { ...g, webhook_names: [] };
            })
          : [],
        default_contact_group_id: row.default_contact_group_id || null,
      });
    } catch (err) {
      logger.error("Workspace alert settings fetch error", {
        error: err.message,
        workspaceId: req.workspace?.id,
      });
      res.status(500).json({
        error: "Failed to fetch workspace alert settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Update workspace-scoped alert settings (managers/admins)
router.put(
  "/api/v1/workspaces/:id/alert-settings",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    try {
      const role = req.authz?.workspaceRole;
      if (!role || !["admin", "workspace_manager"].includes(role)) {
        return res.status(403).json({ error: "Forbidden", code: "FORBIDDEN" });
      }

      const workspaceId = req.workspace.id;
      const {
        alert_thresholds,
        webhook_urls,
        email_alerts_enabled,
        slack_alerts_enabled,
        webhooks_alerts_enabled,
        whatsapp_alerts_enabled,
        contact_groups,
        default_contact_group_id,
        delivery_window_start,
        delivery_window_end,
        delivery_window_tz,
      } = req.body || {};

      // Ensure settings row exists, with defaults for delivery window if creating
      await pool.query(
        `INSERT INTO workspace_settings (workspace_id, delivery_window_start, delivery_window_end, delivery_window_tz)
         VALUES ($1, '00:00', '23:59', 'UTC')
         ON CONFLICT (workspace_id) DO NOTHING`,
        [workspaceId],
      );

      // Load current settings to build before/after summaries
      let currentGroups = [];
      try {
        const curRes = await pool.query(
          "SELECT contact_groups, webhook_urls FROM workspace_settings WHERE workspace_id = $1",
          [workspaceId],
        );
        const row = curRes.rows?.[0] || {};
        currentGroups = Array.isArray(row.contact_groups)
          ? row.contact_groups
          : [];
      } catch (_err) {
        logger.warn("DB operation failed", { error: _err.message });
      }

      const fields = [];
      const params = [];
      let p = 1;
      let updatedGroupIds = null; // Track new group IDs for stale token cleanup
      if (Array.isArray(alert_thresholds)) {
        const norm = alert_thresholds.filter((n) => Number.isFinite(n));
        fields.push(`alert_thresholds = $${p++}`);
        params.push(JSON.stringify(norm));
      }
      if (Array.isArray(webhook_urls)) {
        fields.push(`webhook_urls = $${p++}`);
        params.push(JSON.stringify(webhook_urls));
      }
      if (typeof email_alerts_enabled === "boolean") {
        fields.push(`email_alerts_enabled = $${p++}`);
        params.push(email_alerts_enabled);
      }
      if (typeof slack_alerts_enabled === "boolean") {
        fields.push(`slack_alerts_enabled = $${p++}`);
        params.push(slack_alerts_enabled);
      }
      if (typeof webhooks_alerts_enabled === "boolean") {
        fields.push(`webhooks_alerts_enabled = $${p++}`);
        params.push(webhooks_alerts_enabled);
      }
      if (typeof whatsapp_alerts_enabled === "boolean") {
        fields.push(`whatsapp_alerts_enabled = $${p++}`);
        params.push(whatsapp_alerts_enabled);
      }
      const isValidHHmm = (s) =>
        typeof s === "string" && /^([01]\d|2[0-3]):[0-5]\d$/.test(s.trim());
      if (
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          "delivery_window_start",
        )
      ) {
        if (
          delivery_window_start !== null &&
          delivery_window_start !== undefined
        ) {
          if (!isValidHHmm(String(delivery_window_start))) {
            return res.status(400).json({
              error: "Invalid delivery_window_start. Use HH:mm (00:00-23:59).",
              code: "VALIDATION_ERROR",
            });
          }
        }
        fields.push(`delivery_window_start = $${p++}`);
        params.push(
          typeof delivery_window_start === "string" &&
            delivery_window_start.trim()
            ? delivery_window_start.trim()
            : null,
        );
      }
      if (
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          "delivery_window_end",
        )
      ) {
        if (delivery_window_end !== null && delivery_window_end !== undefined) {
          if (!isValidHHmm(String(delivery_window_end))) {
            return res.status(400).json({
              error: "Invalid delivery_window_end. Use HH:mm (00:00-23:59).",
              code: "VALIDATION_ERROR",
            });
          }
        }
        fields.push(`delivery_window_end = $${p++}`);
        params.push(
          typeof delivery_window_end === "string" && delivery_window_end.trim()
            ? delivery_window_end.trim()
            : null,
        );
      }
      if (
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          "delivery_window_tz",
        )
      ) {
        let tzValue = null;
        if (
          typeof delivery_window_tz === "string" &&
          delivery_window_tz.trim()
        ) {
          const tz = delivery_window_tz.trim();
          // Basic timezone validation using Intl
          try {
            Intl.DateTimeFormat("en-US", { timeZone: tz });
            tzValue = tz;
          } catch (_e) {
            return res.status(400).json({
              error: `Invalid timezone: ${tz}. Use IANA format (e.g., UTC, Europe/Zurich, America/New_York)`,
              code: "VALIDATION_ERROR",
            });
          }
        }
        fields.push(`delivery_window_tz = $${p++}`);
        params.push(tzValue);
      }

      // Contact groups validation and caps
      // Fetch plan for caps enforcement
      const planRow = await pool.query(
        "SELECT plan FROM workspaces WHERE id = $1",
        [workspaceId],
      );
      const plan = String(planRow.rows?.[0]?.plan || "oss").toLowerCase();
      const {
        CONTACT_GROUP_LIMITS,
        CONTACT_GROUP_MEMBER_LIMITS,
      } = require("../services/planLimits.js");
      const groupLimit =
        CONTACT_GROUP_LIMITS[plan] ?? CONTACT_GROUP_LIMITS.oss ?? Infinity;
      const memberLimit =
        CONTACT_GROUP_MEMBER_LIMITS[plan] ??
        CONTACT_GROUP_MEMBER_LIMITS.oss ??
        Infinity;

      if (Array.isArray(contact_groups)) {
        // Normalize groups: id, name, email_contact_ids[], whatsapp_contact_ids[], optional webhook_names[], optional thresholds[] override
        const normGroups = [];
        for (const g of contact_groups) {
          const id = g && g.id ? String(g.id) : null;
          const name = g && typeof g.name === "string" ? g.name.trim() : "";
          if (!id || !name) continue;

          // Process new format: email_contact_ids and whatsapp_contact_ids
          let emailContactIds = [];
          let whatsappContactIds = [];

          try {
            if (Array.isArray(g.email_contact_ids)) {
              emailContactIds = g.email_contact_ids
                .map((id) => String(id || "").trim())
                .filter(Boolean);
            }
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }

          try {
            if (Array.isArray(g.whatsapp_contact_ids)) {
              whatsappContactIds = g.whatsapp_contact_ids
                .map((id) => String(id || "").trim())
                .filter(Boolean);
            }
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }

          // Apply member limit to total unique people (not per channel)
          // Always enforce member caps according to plan limits
          const allContactIds = Array.from(
            new Set([...emailContactIds, ...whatsappContactIds]),
          );
          const trimmedContactIds = allContactIds.slice(0, memberLimit);
          const trimmedEmailContactIds = emailContactIds.filter((id) =>
            trimmedContactIds.includes(id),
          );
          const trimmedWhatsappContactIds = whatsappContactIds.filter((id) =>
            trimmedContactIds.includes(id),
          );

          // Validate all contact_ids exist in workspace_contacts
          if (trimmedContactIds.length > 0) {
            try {
              const { rows } = await pool.query(
                `SELECT id, phone_e164, details
                   FROM workspace_contacts
                  WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
                [workspaceId, trimmedContactIds],
              );
              const foundIds = rows.map((r) => String(r.id));
              const missingIds = trimmedContactIds.filter(
                (id) => !foundIds.includes(id),
              );
              if (missingIds.length > 0) {
                return res.status(400).json({
                  error: "Invalid contact_ids provided",
                  code: "VALIDATION_ERROR",
                  invalid_contact_ids: missingIds,
                });
              }

              // Validate WhatsApp contacts have phone numbers
              const whatsappIds = rows
                .filter((r) => trimmedWhatsappContactIds.includes(String(r.id)))
                .map((r) => String(r.id));
              const withoutPhone = rows
                .filter(
                  (r) =>
                    whatsappIds.includes(String(r.id)) &&
                    (!r.phone_e164 ||
                      String(r.phone_e164 || "").trim().length === 0),
                )
                .map((r) => String(r.id));
              if (withoutPhone.length > 0) {
                return res.status(400).json({
                  error: "Contacts without phone cannot be used for WhatsApp",
                  code: "VALIDATION_ERROR",
                  invalid_contact_ids: withoutPhone,
                });
              }
            } catch (_e) {
              return res.status(400).json({
                error: "Invalid contact_ids",
                code: "VALIDATION_ERROR",
              });
            }
          }

          // Normalize webhook names
          let webhookNames = [];
          try {
            if (Array.isArray(g.webhook_names)) {
              webhookNames = g.webhook_names
                .map((n) => String(n || "").trim())
                .filter(Boolean);
            } else if (g && g.webhook_name) {
              const single = String(g.webhook_name).trim();
              if (single) webhookNames = [single];
            }
            // Dedupe
            webhookNames = Array.from(new Set(webhookNames));
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }
          // Optional thresholds override (sorted desc, filtered to range)
          let thresholdsOverride = [];
          try {
            if (Array.isArray(g.thresholds)) {
              thresholdsOverride = g.thresholds
                .map((n) => Number(n))
                .filter((n) => Number.isFinite(n) && n >= -365 && n <= 730)
                .sort((a, b) => b - a);
              // Dedupe
              thresholdsOverride = Array.from(new Set(thresholdsOverride));
            }
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }

          // Disallow empty groups: must have at least one contact or webhook
          const hasEmailContacts = trimmedEmailContactIds.length > 0;
          const hasWhatsappContacts = trimmedWhatsappContactIds.length > 0;
          const hasWebhook = webhookNames.length > 0;
          if (!hasEmailContacts && !hasWhatsappContacts && !hasWebhook)
            continue;

          const weeklyDigestEmail =
            typeof g.weekly_digest_email === "boolean"
              ? g.weekly_digest_email
              : false;
          const weeklyDigestWhatsapp =
            typeof g.weekly_digest_whatsapp === "boolean"
              ? g.weekly_digest_whatsapp
              : false;
          const weeklyDigestWebhooks =
            typeof g.weekly_digest_webhooks === "boolean"
              ? g.weekly_digest_webhooks
              : false;

          normGroups.push({
            id,
            name,
            ...(hasEmailContacts
              ? { email_contact_ids: trimmedEmailContactIds }
              : {}),
            ...(hasWhatsappContacts
              ? { whatsapp_contact_ids: trimmedWhatsappContactIds }
              : {}),
            ...(hasWebhook ? { webhook_names: webhookNames } : {}),
            ...(Array.isArray(thresholdsOverride) &&
            thresholdsOverride.length > 0
              ? { thresholds: thresholdsOverride }
              : {}),
            weekly_digest_email: weeklyDigestEmail,
            weekly_digest_whatsapp: weeklyDigestWhatsapp,
            weekly_digest_webhooks: weeklyDigestWebhooks,
          });
        }
        if (Number.isFinite(groupLimit) && normGroups.length > groupLimit) {
          // Apply contact group cap according to plan limits
          normGroups.length = groupLimit;
        }
        fields.push(`contact_groups = $${p++}`);
        params.push(JSON.stringify(normGroups));
        updatedGroupIds = normGroups.map((g) => g.id);

        // Validate default group if provided
        if (default_contact_group_id !== undefined) {
          const defId = default_contact_group_id
            ? String(default_contact_group_id)
            : null;
          const exists = defId && normGroups.some((g) => g.id === defId);
          fields.push(`default_contact_group_id = $${p++}`);
          params.push(exists ? defId : normGroups[0]?.id || null);
        }
      } else if (
        Object.prototype.hasOwnProperty.call(
          req.body || {},
          "default_contact_group_id",
        )
      ) {
        // Allow updating default independently when groups omitted
        const currentRes = await pool.query(
          "SELECT contact_groups FROM workspace_settings WHERE workspace_id = $1",
          [workspaceId],
        );
        const currentGroups = Array.isArray(
          currentRes.rows?.[0]?.contact_groups,
        )
          ? currentRes.rows[0].contact_groups
          : [];
        const defId = default_contact_group_id
          ? String(default_contact_group_id)
          : null;
        const exists = defId && currentGroups.some((g) => g.id === defId);
        fields.push(`default_contact_group_id = $${p++}`);
        params.push(exists ? defId : currentGroups[0]?.id || null);
      }

      if (fields.length > 0) {
        await pool.query(
          `UPDATE workspace_settings SET ${fields.join(", ")}, updated_at = NOW(), updated_by = $${p} WHERE workspace_id = $${p + 1}`,
          [...params, req.user.id, workspaceId],
        );
      }

      // Clear stale contact_group_id on tokens that reference groups no longer in the updated array.
      // This prevents delivery failures when a group is deleted but tokens still point to it.
      if (updatedGroupIds !== null) {
        try {
          if (updatedGroupIds.length === 0) {
            // All groups removed: clear every token's contact_group_id in this workspace
            await pool.query(
              `UPDATE tokens SET contact_group_id = NULL, updated_at = NOW()
               WHERE workspace_id = $1 AND contact_group_id IS NOT NULL`,
              [workspaceId],
            );
          } else {
            await pool.query(
              `UPDATE tokens SET contact_group_id = NULL, updated_at = NOW()
               WHERE workspace_id = $1
                 AND contact_group_id IS NOT NULL
                 AND contact_group_id != ALL($2::text[])`,
              [workspaceId, updatedGroupIds],
            );
          }
        } catch (_err) {
          logger.warn("DB operation failed", { error: _err.message });
        }
      }

      // Only write audit event if changes are meaningful (not just email_alerts_enabled auto-save)
      const changedFields = fields.map((f) => f.split(" ")[0]);
      const shouldAudit = !(
        changedFields.length === 1 &&
        changedFields[0] === "email_alerts_enabled"
      );

      if (shouldAudit) {
        try {
          // Build contact group before/after summary when groups or webhooks changed
          let cgTo = null;
          try {
            if (
              changedFields.includes("contact_groups") ||
              changedFields.includes("webhook_urls")
            ) {
              // Resolve webhook name -> url mapping
              const _mapUrls = (webhookList) => {
                const nameToUrl = new Map();
                (Array.isArray(webhookList) ? webhookList : []).forEach((w) => {
                  const nm = w && w.name ? String(w.name).trim() : "";
                  const url = w && w.url ? String(w.url).trim() : "";
                  if (nm && url) nameToUrl.set(nm, url);
                });
                return nameToUrl;
              };
              const _extractContactIds = (group) => {
                if (!group || typeof group !== "object") return [];
                const normalized = [];
                const addIds = (maybeIds) => {
                  if (!Array.isArray(maybeIds)) return;
                  for (const rawId of maybeIds) {
                    if (rawId === null || rawId === undefined) continue;
                    const strId = String(rawId).trim();
                    if (strId) normalized.push(strId);
                  }
                };
                addIds(group.email_contact_ids);
                addIds(group.whatsapp_contact_ids);
                return normalized;
              };

              // Build detailed change description by comparing groups
              const describeChanges = async () => {
                const before = Array.isArray(currentGroups)
                  ? currentGroups
                  : [];
                const after = Array.isArray(contact_groups)
                  ? contact_groups
                  : before;

                // Fetch contact details for readable names
                const contactMap = new Map();
                try {
                  const allContactIds = new Set([
                    ...before.flatMap((g) => [
                      ...(g.email_contact_ids || []),
                      ...(g.whatsapp_contact_ids || []),
                    ]),
                    ...after.flatMap((g) => [
                      ...(g.email_contact_ids || []),
                      ...(g.whatsapp_contact_ids || []),
                    ]),
                  ]);
                  if (allContactIds.size > 0) {
                    const { rows } = await pool.query(
                      `SELECT id, first_name, last_name FROM workspace_contacts WHERE workspace_id = $1 AND id = ANY($2::uuid[])`,
                      [workspaceId, Array.from(allContactIds)],
                    );
                    rows.forEach((r) => {
                      contactMap.set(
                        String(r.id),
                        `${r.first_name} ${r.last_name}`.trim(),
                      );
                    });
                  }
                } catch (_err) {
                  logger.warn("DB operation failed", { error: _err.message });
                }

                const changes = [];
                const afterMap = new Map(after.map((g) => [g.id, g]));
                const beforeMap = new Map(before.map((g) => [g.id, g]));

                // Check each group for changes
                for (const [groupId, afterGroup] of afterMap) {
                  const beforeGroup = beforeMap.get(groupId);
                  const groupName = afterGroup.name || groupId;

                  if (!beforeGroup) {
                    changes.push(`Added group "${groupName}"`);
                    continue;
                  }

                  // Check email contacts
                  const beforeEmail = new Set(
                    beforeGroup.email_contact_ids || [],
                  );
                  const afterEmail = new Set(
                    afterGroup.email_contact_ids || [],
                  );
                  const addedEmail = [...afterEmail].filter(
                    (id) => !beforeEmail.has(id),
                  );
                  const removedEmail = [...beforeEmail].filter(
                    (id) => !afterEmail.has(id),
                  );

                  // Check WhatsApp contacts
                  const beforeWhatsapp = new Set(
                    beforeGroup.whatsapp_contact_ids || [],
                  );
                  const afterWhatsapp = new Set(
                    afterGroup.whatsapp_contact_ids || [],
                  );
                  const addedWhatsapp = [...afterWhatsapp].filter(
                    (id) => !beforeWhatsapp.has(id),
                  );
                  const removedWhatsapp = [...beforeWhatsapp].filter(
                    (id) => !afterWhatsapp.has(id),
                  );

                  if (addedEmail.length > 0) {
                    const names = addedEmail
                      .map((id) => contactMap.get(String(id)) || id)
                      .join(", ");
                    changes.push(`"${groupName}": enabled email for ${names}`);
                  }
                  if (removedEmail.length > 0) {
                    const names = removedEmail
                      .map((id) => contactMap.get(String(id)) || id)
                      .join(", ");
                    changes.push(`"${groupName}": disabled email for ${names}`);
                  }
                  if (addedWhatsapp.length > 0) {
                    const names = addedWhatsapp
                      .map((id) => contactMap.get(String(id)) || id)
                      .join(", ");
                    changes.push(
                      `"${groupName}": enabled WhatsApp for ${names}`,
                    );
                  }
                  if (removedWhatsapp.length > 0) {
                    const names = removedWhatsapp
                      .map((id) => contactMap.get(String(id)) || id)
                      .join(", ");
                    changes.push(
                      `"${groupName}": disabled WhatsApp for ${names}`,
                    );
                  }

                  // Check webhooks
                  const beforeWebhooks = new Set(
                    beforeGroup.webhook_names || [],
                  );
                  const afterWebhooks = new Set(afterGroup.webhook_names || []);
                  const addedWebhooks = [...afterWebhooks].filter(
                    (w) => !beforeWebhooks.has(w),
                  );
                  const removedWebhooks = [...beforeWebhooks].filter(
                    (w) => !afterWebhooks.has(w),
                  );

                  if (addedWebhooks.length > 0) {
                    changes.push(
                      `"${groupName}": added webhooks: ${addedWebhooks.join(", ")}`,
                    );
                  }
                  if (removedWebhooks.length > 0) {
                    changes.push(
                      `"${groupName}": removed webhooks: ${removedWebhooks.join(", ")}`,
                    );
                  }
                }

                // Check for deleted groups
                for (const [groupId, beforeGroup] of beforeMap) {
                  if (!afterMap.has(groupId)) {
                    changes.push(
                      `Removed group "${beforeGroup.name || groupId}"`,
                    );
                  }
                }

                return changes.length > 0 ? changes.join(" | ") : "No changes";
              };

              try {
                cgTo = await describeChanges();
                logger.info("Contact group changes detected", {
                  cgTo,
                  workspaceId,
                });
              } catch (err) {
                logger.error("Failed to describe contact group changes", {
                  error: err.message,
                  workspaceId,
                });
                cgTo = "Error describing changes";
              }

              // After lists: use updated values if provided, else current
              const _afterGroups = Array.isArray(contact_groups)
                ? (function computeNorm() {
                    const norm = [];
                    for (const g of contact_groups) {
                      const id = g && g.id ? String(g.id) : null;
                      const name =
                        g && typeof g.name === "string" ? g.name.trim() : "";
                      if (!id || !name) continue;
                      let emails = [];
                      try {
                        if (Array.isArray(g.emails)) {
                          emails = g.emails
                            .map((e) =>
                              String(e || "")
                                .trim()
                                .toLowerCase(),
                            )
                            .filter((e) => /.+@.+\..+/.test(e));
                        }
                      } catch (_err) {
                        logger.debug("Non-critical operation failed", {
                          error: _err.message,
                        });
                      }
                      const uniqueEmails = Array.from(new Set(emails));
                      let webhookNames = [];
                      try {
                        if (Array.isArray(g.webhook_names)) {
                          webhookNames = Array.from(
                            new Set(
                              g.webhook_names
                                .map((n) => String(n || "").trim())
                                .filter(Boolean),
                            ),
                          );
                        } else if (g && g.webhook_name) {
                          const single = String(g.webhook_name).trim();
                          if (single) webhookNames = [single];
                        }
                      } catch (_err) {
                        logger.debug("Non-critical operation failed", {
                          error: _err.message,
                        });
                      }
                      const hasEmails = uniqueEmails.length > 0;
                      const hasWebhook = webhookNames.length > 0;
                      if (!hasEmails && !hasWebhook) continue;
                      norm.push({
                        id,
                        name,
                        emails: uniqueEmails,
                        ...(hasWebhook ? { webhook_names: webhookNames } : {}),
                      });
                    }
                    return norm;
                  })()
                : currentGroups;
            }
          } catch (_err) {
            logger.debug("Non-critical operation failed", {
              error: _err.message,
            });
          }

          const auditMetadata = {
            changed: changedFields,
            ...(cgTo && cgTo !== "No changes"
              ? { contact_groups_changes: cgTo }
              : {}),
          };

          logger.info("Writing audit event", {
            auditMetadata,
            workspaceId,
            userId: req.user.id,
          });

          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "WORKSPACE_ALERT_SETTINGS_UPDATED",
            targetType: "workspace",
            targetId: null,
            workspaceId,
            metadata: auditMetadata,
          });
        } catch (e) {
          logger.warn("Audit write failed for settings update", {
            error: e.message,
            workspaceId,
            userId: req.user?.id,
          });
        }
      }

      return res.json({
        success: true,
      });
    } catch (err) {
      logger.error("Workspace alert settings update error", {
        error: err.message,
        userId: req.user?.id,
        workspaceId: req.workspace?.id,
      });
      return res.status(500).json({
        error: "Failed to update workspace alert settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);
router.put(
  "/api/account/alert-settings",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const {
        alert_thresholds,
        webhook_urls,
        email_alerts_enabled,
        slack_alerts_enabled,
        webhooks_alerts_enabled,
        _apply_default_email_to_all_tokens,
      } = req.body;

      // Fetch current values to capture a precise audit diff
      let before = null;
      try {
        const beforeRes = await pool.query(
          "SELECT alert_thresholds, webhook_urls, email_alerts_enabled, slack_alerts_enabled, webhooks_alerts_enabled, phone_e164, whatsapp_alerts_enabled FROM users WHERE id = $1",
          [req.user.id],
        );
        before = beforeRes.rows[0] || null;
      } catch (_err) {
        logger.warn("Failed to fetch current alert settings for diff", {
          error: _err.message,
        });
      }

      const updates = [];
      const params = [];
      let p = 1;
      const changed = {};

      // Helper: compare arrays of primitives
      const arraysEqual = (a, b) => {
        if (!Array.isArray(a) || !Array.isArray(b)) return false;
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
          if (a[i] !== b[i]) return false;
        }
        return true;
      };

      // Normalize before values
      let beforeThresholds = [];
      try {
        if (Array.isArray(before?.alert_thresholds)) {
          beforeThresholds = before.alert_thresholds
            .filter((n) => Number.isFinite(n))
            .sort((a, b) => b - a);
        }
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      let beforeWebhooks = [];
      try {
        if (Array.isArray(before?.webhook_urls)) {
          beforeWebhooks = before.webhook_urls;
        } else if (
          typeof before?.webhook_urls === "string" &&
          before.webhook_urls.trim().length > 0
        ) {
          const parsed = JSON.parse(before.webhook_urls);
          if (Array.isArray(parsed)) beforeWebhooks = parsed;
        }
      } catch (_err) {
        logger.debug("Parse failed", { error: _err.message });
      }

      // Helper: normalize webhook list for stable comparison (lowercase kinds/severity, drop unknown keys, stable key order, sorted list)
      const normalizeWebhookList = (list) => {
        if (!Array.isArray(list)) return [];
        const cleaned = list
          .filter(
            (w) => w && typeof w.url === "string" && w.url.trim().length > 0,
          )
          .map((w) => {
            const item = {
              kind: String(w.kind || "generic").toLowerCase(),
              url: w.url,
            };
            if (w.routingKey) item.routingKey = w.routingKey;
            if (w.severity) item.severity = String(w.severity).toLowerCase();
            if (w.template) item.template = w.template;
            // Return with stable key order
            const ordered = {};
            const keys = ["kind", "url", "routingKey", "severity", "template"];
            for (const k of keys) if (k in item) ordered[k] = item[k];
            return ordered;
          });
        // Sort deterministically by kind+url+routingKey
        cleaned.sort((a, b) => {
          const ak = `${a.kind}|${a.url}|${a.routingKey || ""}`;
          const bk = `${b.kind}|${b.url}|${b.routingKey || ""}`;
          return ak.localeCompare(bk);
        });
        return cleaned;
      };

      // Thresholds
      if (Object.prototype.hasOwnProperty.call(req.body, "alert_thresholds")) {
        let list = [];
        try {
          if (Array.isArray(alert_thresholds)) {
            list = alert_thresholds
              .filter((n) => Number.isFinite(n) && n >= -365 && n <= 730)
              .sort((a, b) => b - a);
          }
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
        // If nothing valid provided, keep existing thresholds (do not error)
        if (list.length === 0) {
          // no-op: do not push an update; still return 200
        } else {
          // Only update if actually different
          if (!arraysEqual(list, beforeThresholds)) {
            updates.push(`alert_thresholds = $${p}::jsonb`);
            params.push(JSON.stringify(list));
            p += 1;
            changed.alert_thresholds = {
              before: beforeThresholds.length > 0 ? beforeThresholds : null,
              after: list,
            };
          }
        }
      }

      // Toggles
      if (
        Object.prototype.hasOwnProperty.call(req.body, "email_alerts_enabled")
      ) {
        const newVal = Boolean(email_alerts_enabled);
        const oldVal = Boolean(before?.email_alerts_enabled);
        if (newVal !== oldVal) {
          updates.push(`email_alerts_enabled = $${p}`);
          params.push(newVal);
          p += 1;
          changed.email_alerts_enabled = { before: oldVal, after: newVal };
        }
      }
      if (
        Object.prototype.hasOwnProperty.call(req.body, "slack_alerts_enabled")
      ) {
        const newVal = Boolean(slack_alerts_enabled);
        const oldVal = Boolean(before?.slack_alerts_enabled);
        if (newVal !== oldVal) {
          updates.push(`slack_alerts_enabled = $${p}`);
          params.push(newVal);
          p += 1;
          changed.slack_alerts_enabled = { before: oldVal, after: newVal };
        }
      }
      if (
        Object.prototype.hasOwnProperty.call(
          req.body,
          "webhooks_alerts_enabled",
        )
      ) {
        const newVal = Boolean(webhooks_alerts_enabled);
        const oldVal = Boolean(before?.webhooks_alerts_enabled);
        if (newVal !== oldVal) {
          updates.push(`webhooks_alerts_enabled = $${p}`);
          params.push(newVal);
          p += 1;
          changed.webhooks_alerts_enabled = { before: oldVal, after: newVal };
        }
      }

      // Phone (E.164) and WhatsApp opt-in
      if (Object.prototype.hasOwnProperty.call(req.body, "phone_e164")) {
        let normalizedPhone = null;
        if (typeof phone_e164 === "string" && phone_e164.trim().length > 0) {
          const pStr = phone_e164.trim();
          if (!/^\+?[1-9]\d{6,14}$/.test(pStr)) {
            return res.status(400).json({
              error: "Invalid phone format (E.164 expected)",
              code: "INVALID_PHONE_FORMAT",
            });
          }
          normalizedPhone = pStr.startsWith("+") ? pStr : `+${pStr}`;
        }
        const oldVal = before?.phone_e164 || null;
        if (oldVal !== normalizedPhone) {
          updates.push(`phone_e164 = $${p}`);
          params.push(normalizedPhone);
          p += 1;
          changed.phone_e164 = { before: oldVal, after: normalizedPhone };
        }
      }
      if (
        Object.prototype.hasOwnProperty.call(
          req.body,
          "whatsapp_alerts_enabled",
        )
      ) {
        const newVal = Boolean(whatsapp_alerts_enabled);
        const oldVal = Boolean(before?.whatsapp_alerts_enabled);
        if (newVal !== oldVal) {
          updates.push(`whatsapp_alerts_enabled = $${p}`);
          params.push(newVal);
          p += 1;
          changed.whatsapp_alerts_enabled = { before: oldVal, after: newVal };
        }
      }

      // Webhooks list (validate strictly only when provided)
      const normalizedWebhooks = null;
      const _webhooksEnabledBool = undefined;
      if (Object.prototype.hasOwnProperty.call(req.body, "webhook_urls")) {
        const MAX_WEBHOOKS = parseInt(process.env.MAX_WEBHOOKS || "5", 10) || 5;
        let validWebhooks = [];
        if (Array.isArray(webhook_urls)) {
          validWebhooks = webhook_urls
            .filter(
              (wh) =>
                wh && typeof wh.url === "string" && wh.url.trim().length > 0,
            )
            .slice(0, MAX_WEBHOOKS);
        }
        // Strict verification for each provided webhook (skip in tests for flexibility)
        if (process.env.NODE_ENV !== "test") {
          for (const wh of validWebhooks) {
            const resProbe = await testWebhookUrl(
              wh.url,
              wh.kind || "generic",
              wh.routingKey || null,
            );
            if (!resProbe.success) {
              return res.status(400).json({
                error: `Invalid webhook (${(wh.kind || "generic").toLowerCase()}): ${resProbe.error}`,
                code: "WEBHOOK_VALIDATION_FAILED",
              });
            }
          }
        }
        const normalizedAfter = normalizeWebhookList(validWebhooks);
        const normalizedBefore = normalizeWebhookList(beforeWebhooks);
        const beforeStr = JSON.stringify(normalizedBefore);
        const afterStr = JSON.stringify(normalizedAfter);
        if (beforeStr !== afterStr) {
          updates.push(`webhook_urls = $${p}::jsonb`);
          params.push(JSON.stringify(normalizedAfter));
          p += 1;
          changed.webhook_urls = {
            before: normalizedBefore,
            after: normalizedAfter,
          };
        }
      }

      if (updates.length === 0) {
        // Idempotent no-op: return success to avoid frontend error toasts on load
        return res.json({ success: true, no_changes: true });
      }

      // Apply the updates
      const userIdParamIndex = p;
      params.push(req.user.id);
      if (updates.length > 0) {
        const sql = `UPDATE users SET ${updates.join(", ")} WHERE id = $${userIdParamIndex}`;
        await pool.query(sql, params);
      }

      // If webhooks were updated and enabled, re-enable retries for webhook-failed alerts
      if (
        normalizedWebhooks &&
        normalizedWebhooks.length > 0 &&
        (webhooks_alerts_enabled === true ||
          webhooks_alerts_enabled === undefined)
      ) {
        try {
          await pool.query(
            `UPDATE alert_queue
             SET 
               channels = (
                 SELECT (
                   SELECT jsonb_agg(DISTINCT to_jsonb(v)) FROM (
                     SELECT jsonb_array_elements_text(COALESCE(alert_queue.channels::jsonb, '[]'::jsonb)) AS v
                     UNION SELECT 'webhooks'
                   ) s
                 )
               )
               , status = 'pending'
               , next_attempt_at = NOW()
               , updated_at = NOW()
             WHERE user_id = $1
               AND status = 'failed'
               AND (
                 error_message ILIKE '%webhooks%'
                 OR channels::text NOT LIKE '%webhooks%'
               )`,
            [req.user.id],
          );
        } catch (_err) {
          logger.debug("Non-critical operation failed", {
            error: _err.message,
          });
        }
      }

      // Record a single consolidated audit event capturing the changed fields (only if there were changes)
      if (Object.keys(changed).length > 0) {
        try {
          await writeAudit({
            actorUserId: req.user.id,
            subjectUserId: req.user.id,
            action: "ALERT_PREFS_UPDATED",
            targetType: "user",
            targetId: req.user.id,
            channel: null,
            workspaceId: null,
            metadata: { changed },
          });
        } catch (_err) {
          logger.warn("Audit write failed (ALERT_PREFS_UPDATED)", {
            error: _err.message,
          });
        }
      }

      // Respond with minimal echo of changed fields
      return res.json({
        success: true,
      });
    } catch (err) {
      logger.error("Alert settings update error", {
        error: err.message,
        userId: req.user.id,
      });
      res.status(500).json({
        error: "Failed to update alert settings",
        code: "INTERNAL_ERROR",
      });
    }
  },
);

// Test webhook endpoint (supports kind: slack, pagerduty, generic)

// Specific rate limiters for webhook test (5/min and 10/5min per user/IP)
const generateTestWebhookKey = (req) => {
  if (req.user && req.user.id) {
    return `user-${req.user.id}`;
  }
  return ipKeyGenerator(req);
};

const testWebhookLimiter1m = rateLimit({
  windowMs: intEnv("TEST_WEBHOOK_RATE_LIMIT_1M_WINDOW_MS", 60 * 1000),
  max: intEnv("TEST_WEBHOOK_RATE_LIMIT_1M_MAX", 5),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: generateTestWebhookKey,
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "test_webhook_1m",
      userId: req.user?.id,
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res.status(429).json({
      error: "Too many webhook test attempts. Max 5 per minute.",
      code: "RATE_LIMIT_EXCEEDED",
    });
  },
});

const testWebhookLimiter5m = rateLimit({
  windowMs: intEnv("TEST_WEBHOOK_RATE_LIMIT_5M_WINDOW_MS", 5 * 60 * 1000),
  max: intEnv("TEST_WEBHOOK_RATE_LIMIT_5M_MAX", 10),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: generateTestWebhookKey,
  handler: (req, res) => {
    logger.warn("RATE_LIMIT_EXCEEDED", {
      type: "test_webhook_5m",
      userId: req.user?.id,
      ip: ipKeyGenerator(req),
      userAgent: req.get("User-Agent"),
    });
    res.status(429).json({
      error: "Too many webhook test attempts. Max 10 per 5 minutes.",
      code: "RATE_LIMIT_EXCEEDED",
    });
  },
});
router.post(
  "/api/test-webhook",
  getApiLimiter(),
  requireAuth,
  testWebhookLimiter1m,
  testWebhookLimiter5m,
  async (req, res) => {
    try {
      // Lightweight per-user cooldown in memory (5s)
      // Note: acceptable for single-instance; for multi-instance, use a shared store
      if (!global.__testWebhookCooldown)
        global.__testWebhookCooldown = new Map();
      const userKey =
        req.user && req.user.id
          ? `u:${req.user.id}`
          : `ip:${ipKeyGenerator(req)}`;
      const now = Date.now();
      const until = global.__testWebhookCooldown.get(userKey) || 0;
      if (until > now) {
        const secs = Math.ceil((until - now) / 1000);
        return res.status(429).json({
          error: `Please wait ${secs}s before sending another test.`,
          code: "TEST_WEBHOOK_COOLDOWN",
        });
      }
      // Allowed provider hosts (align with apps/worker delivery logic)
      const DEFAULT_PROVIDER_HOSTS = [
        "hooks.slack.com",
        "discord.com",
        "discordapp.com",
        "outlook.office.com",
        "webhook.office.com",
        "office.com",
        "office365.com",
        "events.eu.pagerduty.com",
        "*.office.com",
        "*.office365.com",
        "events.pagerduty.com",
        "*.pagerduty.com",
      ];
      const hostMatchesAllowed = (hostname, allowedList) => {
        for (const entry of allowedList) {
          if (entry.startsWith("*.")) {
            const suffix = entry.slice(1); // .domain
            if (hostname.endsWith(suffix)) return true;
          }
          if (hostname === entry) return true;
        }
        return false;
      };
      const extraHostsEnv = (
        process.env.WEBHOOK_EXTRA_PROVIDER_HOSTS ||
        process.env.WEBHOOK_PROVIDER_HOSTS ||
        ""
      )
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const ALLOW_ALL_HOSTS =
        String(process.env.WEBHOOK_ALLOW_ALL_HOSTS || "").toLowerCase() ===
          "true" || extraHostsEnv.includes("*");
      const {
        url,
        kind = "generic",
        severity = "warning",
        template = null,
        routingKey = null,
      } = req.body;
      if (!url) {
        return res
          .status(400)
          .json({ error: "Webhook URL is required", code: "VALIDATION_ERROR" });
      }
      // Basic validation
      let target;
      try {
        target = new URL(url);
      } catch (_) {
        return res
          .status(400)
          .json({ error: "Invalid webhook URL", code: "VALIDATION_ERROR" });
      }
      if (!/^https?:$/.test(target.protocol)) {
        return res.status(400).json({
          error: "Webhook URL must be http(s)",
          code: "VALIDATION_ERROR",
        });
      }

      const normalizeSeverity = (raw) => {
        const s = String(raw || "").toLowerCase();
        return ["critical", "error", "warning", "info"].includes(s)
          ? s
          : "warning";
      };

      // Friendly provider allowlist check
      const lowerKind = String(req.body?.kind || "generic").toLowerCase();
      if (lowerKind !== "generic") {
        const allowed = hostMatchesAllowed(
          target.hostname,
          DEFAULT_PROVIDER_HOSTS,
        );
        if (!allowed && !ALLOW_ALL_HOSTS) {
          return res.status(400).json({
            error: `Webhook host not allowed for provider (${lowerKind}). Use a domain such as hooks.slack.com, discord.com, outlook.office.com/webhook.office.com, office365.com, or events.pagerduty.com`,
            code: "WEBHOOK_HOST_NOT_ALLOWED",
          });
        }
      }

      const testTokenData = {
        token_id: "test",
        name: "Test Token",
        type: "ssl_cert",
        expiration: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
          .toISOString()
          .slice(0, 10),
        daysLeft: 7,
      };

      const text = template || "This is a test message from TokenTimer";
      const sev = normalizeSeverity(severity);

      // Build a payload similar to the alert runner's templates for realism
      let payload;
      switch (String(kind || "generic").toLowerCase()) {
        case "slack": {
          const testTitle = template || "TokenTimer Test";
          const daysText =
            typeof testTokenData.daysLeft === "number" &&
            testTokenData.daysLeft <= 0
              ? "EXPIRED"
              : `${testTokenData.daysLeft} day(s)`;
          const fallback = `${testTitle}: ${testTokenData.name} expires in ${daysText}${testTokenData.expiration ? ` (on ${testTokenData.expiration})` : ""}.`;
          payload = {
            text: fallback,
            blocks: [
              {
                type: "header",
                text: {
                  type: "plain_text",
                  text: `\u{1F514} ${testTitle}`,
                  emoji: true,
                },
              },
              { type: "divider" },
              {
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `*${testTokenData.name}* ${
                    daysText === "EXPIRED"
                      ? "has *EXPIRED*"
                      : `expires in *${daysText}*`
                  }`,
                },
              },
              {
                type: "section",
                fields: [
                  { type: "mrkdwn", text: `*Type:*\n${testTokenData.type}` },
                  {
                    type: "mrkdwn",
                    text: `*Expiration:*\n${testTokenData.expiration}`,
                  },
                  { type: "mrkdwn", text: `*Severity:*\n${sev.toUpperCase()}` },
                  { type: "mrkdwn", text: `*Days Remaining:*\n${daysText}` },
                ],
              },
              {
                type: "actions",
                elements: [
                  {
                    type: "button",
                    text: {
                      type: "plain_text",
                      text: "View in TokenTimer",
                      emoji: true,
                    },
                    url: `${(process.env.APP_URL || "http://localhost:5173").replace(/\/$/, "")}/dashboard`,
                    style: sev === "critical" ? "danger" : "primary",
                  },
                ],
              },
              {
                type: "context",
                elements: [
                  {
                    type: "mrkdwn",
                    text: `Generated - ${new Date().toISOString()}`,
                  },
                ],
              },
            ],
          };
          break;
        }
        case "discord": {
          const color =
            sev === "critical"
              ? 15158332
              : sev === "error"
                ? 16738816
                : sev === "warning"
                  ? 16776960
                  : 3447003;
          payload = {
            content: `\u{1F514} **${template || "TokenTimer Test"}**`,
            embeds: [
              {
                title: testTokenData.name,
                description: `Expires in **${testTokenData.daysLeft} day(s)**`,
                color,
                fields: [
                  { name: "Type", value: testTokenData.type, inline: true },
                  {
                    name: "Expiration",
                    value: testTokenData.expiration,
                    inline: true,
                  },
                  { name: "Severity", value: sev, inline: true },
                ],
                timestamp: new Date().toISOString(),
              },
            ],
          };
          break;
        }
        case "teams": {
          const theme =
            sev === "critical" || sev === "error"
              ? "attention"
              : sev === "warning"
                ? "warning"
                : "accent";
          payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            summary: template || "TokenTimer Test",
            themeColor: theme,
            sections: [
              {
                activityTitle: template || "TokenTimer Test",
                activitySubtitle: `${testTokenData.name} expires in ${testTokenData.daysLeft} day(s)`,
                facts: [
                  { name: "Type", value: testTokenData.type },
                  { name: "Expiration Date", value: testTokenData.expiration },
                  { name: "Severity", value: sev },
                ],
              },
            ],
          };
          break;
        }
        case "pagerduty": {
          // Validate routing key format before issuing network call
          const key = String(routingKey || "").trim();
          if (!key) {
            return res.status(400).json({
              error: "PagerDuty routing key is required for kind=pagerduty",
              code: "VALIDATION_ERROR",
            });
          }
          // PagerDuty Events v2 routing keys are 32-character strings (alphanumeric)
          if (key.length !== 32 || !/^[A-Za-z0-9]{32}$/.test(key)) {
            return res.status(400).json({
              error:
                "Invalid PagerDuty routing key format (must be 32 alphanumeric characters)",
              code: "VALIDATION_ERROR",
            });
          }
          payload = {
            routing_key: key,
            event_action: "trigger",
            payload: {
              summary: template || text,
              source: "TokenTimer",
              severity: sev,
              timestamp: new Date().toISOString(),
              custom_details: testTokenData,
            },
          };
          break;
        }
        case "generic":
        default: {
          // Generic payload that aims to be accepted by many endpoints (Slack/Discord/generic JSON)
          payload = {
            // Slack-friendly
            text,
            // Discord-friendly
            content: `\u{1F514} ${template || text}`,
            // Generic fields
            message: text,
            severity: sev,
            title: template || undefined,
            timestamp: new Date().toISOString(),
            type: "token_expiry_alert",
            token: testTokenData,
          };
        }
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const resp = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        clearTimeout(timeout);
        // Set cooldown after attempt regardless of outcome
        global.__testWebhookCooldown.set(
          userKey,
          Date.now() + intEnv("TEST_WEBHOOK_COOLDOWN_MS", 5000),
        );
        const { status } = resp;
        let rawText = "";
        try {
          rawText = await resp.text();
        } catch (_) {
          rawText = "";
        }

        // Provider-specific validation
        const k = String(kind || "generic").toLowerCase();
        const fail = (msg) =>
          res
            .status(400)
            .json({ success: false, error: msg, code: "WEBHOOK_TEST_FAILED" });
        const pass = (msg) =>
          res.json({ success: true, message: msg || `OK (${status})` });

        if (k === "slack") {
          if (status === 200 && rawText.trim().toLowerCase() === "ok") {
            return pass("Slack responded OK (200)");
          }
          return fail(`Slack responded ${status}: ${rawText}`);
        }

        if (k === "discord") {
          if (status === 204 || status === 200) {
            return pass(`Discord accepted (${status})`);
          }
          return fail(`Discord responded ${status}: ${rawText}`);
        }

        if (k === "teams") {
          // Teams typically returns 200 and sometimes body '1'
          if (status === 200) {
            return pass("Teams accepted (200)");
          }
          return fail(`Teams responded ${status}: ${rawText}`);
        }

        if (k === "pagerduty") {
          let body = {};
          try {
            body = JSON.parse(rawText || "{}");
          } catch (_err) {
            logger.debug("Parse failed", { error: _err.message });
          }
          // Require explicit success field
          if (
            status >= 200 &&
            status < 300 &&
            body &&
            String(body.status || "").toLowerCase() === "success"
          ) {
            return pass("PagerDuty accepted");
          }
          return fail(`PagerDuty responded ${status}: ${rawText || "no body"}`);
        }

        // Generic: require 2xx
        if (status >= 200 && status < 300) {
          return pass(`OK (${status})`);
        }
        return fail(`Webhook responded ${status}: ${rawText}`);
      } catch (e) {
        clearTimeout(timeout);
        // Provide friendlier messages for common network failures
        const msg = String(e && e.message ? e.message : "").toLowerCase();
        if (e.name === "AbortError") {
          return res.status(504).json({
            error:
              "Timed out connecting to the webhook endpoint (5s). Please verify the URL is reachable and try again.",
            code: "WEBHOOK_TIMEOUT",
          });
        }
        if (msg.includes("fetch failed") || msg.includes("system error")) {
          return res.status(502).json({
            error:
              "Could not connect to the webhook endpoint. The URL may be invalid or unreachable from the server. Please verify the URL and network access.",
            code: "WEBHOOK_UNREACHABLE",
          });
        }
        return res.status(500).json({
          error: e.message || "Failed to test webhook",
          code: "INTERNAL_ERROR",
        });
      }
    } catch (error) {
      logger.error("Test webhook error:", {
        error: error.message,
        stack: error.stack,
      });
      res
        .status(500)
        .json({ error: "Failed to test webhook", code: "INTERNAL_ERROR" });
    }
  },
);
// Alert queue visibility for current user
router.get(
  "/api/alert-queue",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const workspaceId = req.query.workspace_id || null;
      const limit = Math.max(
        1,
        Math.min(200, parseInt(req.query.limit || "100", 10)),
      );
      const offset = Math.max(
        0,
        Math.min(100000, parseInt(req.query.offset || "0", 10)),
      );
      let rows;
      if (workspaceId) {
        // Workspace-scoped queue for managers/admins
        const m = await pool.query(
          "SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
          [workspaceId, req.user.id],
        );
        const role = m.rows?.[0]?.role || null;
        if (!role || !["admin", "workspace_manager"].includes(role))
          return res
            .status(403)
            .json({ error: "Forbidden", code: "FORBIDDEN" });
        rows = await pool.query(
          `SELECT aq.id, aq.token_id, aq.threshold_days, aq.due_date, aq.status, aq.attempts, aq.error_message, aq.channels, aq.created_at, aq.updated_at,
              aq.next_attempt_at, aq.attempts_email, aq.attempts_webhooks, aq.attempts_whatsapp,
              -- channel-specific last errors
              (SELECT l.error_message FROM alert_delivery_log l WHERE l.alert_queue_id = aq.id AND l.channel='email' ORDER BY l.sent_at DESC LIMIT 1) AS last_error_email,
              (SELECT l.error_message FROM alert_delivery_log l WHERE l.alert_queue_id = aq.id AND l.channel='webhooks' ORDER BY l.sent_at DESC LIMIT 1) AS last_error_webhooks,
              (SELECT l.error_message FROM alert_delivery_log l WHERE l.alert_queue_id = aq.id AND l.channel='whatsapp' ORDER BY l.sent_at DESC LIMIT 1) AS last_error_whatsapp,
              t.name as token_name, t.type as token_type
       FROM alert_queue aq
       JOIN tokens t ON t.id = aq.token_id
       WHERE t.workspace_id = $1 AND aq.status IN ('pending','failed','limit_exceeded','blocked','partial')
       ORDER BY aq.due_date ASC, aq.created_at ASC
       LIMIT $2
       OFFSET $3`,
          [workspaceId, limit, offset],
        );
      } else {
        // Legacy/user-scoped queue
        rows = await pool.query(
          `SELECT aq.id, aq.token_id, aq.threshold_days, aq.due_date, aq.status, aq.attempts, aq.error_message, aq.channels, aq.created_at, aq.updated_at,
              aq.next_attempt_at, aq.attempts_email, aq.attempts_webhooks, aq.attempts_whatsapp,
              -- channel-specific last errors
              (SELECT l.error_message FROM alert_delivery_log l WHERE l.alert_queue_id = aq.id AND l.channel='email' ORDER BY l.sent_at DESC LIMIT 1) AS last_error_email,
              (SELECT l.error_message FROM alert_delivery_log l WHERE l.alert_queue_id = aq.id AND l.channel='webhooks' ORDER BY l.sent_at DESC LIMIT 1) AS last_error_webhooks,
              (SELECT l.error_message FROM alert_delivery_log l WHERE l.alert_queue_id = aq.id AND l.channel='whatsapp' ORDER BY l.sent_at DESC LIMIT 1) AS last_error_whatsapp,
              t.name as token_name, t.type as token_type
       FROM alert_queue aq
       JOIN tokens t ON t.id = aq.token_id
       WHERE aq.user_id = $1 AND aq.status IN ('pending','failed','limit_exceeded','blocked','partial')
       ORDER BY aq.due_date ASC, aq.created_at ASC
       LIMIT $2
       OFFSET $3`,
          [req.user.id, limit, offset],
        );
      }

      // Expand channels into separate rows
      const expandedAlerts = [];
      for (const alert of rows.rows) {
        let channels = [];
        try {
          channels = Array.isArray(alert.channels)
            ? alert.channels
            : JSON.parse(alert.channels);
        } catch (_) {
          channels = [];
        }

        if (channels.length === 0) {
          // If no channels, still show the alert
          expandedAlerts.push({
            ...alert,
            channel: null,
            channel_display: "None",
            channel_error_message: null,
          });
        } else {
          // Create one row per channel
          for (const channel of channels) {
            const channel_error_message =
              channel === "email"
                ? alert.last_error_email
                : channel === "webhooks"
                  ? alert.last_error_webhooks
                  : channel === "whatsapp"
                    ? alert.last_error_whatsapp
                    : null;
            expandedAlerts.push({
              ...alert,
              channel,
              channel_display:
                channel === "email"
                  ? "\u{1F4E7} Email"
                  : channel === "webhooks"
                    ? "\u{1F517} Webhooks"
                    : channel === "whatsapp"
                      ? "\u{1F4AC} WhatsApp"
                      : channel,
              channel_error_message,
            });
          }
        }
      }

      res.json({ alerts: expandedAlerts });
    } catch (err) {
      logger.error("Alert queue fetch error", {
        error: err.message,
        userId: req.user.id,
      });
      res
        .status(500)
        .json({ error: "Failed to fetch alert queue", code: "INTERNAL_ERROR" });
    }
  },
);

// Delivery statistics (workspace-scoped; managers/admins only)
router.get(
  "/api/alert-stats",
  getApiLimiter(),
  requireAuth,
  async (req, res) => {
    try {
      const workspaceId = req.query.workspace_id || null;
      if (!workspaceId)
        return res
          .status(400)
          .json({ error: "workspace_id required", code: "VALIDATION_ERROR" });
      const m = await pool.query(
        "SELECT role FROM workspace_memberships WHERE workspace_id=$1 AND user_id=$2",
        [workspaceId, req.user.id],
      );
      const role = m.rows?.[0]?.role || null;
      if (!role || !["admin", "workspace_manager"].includes(role))
        return res.status(403).json({ error: "Forbidden", code: "FORBIDDEN" });

      const byChannel = await pool.query(
        `SELECT d.channel,
              COUNT(*)::int AS attempts,
              COUNT(*) FILTER (WHERE d.status='success')::int AS successes
       FROM alert_delivery_log d
      WHERE d.workspace_id = $1
        AND date_trunc('month', (d.sent_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))
      GROUP BY d.channel`,
        [workspaceId],
      );
      // monthUsage excludes WhatsApp to reflect only email+webhook plan consumption
      const monthUsage = await pool.query(
        `SELECT COUNT(*)::int AS c
         FROM alert_delivery_log d
        WHERE d.workspace_id = $1 AND d.status='success'
          AND d.channel <> 'whatsapp'
          AND date_trunc('month', (d.sent_at AT TIME ZONE 'UTC')) = date_trunc('month', (NOW() AT TIME ZONE 'UTC'))`,
        [workspaceId],
      );
      res.json({
        byChannel: byChannel.rows,
        monthUsage: monthUsage.rows?.[0]?.c || 0,
      });
    } catch (err) {
      logger.error("Alert stats fetch error", {
        error: err.message,
        userId: req.user.id,
      });
      res
        .status(500)
        .json({ error: "Failed to fetch alert stats", code: "INTERNAL_ERROR" });
    }
  },
);
// Delete user account (GDPR Right to be Forgotten)

module.exports = router;
