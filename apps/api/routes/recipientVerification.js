const express = require("express");
const { pool } = require("../db/database");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const { getApiLimiter, recipientVerificationPageLimiter } = require("../middleware/rateLimit");
const { resolveClientIp } = require("../utils/logger");
const { requireAuth } = require("../middleware/auth");
const { loadWorkspace, requireWorkspaceMembership } = require("../services/rbac");
const { sendEmail } = require("../services/emailService");
const systemSettings = require("../services/systemSettings");
const verification = require("../../../packages/recipient-verification");

const router = express.Router({ mergeParams: true });

function managerOnly(req, res) {
  const role = req.authz?.workspaceRole;
  if (!role || !["admin", "workspace_manager"].includes(role)) {
    res.status(403).json({ error: "Forbidden: insufficient role", code: "FORBIDDEN" });
    return false;
  }
  return true;
}

function sendError(res, error) {
  const status = error.status || 500;
  if (status >= 500) logger.error("recipient verification failed", { code: error.code || "INTERNAL_ERROR" });
  return res.status(status).json({
    error: status >= 500 ? "Recipient verification failed" : error.message,
    code: error.code || "INTERNAL_ERROR",
    ...(error.retryAfter ? { retryAfter: error.retryAfter } : {}),
  });
}

async function audit(req, action, metadata) {
  try {
    await writeAudit({
      actorUserId: req.user?.id || null,
      subjectUserId: req.user?.id || null,
      action,
      targetType: "workspace",
      targetId: null,
      workspaceId: req.workspace?.id || metadata.workspace_id || null,
      metadata,
    });
  } catch (error) {
    logger.debug("recipient verification audit skipped", { error: error.message });
  }
}

router.post(
  "/api/v1/workspaces/:id/contacts/:contactId/verifications/:channel",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    if (!managerOnly(req, res)) return undefined;
    const channel = String(req.params.channel || "");
    if (channel !== "email" && channel !== "whatsapp") {
      return res.status(400).json({ error: "Unsupported channel", code: "VALIDATION_ERROR" });
    }
    try {
      if (!verification.publicApiBase()) {
        return res.status(503).json({
          error: "PUBLIC_BASE_URL or API_URL must be set before verification invitations can be created",
          code: "RECIPIENT_VERIFICATION_UNAVAILABLE",
        });
      }
      const invitation = await verification.createInvitation({
        pool,
        workspaceId: req.workspace.id,
        contactId: req.params.contactId,
        channel,
        actorUserId: req.user.id,
      });
      if (invitation.withholdDelivery || !invitation.token) {
        await audit(req, "RECIPIENT_VERIFICATION_RESUBSCRIBE_REQUIRED", {
          contact_id: req.params.contactId,
          channel,
          destination_masked: channel === "email"
            ? verification.maskEmail(invitation.destination)
            : verification.maskPhone(invitation.destination),
        });
        return res.status(200).json({
          status: "opted_out",
          channel,
          code: "RECIPIENT_OPTED_OUT",
          ...(channel === "email"
            ? { resubscribe_url: `${verification.publicApiBase()}/verify/recipient/resubscribe` }
            : {}),
        });
      }
      if (channel === "email") {
        const link = `${verification.publicApiBase()}/verify/recipient/${encodeURIComponent(invitation.token)}`;
        const workspaceName = req.workspace.name || "your workspace";
        const sent = await sendEmail({
          to: invitation.destination,
          subject: "Confirm TokenTimer notifications",
          text: `${workspaceName} invited this address to receive TokenTimer expiration alerts and weekly digests. Open ${link} and choose whether to confirm. This link expires in 48 hours.`,
          html: `<p><strong>${verification.escapeHtml(workspaceName)}</strong> invited this address to receive TokenTimer expiration alerts and weekly digests.</p><p><a href="${verification.escapeHtml(link)}">Review and confirm</a></p><p>The link expires in 48 hours. Opening it does not confirm anything.</p>`,
        });
        const outcome = sent?.success ? "accepted" : (sent?.code === "SMTP_TIMEOUT" ? "ambiguous" : "failed");
        await verification.noteInvitationDispatch({
          pool,
          workspaceId: req.workspace.id,
          contactId: req.params.contactId,
          channel,
          challengeId: invitation.challengeId,
          outcome,
        });
        if (!sent?.success) {
          return res.status(502).json({
            error: outcome === "ambiguous"
              ? "Verification email may already have been accepted. Wait before sending another."
              : "Verification email could not be sent",
            code: outcome === "ambiguous" ? "VERIFICATION_EMAIL_UNCERTAIN" : "VERIFICATION_EMAIL_FAILED",
          });
        }
        await audit(req, "RECIPIENT_VERIFICATION_INVITED", {
          contact_id: req.params.contactId,
          channel,
          destination_masked: verification.maskEmail(invitation.destination),
        });
        return res.status(202).json({ status: "sent", channel, expires_at: invitation.expiresAt });
      }
      const shareUrl = `${verification.publicApiBase() || ""}/verify/recipient/${encodeURIComponent(invitation.token)}`;
      await audit(req, "RECIPIENT_VERIFICATION_INVITED", {
        contact_id: req.params.contactId,
        channel,
        destination_masked: verification.maskPhone(invitation.destination),
      });
      return res.status(201).json({
        status: "pending",
        channel,
        expires_at: invitation.expiresAt,
        share_url: shareUrl,
      });
    } catch (error) {
      if (error.status === 429) {
        await audit(req, "RECIPIENT_VERIFICATION_RATE_LIMITED", {
          contact_id: req.params.contactId,
          channel,
          code: error.code,
        });
      }
      return sendError(res, error);
    }
  },
);

router.post(
  "/api/v1/workspaces/:id/contacts/:contactId/verifications/:channel/revoke",
  getApiLimiter(),
  requireAuth,
  loadWorkspace,
  requireWorkspaceMembership,
  async (req, res) => {
    if (!managerOnly(req, res)) return undefined;
    const channel = String(req.params.channel || "");
    try {
      await verification.revokeChannel({
        pool,
        workspaceId: req.workspace.id,
        contactId: req.params.contactId,
        channel,
        actorUserId: req.user.id,
      });
      await audit(req, "RECIPIENT_VERIFICATION_REVOKED", { contact_id: req.params.contactId, channel });
      return res.json({ status: "revoked", channel });
    } catch (error) {
      return sendError(res, error);
    }
  },
);

function html(res, status, body) {
  verification.verificationResponseHeaders(res);
  res.status(status).type("html").send(body);
}

async function limitPublicVerification(req, res) {
  const ip = resolveClientIp(req) || "unknown";
  const key = verification.destinationFingerprint("public", ip) || verification.hashToken(`public:${ip}`);
  try {
    await verification.assertPublicVerificationBudget(pool, key);
    return false;
  } catch (error) {
    if (error.status === 429) {
      res.set("Retry-After", String(error.retryAfter || 60));
      html(res, 429, verification.renderDone("invalid"));
      return true;
    }
    logger.error("recipient verification page limit failed", { code: error.code || "INTERNAL_ERROR" });
    html(res, 503, verification.renderDone("invalid"));
    return true;
  }
}

router.get("/verify/recipient/resubscribe", recipientVerificationPageLimiter, async (req, res) => {
  if (await limitPublicVerification(req, res)) return undefined;
  return html(res, 200, verification.renderResubscribeForm());
});

router.post("/verify/recipient/resubscribe", recipientVerificationPageLimiter, async (req, res) => {
  if (await limitPublicVerification(req, res)) return undefined;
  const email = req.body && (req.body.email || req.body.destination);
  try {
    const invitations = await verification.requestEmailResubscribe({
      pool,
      email,
      requestIp: resolveClientIp(req) || null,
    });
    for (const invitation of invitations) {
      if (!invitation.token) continue;
      const link = `${verification.publicApiBase()}/verify/recipient/${encodeURIComponent(invitation.token)}`;
      const workspaceName = invitation.workspaceName || "A TokenTimer workspace";
      const sent = await sendEmail({
        to: invitation.destination,
        subject: "Confirm TokenTimer notifications again",
        text: `${workspaceName} can send expiration alerts to this address again only if you open ${link} and accept. This link expires in 48 hours.`,
        html: `<p><strong>${verification.escapeHtml(workspaceName)}</strong> can send expiration alerts to this address again only if you accept.</p><p><a href="${verification.escapeHtml(link)}">Review and confirm</a></p><p>The link expires in 48 hours. Opening it does not confirm anything.</p>`,
      });
      await verification.noteInvitationDispatch({
        pool,
        workspaceId: invitation.workspaceId,
        contactId: invitation.contactId,
        channel: "email",
        challengeId: invitation.challengeId,
        outcome: sent?.success ? "accepted" : (sent?.code === "SMTP_TIMEOUT" ? "ambiguous" : "failed"),
      });
    }
  } catch (error) {
    logger.error("recipient resubscribe failed", { code: error.code || "INTERNAL_ERROR" });
  }
  return html(res, 200, verification.renderResubscribeAccepted());
});

router.get("/verify/recipient/done", recipientVerificationPageLimiter, async (req, res) => {
  if (await limitPublicVerification(req, res)) return undefined;
  const result = req.query.result === "accepted" || req.query.result === "declined" ? req.query.result : "invalid";
  return html(res, 200, verification.renderDone(result));
});

router.get("/verify/recipient/:token", recipientVerificationPageLimiter, async (req, res) => {
  if (await limitPublicVerification(req, res)) return undefined;
  try {
    const challenge = await verification.loadChallenge(pool, req.params.token);
    const fromNumber = challenge.channel === "whatsapp" ? await officialWhatsAppFrom() : null;
    return html(res, 200, verification.renderChallengePage({
      ...challenge,
      token: req.params.token,
      fromNumber,
    }));
  } catch (error) {
    logger.error("recipient verification page failed", { error: error.message });
    return html(res, 404, verification.renderDone("invalid"));
  }
});

router.post("/verify/recipient/:token/accept", recipientVerificationPageLimiter, async (req, res) => {
  if (await limitPublicVerification(req, res)) return undefined;
  try {
    const result = await verification.consumeEmailChallenge({ pool, token: req.params.token, decision: "accept" });
    return res.redirect(303, `/verify/recipient/done?result=${result.ok ? "accepted" : "invalid"}`);
  } catch (error) {
    logger.error("recipient verification accept failed", { error: error.message });
    return res.redirect(303, "/verify/recipient/done?result=invalid");
  }
});

router.post("/verify/recipient/:token/decline", recipientVerificationPageLimiter, async (req, res) => {
  if (await limitPublicVerification(req, res)) return undefined;
  try {
    const loaded = await verification.loadChallenge(pool, req.params.token);
    if (loaded.channel === "whatsapp" && loaded.state === "pending") {
      await declineWhatsAppChallenge(req.params.token);
      return res.redirect(303, "/verify/recipient/done?result=declined");
    }
    const result = await verification.consumeEmailChallenge({ pool, token: req.params.token, decision: "decline" });
    return res.redirect(303, `/verify/recipient/done?result=${result.ok ? "declined" : "invalid"}`);
  } catch (error) {
    logger.error("recipient verification decline failed", { error: error.message });
    return res.redirect(303, "/verify/recipient/done?result=invalid");
  }
});

async function declineWhatsAppChallenge(token) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const consumed = await client.query(
      `UPDATE contact_verification_challenges
          SET status = 'declined', consumed_at = NOW(), attempt_count = attempt_count + 1
        WHERE token_hash = $1 AND channel = 'whatsapp' AND status = 'pending' AND expires_at > NOW()
        RETURNING workspace_id, contact_id, channel, destination_normalized, destination_fingerprint`,
      [verification.hashToken(token)],
    );
    const row = consumed.rows[0];
    if (!row) {
      await client.query("ROLLBACK");
      return;
    }
    await client.query(
      `INSERT INTO contact_channel_verifications
         (workspace_id, contact_id, channel, destination_normalized, destination_fingerprint, status, opted_out_at, opt_out_method, updated_at)
       VALUES ($1,$2,$3,$4,$5,'opted_out', NOW(), 'recipient_declined', NOW())
       ON CONFLICT (workspace_id, contact_id, channel) DO UPDATE
         SET status = 'opted_out', opted_out_at = NOW(), opt_out_method = 'recipient_declined',
             verified_at = NULL, consent_at = NULL, updated_at = NOW()`,
      [row.workspace_id, row.contact_id, row.channel, row.destination_normalized, row.destination_fingerprint],
    );
    await client.query(
      `INSERT INTO notification_suppressions
         (channel, destination_fingerprint, scope, workspace_id, reason)
       VALUES ($1,$2,'workspace',$3,'recipient_declined')
       ON CONFLICT (channel, destination_fingerprint, workspace_id, reason) WHERE scope = 'workspace'
       DO NOTHING`,
      [row.channel, row.destination_fingerprint, row.workspace_id],
    );
    await client.query("COMMIT");
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch (_) { /* ignore */ }
    throw error;
  } finally {
    client.release();
  }
}

async function officialWhatsAppFrom() {
  const envFrom = process.env.TWILIO_WHATSAPP_FROM;
  if (envFrom) return envFrom;
  try {
    return await systemSettings.getSettingValue(pool, "twilio_whatsapp_from");
  } catch (_) {
    return null;
  }
}

router.post("/webhooks/twilio/whatsapp/inbound", getApiLimiter(), async (req, res) => {
  try {
    const token = process.env.TWILIO_AUTH_TOKEN
      || await systemSettings.getSettingValue(pool, "twilio_auth_token")
      || "";
    const base = verification.publicApiBase();
    if (!token || !base) return res.status(503).json({ error: "Twilio inbound webhook is not configured", code: "WEBHOOK_NOT_CONFIGURED" });
    const url = base + req.originalUrl;
    const valid = verification.verifyTwilioSignature({
      url,
      params: req.body && typeof req.body === "object" ? req.body : {},
      signature: req.get("X-Twilio-Signature") || "",
      authToken: token,
    });
    if (!valid) return res.status(403).json({ error: "Invalid signature", code: "FORBIDDEN" });
    const result = await verification.confirmWhatsAppInbound({
      pool,
      from: req.body?.From,
      body: req.body?.Body,
      messageSid: req.body?.MessageSid || req.body?.SmsSid,
    });
    if (result.ok) {
      try {
        await writeAudit({
          actorUserId: null,
          action: "RECIPIENT_WHATSAPP_CONFIRMED",
          targetType: "workspace",
          workspaceId: result.workspaceId,
          metadata: { channel: "whatsapp" },
        });
      } catch (error) {
        logger.debug("whatsapp confirmation audit skipped", { error: error.message });
      }
    }
    return res.status(200).type("text/xml").send("<Response></Response>");
  } catch (error) {
    logger.warn("twilio inbound verification failed", { error: error.message });
    return res.status(200).type("text/xml").send("<Response></Response>");
  }
});

module.exports = router;
