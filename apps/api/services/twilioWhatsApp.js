const axios = require("axios");
const { logger } = require("../utils/logger");
const systemSettings = require("./systemSettings");

// Pool reference for system settings resolver (set via setPool)
let _pool = null;
/**
 * Inject the database pool for resolving Twilio settings from system_settings.
 * @param {import('pg').Pool} pool
 */
function setPool(pool) {
  _pool = pool;
}

/**
 * Mask a phone number for safe logging, keeping only the last 4 digits.
 * @param {string} e164 - Phone number in E.164 format
 * @returns {string} Masked phone like "***1234"
 */
function maskPhone(e164) {
  try {
    const s = String(e164 || "").replace(/[^\d+]/g, "");
    const tail = s.slice(-4);
    return s.length > 4 ? `***${tail}` : `***`;
  } catch (_) {
    return "***";
  }
}

function getTwilioAuth() {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) return null;
  return { sid, token };
}

// Async version: checks env vars first, then DB
async function getTwilioAuthResolved() {
  // Try env first (fast path)
  const envAuth = getTwilioAuth();
  if (envAuth) return envAuth;
  // Try DB
  if (!_pool) return null;
  const sid = await systemSettings.getSettingValue(_pool, "twilio_account_sid");
  const token = await systemSettings.getSettingValue(
    _pool,
    "twilio_auth_token",
  );
  if (!sid || !token) return null;
  return { sid, token };
}

async function getTwilioFromResolved() {
  const envFrom = process.env.TWILIO_WHATSAPP_FROM;
  if (envFrom) return envFrom;
  if (!_pool) return null;
  return await systemSettings.getSettingValue(_pool, "twilio_whatsapp_from");
}

function normalizeWhatsAppTo(to) {
  const trimmed = String(to || "").trim();
  if (!trimmed) return null;
  // Ensure E.164 and add whatsapp: prefix
  const e164 = trimmed.startsWith("+") ? trimmed : `+${trimmed}`;
  return `whatsapp:${e164}`;
}

/**
 * Send a WhatsApp message via the Twilio API.
 * Supports both freeform text and content template messages.
 * @param {object} options
 * @param {string} options.to - Recipient phone number (E.164)
 * @param {string} [options.body] - Text message body (max 4000 chars)
 * @param {string} [options.idempotencyKey] - Optional idempotency key for dedup
 * @param {string} [options.contentSid] - Twilio content template SID
 * @param {object} [options.contentVariables] - Template variable values
 * @returns {Promise<{success: boolean, messageSid?: string, error?: string, code?: string}>}
 */
async function sendWhatsApp({
  to,
  body,
  idempotencyKey,
  contentSid = null,
  contentVariables = null,
}) {
  // In tests, short-circuit success for determinism
  if (process.env.NODE_ENV === "test") {
    return { success: true };
  }
  // Dry-run mode: log but don't send
  if (process.env.WHATSAPP_DRY_RUN === "true") {
    try {
      logger.info(
        JSON.stringify({
          level: "INFO",
          message: "whatsapp-dry-run",
          to: maskPhone(to),
          body: String(body || "").slice(0, 100),
          idempotencyKey,
        }),
      );
    } catch (_) {
      logger.debug("Non-critical operation failed", { error: _?.message });
    }
    return { success: true, messageSid: "DRY_RUN_SID" };
  }
  try {
    const auth = await getTwilioAuthResolved();
    const from = await getTwilioFromResolved();
    if (!auth || !from) {
      return {
        success: false,
        error:
          "WhatsApp provider not configured. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_WHATSAPP_FROM.",
        code: "WHATSAPP_NOT_CONFIGURED",
      };
    }
    const toAddr = normalizeWhatsAppTo(to);
    if (!toAddr) {
      return {
        success: false,
        error: "INVALID_RECIPIENT",
        code: "INVALID_RECIPIENT",
      };
    }
    const url = `https://api.twilio.com/2010-04-01/Accounts/${auth.sid}/Messages.json`;
    const params = new URLSearchParams();
    params.append("To", toAddr);
    if (contentSid) {
      params.append("ContentSid", contentSid);
      if (contentVariables && typeof contentVariables === "object") {
        try {
          params.append("ContentVariables", JSON.stringify(contentVariables));
        } catch (_) {
          logger.debug("Non-critical operation failed", { error: _?.message });
        }
      }
    } else {
      const text = String(body || "").trim();
      if (!text) {
        return {
          success: false,
          error: "A text message body or ContentSid must be provided",
          code: "BODY_REQUIRED",
        };
      }
      params.append("Body", text.slice(0, 4000));
    }
    params.append("From", `whatsapp:${from}`);

    const res = await axios.post(url, params, {
      auth: { username: auth.sid, password: auth.token },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        ...(idempotencyKey
          ? { "Idempotency-Key": String(idempotencyKey) }
          : {}),
      },
      timeout: 30000,
      validateStatus: () => true,
    });
    const status = res.status;
    const data = res.data || {};
    const messageSid = data?.sid || null;
    // Twilio returns 201 on success
    if (status >= 200 && status < 300 && messageSid) {
      try {
        logger.info(
          JSON.stringify({
            level: "INFO",
            message: "whatsapp-send-succeeded",
            to: maskPhone(toAddr),
            messageSid,
            provider: "twilio",
          }),
        );
      } catch (_) {
        logger.debug("Non-critical operation failed", { error: _?.message });
      }
      return { success: true, messageSid };
    }
    const errorCode = data?.code || data?.error_code || null;
    const errorMsg = data?.message || data?.error_message || `HTTP_${status}`;
    try {
      logger.error(
        JSON.stringify({
          level: "ERROR",
          message: "whatsapp-send-failed",
          to: maskPhone(toAddr),
          provider: "twilio",
          errorCode,
          error: errorMsg,
          status,
          response: data,
        }),
      );
    } catch (_) {
      logger.debug("Non-critical operation failed", { error: _?.message });
    }
    return {
      success: false,
      error: errorMsg,
      code: errorCode ? String(errorCode) : `HTTP_${status}`,
      providerError: data,
    };
  } catch (e) {
    const raw = String(e?.message || "").trim();
    return { success: false, error: raw || "SEND_ERROR", code: "SEND_ERROR" };
  }
}

module.exports = { sendWhatsApp, maskPhone, setPool };
