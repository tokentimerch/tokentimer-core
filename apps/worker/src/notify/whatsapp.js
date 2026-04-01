import axios from "axios";
import crypto from "node:crypto";
import { logger } from "../logger.js";
import { pool } from "../db.js";

const KDF_SALT = "tokentimer-settings-encryption";
let dbTwilioCache = null;
let dbTwilioCacheTime = 0;
const DB_TWILIO_CACHE_TTL = 30000;
let httpPostOverride = null;

export function setWhatsAppHttpPostOverride(fn) {
  httpPostOverride = typeof fn === "function" ? fn : null;
}

function decryptWithKey(ciphertext, key) {
  const parts = String(ciphertext || "").split(":");
  if (parts.length !== 3) return null;
  const iv = Buffer.from(parts[0], "hex");
  const tag = Buffer.from(parts[1], "hex");
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

function decryptSetting(ciphertext) {
  if (!ciphertext) return null;
  const secret = process.env.SESSION_SECRET || "";
  try {
    return decryptWithKey(ciphertext, crypto.scryptSync(secret, KDF_SALT, 32));
  } catch (_) {
    try {
      return decryptWithKey(
        ciphertext,
        crypto.createHash("sha256").update(secret).digest(),
      );
    } catch (_e) {
      return null;
    }
  }
}

async function getDbTwilioConfig() {
  const now = Date.now();
  if (dbTwilioCache && now - dbTwilioCacheTime < DB_TWILIO_CACHE_TTL) {
    return dbTwilioCache;
  }
  try {
    const { rows } = await pool.query(
      "SELECT twilio_account_sid, twilio_auth_token_encrypted, twilio_whatsapp_from FROM system_settings WHERE id = 1",
    );
    const row = rows[0] || null;
    if (!row) {
      dbTwilioCache = null;
      dbTwilioCacheTime = now;
      return null;
    }
    const cfg = {
      sid: row.twilio_account_sid || null,
      token: decryptSetting(row.twilio_auth_token_encrypted),
      from: row.twilio_whatsapp_from || null,
    };
    dbTwilioCache = cfg;
    dbTwilioCacheTime = now;
    return cfg;
  } catch (_) {
    return null;
  }
}

function getTwilioAuth() {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const token = process.env.TWILIO_AUTH_TOKEN;
  if (!sid || !token) return null;
  return { sid, token };
}

function normalizeWhatsAppTo(to) {
  const trimmed = String(to || "").trim();
  if (!trimmed) return null;
  // Ensure E.164 and add whatsapp: prefix
  const e164 = trimmed.startsWith("+") ? trimmed : `+${trimmed}`;
  return `whatsapp:${e164}`;
}

function maskPhone(e164) {
  try {
    const s = String(e164 || "").replace(/[^\d+]/g, "");
    const tail = s.slice(-4);
    return s.length > 4 ? `***${tail}` : `***`;
  } catch (_) {
    return "***";
  }
}

export async function sendWhatsApp({
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
    } catch (_err) {
      logger.warn("WhatsApp operation failed", { error: _err.message });
    }
    return { success: true, messageSid: "DRY_RUN_SID" };
  }
  try {
    const dbTwilio = await getDbTwilioConfig();
    const envAuth = getTwilioAuth();
    const envFrom = process.env.TWILIO_WHATSAPP_FROM || null;
    const auth =
      envAuth ||
      (dbTwilio?.sid && dbTwilio?.token
        ? { sid: dbTwilio.sid, token: dbTwilio.token }
        : null);
    const from = envFrom || dbTwilio?.from || null;
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
    const sendWith = async (authCfg, fromCfg) => {
      const url = `https://api.twilio.com/2010-04-01/Accounts/${authCfg.sid}/Messages.json`;
      const params = new URLSearchParams();
      params.append("To", toAddr);
      if (contentSid) {
        params.append("ContentSid", contentSid);
        if (contentVariables && typeof contentVariables === "object") {
          try {
            params.append("ContentVariables", JSON.stringify(contentVariables));
          } catch (_err) {
            logger.warn("Network call failed", { error: _err.message });
          }
        }
      } else {
        const text = String(body || "").trim();
        if (!text) {
          return {
            ok: false,
            result: {
              success: false,
              error: "A text message body or ContentSid must be provided",
              code: "BODY_REQUIRED",
            },
          };
        }
        params.append("Body", text.slice(0, 4000));
      }
      params.append("From", `whatsapp:${fromCfg}`);

      const postFn = httpPostOverride || axios.post;
      const res = await postFn(url, params, {
        auth: { username: authCfg.sid, password: authCfg.token },
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
      if (status >= 200 && status < 300 && messageSid) {
        return {
          ok: true,
          result: { success: true, messageSid },
          status,
          data,
          errorCode: null,
          errorMsg: null,
        };
      }
      const errorCode = data?.code || data?.error_code || null;
      const errorMsg = data?.message || data?.error_message || `HTTP_${status}`;
      try {
        logger.debug("whatsapp-send-attempt-failed", {
          status,
          errorCode,
          errorMsg,
        });
      } catch (_err) {
        logger.debug("Non-critical operation failed", { error: _err.message });
      }
      return {
        ok: false,
        status,
        data,
        errorCode,
        errorMsg,
        result: {
          success: false,
          error: errorMsg,
          code: errorCode ? String(errorCode) : `HTTP_${status}`,
          providerError: data,
        },
      };
    };

    let attempted = await sendWith(auth, from);
    const canRetryWithDbCreds =
      !attempted.ok &&
      !!envAuth &&
      !!dbTwilio?.sid &&
      !!dbTwilio?.token &&
      !!dbTwilio?.from &&
      (dbTwilio.sid !== envAuth.sid || dbTwilio.token !== envAuth.token);
    if (canRetryWithDbCreds) {
      const errorCode = String(attempted.errorCode || "").trim();
      const errLower = String(attempted.errorMsg || "").toLowerCase();
      const authFailure =
        attempted.status === 401 ||
        attempted.status === 403 ||
        ["20003", "20001", "20006"].includes(errorCode) ||
        /auth|credential|unauthorized|forbidden|permission/.test(errLower);
      if (authFailure) {
        attempted = await sendWith(
          { sid: dbTwilio.sid, token: dbTwilio.token },
          dbTwilio.from,
        );
      }
    }

    if (attempted.ok) {
      try {
        logger.info(
          JSON.stringify({
            level: "INFO",
            message: "whatsapp-send-succeeded",
            to: maskPhone(toAddr),
            messageSid: attempted.result.messageSid,
            provider: "twilio",
          }),
        );
      } catch (_err) {
        logger.warn("WhatsApp operation failed", { error: _err.message });
      }
      return attempted.result;
    }

    try {
      logger.error(
        JSON.stringify({
          level: "ERROR",
          message: "whatsapp-send-failed",
          to: maskPhone(toAddr),
          provider: "twilio",
          errorCode: attempted.errorCode,
          error: attempted.errorMsg,
          status: attempted.status,
          response: attempted.data,
        }),
      );
    } catch (_err) {
      logger.warn("WhatsApp operation failed", { error: _err.message });
    }
    return attempted.result;
  } catch (e) {
    const raw = String(e?.message || "").trim();
    return { success: false, error: raw || "SEND_ERROR", code: "SEND_ERROR" };
  }
}
