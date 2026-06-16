const crypto = require("crypto");
const { logger } = require("../utils/logger");

/**
 * Hash a phone number for privacy-safe storage (opt-in evidence).
 * @param {string} phone - E.164 formatted phone number
 * @returns {string|null} SHA-256 hex hash, or null on error
 */
function hashPhone(phone) {
  try {
    const salt = process.env.PHONE_HASH_SALT || "";
    const val = String(phone || "").trim();
    const h = crypto
      .createHash("sha256")
      .update(salt + val)
      .digest("hex");
    return h;
  } catch (_) {
    return null;
  }
}

/**
 * Mask a phone number for logging, showing only the last 4 digits.
 * @param {string} e164 - E.164 formatted phone number
 * @returns {string} Masked phone number
 */
function maskPhone(e164) {
  try {
    const s = String(e164 || "").replace(/[^\d+]/g, "");
    const tail = s.slice(-4);
    return s.length > 4 ? `***${tail}` : `***`;
  } catch (_) {
    logger.debug("maskPhone failed", { error: _?.message });
    return "***";
  }
}

/**
 * Sanitize objects for logging by redacting sensitive fields.
 * @param {*} value - Value to sanitize
 * @returns {*} Sanitized value
 */
function sanitizeForLogging(value) {
  const sensitiveKeys = new Set([
    "password",
    "confirmPassword",
    "newPassword",
    "token",
    "verificationToken",
    "resetToken",
    "authorization",
    "auth",
    "accessToken",
    "refreshToken",
    "session",
  ]);
  const redact = (v) => {
    if (v === null || v === undefined) return v;
    if (typeof v !== "object")
      return typeof v === "string" && v.length > 0 ? "REDACTED" : v;
    if (Array.isArray(v)) return v.map(redact);
    const out = {};
    for (const [k, val] of Object.entries(v)) {
      if (sensitiveKeys.has(k)) {
        out[k] = "REDACTED";
      } else if (typeof val === "object" && val !== null) {
        out[k] = redact(val);
      } else {
        out[k] = val;
      }
    }
    return out;
  };
  return redact(value);
}

/**
 * Escape a value for safe interpolation into HTML.
 * @param {*} value
 * @returns {string}
 */
function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Strip ASCII control characters (incl. CR/LF) from a single-line value,
 * e.g. email subject parts, to prevent header/format injection.
 * @param {*} value
 * @param {number} maxLength
 * @returns {string}
 */
function sanitizeSingleLine(value, maxLength = 200) {
  // eslint-disable-next-line no-control-regex
  return String(value ?? "").replace(/[\x00-\x1f\x7f]+/g, " ").trim().slice(0, maxLength);
}

module.exports = {
  hashPhone,
  maskPhone,
  sanitizeForLogging,
  escapeHtml,
  sanitizeSingleLine,
};
