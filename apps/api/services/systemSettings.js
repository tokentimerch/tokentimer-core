const crypto = require("crypto");
const { logger } = require("../utils/logger");

// Mapping: DB column -> environment variable name
const ENV_MAP = {
  smtp_host: "SMTP_HOST",
  smtp_port: "SMTP_PORT",
  smtp_user: "SMTP_USER",
  smtp_pass: "SMTP_PASS",
  smtp_from_email: "FROM_EMAIL",
  smtp_from_name: "FROM_EMAIL_NAME",
  smtp_secure: "SMTP_SECURE",
  smtp_require_tls: "SMTP_REQUIRE_TLS",
  twilio_account_sid: "TWILIO_ACCOUNT_SID",
  twilio_auth_token: "TWILIO_AUTH_TOKEN",
  twilio_whatsapp_from: "TWILIO_WHATSAPP_FROM",
  twilio_whatsapp_test_content_sid: "TWILIO_WHATSAPP_TEST_CONTENT_SID",
  twilio_whatsapp_alert_content_sid_expires:
    "TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRES",
  twilio_whatsapp_alert_content_sid_expired:
    "TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRED",
  twilio_whatsapp_alert_content_sid_endpoint_down:
    "TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN",
  twilio_whatsapp_alert_content_sid_endpoint_recovered:
    "TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED",
  twilio_whatsapp_weekly_digest_content_sid:
    "TWILIO_WHATSAPP_WEEKLY_DIGEST_CONTENT_SID",
};

// Fields that are secrets (encrypted in DB, masked on read)
const SECRET_FIELDS = ["smtp_pass", "twilio_auth_token"];

// DB column names for encrypted fields (suffixed with _encrypted)
function dbColumn(key) {
  return SECRET_FIELDS.includes(key) ? `${key}_encrypted` : key;
}

// --- Encryption helpers using AES-256-GCM ---

const KDF_SALT = "tokentimer-settings-encryption";

function getEncryptionKey() {
  const secret = process.env.SESSION_SECRET || "";
  return crypto.scryptSync(secret, KDF_SALT, 32);
}

// Legacy key derivation for backwards compatibility with pre-v0.1 encrypted values
function getLegacyEncryptionKey() {
  const secret = process.env.SESSION_SECRET || "";
  return crypto.createHash("sha256").update(secret).digest();
}

function encrypt(plaintext) {
  if (!plaintext) return null;
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(plaintext, "utf8", "hex");
  encrypted += cipher.final("hex");
  const tag = cipher.getAuthTag().toString("hex");
  return `${iv.toString("hex")}:${tag}:${encrypted}`;
}

function decryptWithKey(ciphertext, key) {
  const parts = ciphertext.split(":");
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

function decrypt(ciphertext) {
  if (!ciphertext) return null;
  // Try current KDF first, then fall back to legacy SHA-256 KDF
  try {
    return decryptWithKey(ciphertext, getEncryptionKey());
  } catch (_) {
    try {
      return decryptWithKey(ciphertext, getLegacyEncryptionKey());
    } catch (e) {
      logger.error("Failed to decrypt system setting:", e.message);
      return null;
    }
  }
}

// Mask a secret value for display: show last 4 chars
function maskSecret(value) {
  if (!value) return null;
  const s = String(value);
  if (s.length <= 4) return "****";
  return "****" + s.slice(-4);
}

// --- Core resolver ---

// Cache DB row for 30 seconds to avoid hitting DB on every request
let _cache = null;
let _cacheTime = 0;
const CACHE_TTL = 30000;

async function getDbRow(pool) {
  const now = Date.now();
  if (_cache && now - _cacheTime < CACHE_TTL) return _cache;
  try {
    const { rows } = await pool.query(
      "SELECT * FROM system_settings WHERE id = 1",
    );
    _cache = rows[0] || null;
    _cacheTime = now;
    return _cache;
  } catch (e) {
    // Table may not exist yet (pre-migration)
    logger.warn("system_settings table not available:", e.message);
    return null;
  }
}

function invalidateCache() {
  _cache = null;
  _cacheTime = 0;
}

/**
 * Get the effective value for a setting key.
 * Priority: env var > database > null
 * @returns {{ value: string|null, source: 'env'|'database'|null, locked: boolean }}
 */
async function getSetting(pool, key) {
  const envName = ENV_MAP[key];
  if (!envName) return { value: null, source: null, locked: false };

  // Check env var first
  const envVal = process.env[envName];
  if (envVal && envVal.trim()) {
    return { value: envVal.trim(), source: "env", locked: true };
  }

  // Check database
  const row = await getDbRow(pool);
  if (row) {
    const col = dbColumn(key);
    const raw = row[col];
    if (raw && String(raw).trim()) {
      const value = SECRET_FIELDS.includes(key)
        ? decrypt(raw)
        : String(raw).trim();
      if (value) return { value, source: "database", locked: false };
    }
  }

  return { value: null, source: null, locked: false };
}

/**
 * Get the raw effective value (no metadata). For use by services.
 */
async function getSettingValue(pool, key) {
  const result = await getSetting(pool, key);
  return result.value;
}

/**
 * Get all settings with metadata for the admin UI.
 * Secrets are masked.
 */
async function getAllSettings(pool) {
  const result = {};
  for (const key of Object.keys(ENV_MAP)) {
    const setting = await getSetting(pool, key);
    result[key] = {
      value: SECRET_FIELDS.includes(key)
        ? maskSecret(setting.value)
        : setting.value,
      source: setting.source,
      locked: setting.locked,
    };
  }
  return result;
}

/**
 * Save settings to the database.
 * Skips env-locked fields. Encrypts secrets.
 */
async function saveSettings(pool, settings, userId) {
  const fields = [];
  const params = [];
  let p = 1;

  for (const [key, value] of Object.entries(settings)) {
    if (!ENV_MAP[key]) continue; // unknown key

    // Check if locked by env var
    const envName = ENV_MAP[key];
    const envVal = process.env[envName];
    if (envVal && envVal.trim()) {
      continue; // skip env-locked fields
    }

    const col = dbColumn(key);
    if (SECRET_FIELDS.includes(key)) {
      // Encrypt secrets
      const encrypted = value ? encrypt(String(value).trim()) : null;
      fields.push(`${col} = $${p++}`);
      params.push(encrypted);
    } else {
      fields.push(`${col} = $${p++}`);
      if (value === undefined || value === null || value === "") {
        params.push(null);
      } else {
        params.push(String(value).trim());
      }
    }
  }

  if (fields.length === 0) return;

  fields.push(`updated_at = NOW()`);
  if (userId) {
    fields.push(`updated_by = $${p++}`);
    params.push(userId);
  }

  await pool.query(
    `UPDATE system_settings SET ${fields.join(", ")} WHERE id = 1`,
    params,
  );

  invalidateCache();
}

/**
 * Check if WhatsApp (Twilio) is available from env or DB.
 */
async function isWhatsAppAvailable(pool) {
  const sid = await getSettingValue(pool, "twilio_account_sid");
  const token = await getSettingValue(pool, "twilio_auth_token");
  const from = await getSettingValue(pool, "twilio_whatsapp_from");
  return !!(sid && token && from);
}

/**
 * Check if SMTP is configured from env or DB.
 */
async function isSmtpConfigured(pool) {
  const host = await getSettingValue(pool, "smtp_host");
  const user = await getSettingValue(pool, "smtp_user");
  const pass = await getSettingValue(pool, "smtp_pass");
  return !!(host && user && pass);
}

module.exports = {
  ENV_MAP,
  SECRET_FIELDS,
  getSetting,
  getSettingValue,
  getAllSettings,
  saveSettings,
  isWhatsAppAvailable,
  isSmtpConfigured,
  invalidateCache,
  encrypt,
  decrypt,
  maskSecret,
};
