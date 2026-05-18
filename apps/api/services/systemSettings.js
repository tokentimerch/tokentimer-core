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

// JSON-column registry.
//
// Plugins register extra JSONB columns on `system_settings` at startup via
// `registerJsonColumn`. Core ships with the registry empty so OSS
// deployments do not expose any JSONB extras out of the box.
//
// Each registered entry maps a DB column name to:
//   - envMap:       { jsonKey: ENV_VAR_NAME }  same env > DB > default precedence as ENV_MAP
//   - secretFields: string[]                    keys encrypted at rest under `${key}_encrypted`
//   - responseKey:  string                       key under which the column surfaces in
//                                                /api/admin/system-settings responses
const JSON_ENV_MAP = {};
const JSON_SECRET_FIELDS = {};
const JSON_RESPONSE_KEYS = {};
// Optional per-column entitlement gate. When provided, the alerts.js route
// only surfaces the column to admins whose request passes the gate.
// The signature is intentionally narrow: `(req) => Promise<boolean>`, so
// plugins can plug in their own license/entitlement check without core
// having to know about it.
const JSON_FEATURE_GATES = {};

/**
 * Register a JSONB column on `system_settings`. Idempotent: re-registering
 * an existing column merges into the existing maps.
 *
 * @param {string} columnName  the DB column name on `system_settings`
 * @param {object} options
 * @param {object} options.envMap         { jsonKey: ENV_VAR_NAME }
 * @param {string[]} [options.secretFields] keys stored encrypted at rest
 * @param {string} [options.responseKey]  alias used in API responses (defaults to columnName)
 * @param {(req: object) => boolean | Promise<boolean>} [options.featureGate]
 *   Optional async predicate. When provided and it resolves to a falsy
 *   value, the column is hidden on GET and refused on PUT. Plugins use
 *   this to enforce their own entitlement boundaries.
 */
function registerJsonColumn(columnName, options = {}) {
  if (!columnName || typeof columnName !== "string") {
    throw new Error("registerJsonColumn: columnName must be a non-empty string");
  }
  const envMap = options.envMap || {};
  const secretFields = Array.isArray(options.secretFields)
    ? options.secretFields
    : [];
  const responseKey =
    typeof options.responseKey === "string" && options.responseKey.length > 0
      ? options.responseKey
      : columnName;

  JSON_ENV_MAP[columnName] = { ...(JSON_ENV_MAP[columnName] || {}), ...envMap };
  const existingSecrets = JSON_SECRET_FIELDS[columnName] || [];
  JSON_SECRET_FIELDS[columnName] = Array.from(
    new Set([...existingSecrets, ...secretFields]),
  );
  JSON_RESPONSE_KEYS[columnName] = responseKey;
  if (typeof options.featureGate === "function") {
    JSON_FEATURE_GATES[columnName] = options.featureGate;
  }
}

/**
 * List all registered JSON columns. Used by route handlers (e.g. alerts.js)
 * to build the system-settings response without hardcoding column names.
 *
 * @returns {{ column: string, responseKey: string, featureGate: (Function|null) }[]}
 */
function listRegisteredJsonColumns() {
  return Object.keys(JSON_ENV_MAP).map((column) => ({
    column,
    responseKey: JSON_RESPONSE_KEYS[column] || column,
    featureGate: JSON_FEATURE_GATES[column] || null,
  }));
}

function isJsonColumn(name) {
  return Object.prototype.hasOwnProperty.call(JSON_ENV_MAP, name);
}

function jsonSecretStorageKey(key) {
  return `${key}_encrypted`;
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

// Track whether we've already warned about the table being unavailable so
// that repeated misses during boot (or in tests that don't seed the schema)
// don't flood the logs.
let _missingTableWarned = false;

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
    // Table may not exist yet (pre-migration). Postgres returns code 42P01
    // for `relation does not exist`. Warn once, then drop to debug-level
    // for subsequent calls so boot logs aren't drowned.
    if (e?.code === "42P01") {
      if (!_missingTableWarned) {
        logger.warn(
          "system_settings table not available yet; will retry once migrations have run.",
          { error: e.message },
        );
        _missingTableWarned = true;
      } else {
        logger.debug?.("system_settings still unavailable", {
          error: e.message,
        });
      }
    } else {
      logger.warn("system_settings query failed", { error: e.message });
    }
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

// --- JSON-column helpers ---

function parseEnvBoolean(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "true") return true;
  if (trimmed === "false") return false;
  return value;
}

/**
 * Resolve a single key inside a JSONB column with env > DB > default precedence.
 * Returns the same `{ value, source, locked }` envelope used by getSetting().
 * Secret keys are stored under the `${key}_encrypted` suffix inside the
 * JSON and decrypted on read.
 */
async function getJsonSetting(pool, column, key) {
  if (!isJsonColumn(column)) {
    return { value: null, source: null, locked: false };
  }
  const envMap = JSON_ENV_MAP[column] || {};
  const envName = envMap[key];

  if (envName) {
    const envVal = process.env[envName];
    if (envVal && envVal.trim()) {
      return {
        value: parseEnvBoolean(envVal.trim()),
        source: "env",
        locked: true,
      };
    }
  }

  const row = await getDbRow(pool);
  if (row && row[column] && typeof row[column] === "object") {
    const obj = row[column];
    const isSecret = (JSON_SECRET_FIELDS[column] || []).includes(key);
    if (isSecret) {
      const cipher = obj[jsonSecretStorageKey(key)];
      if (cipher) {
        const plain = decrypt(cipher);
        if (plain) return { value: plain, source: "database", locked: false };
      }
      return { value: null, source: null, locked: false };
    }
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      const raw = obj[key];
      if (raw === null || raw === undefined || raw === "") {
        return { value: null, source: null, locked: false };
      }
      return { value: raw, source: "database", locked: false };
    }
  }

  return { value: null, source: null, locked: false };
}

/**
 * Resolve all keys of a JSONB column. Secrets are masked.
 * Returns `{ key: { value, source, locked } }`.
 */
async function getJsonColumn(pool, column) {
  if (!isJsonColumn(column)) return {};
  const result = {};
  const envMap = JSON_ENV_MAP[column] || {};
  const secrets = JSON_SECRET_FIELDS[column] || [];

  const row = await getDbRow(pool);
  const dbObj =
    row && row[column] && typeof row[column] === "object" ? row[column] : {};

  const dbKeys = Object.keys(dbObj)
    .map((k) => (k.endsWith("_encrypted") ? k.slice(0, -"_encrypted".length) : k));
  const allKeys = Array.from(
    new Set([...Object.keys(envMap), ...dbKeys]),
  );

  for (const key of allKeys) {
    const setting = await getJsonSetting(pool, column, key);
    if (secrets.includes(key)) {
      result[key] = {
        value: maskSecret(setting.value),
        source: setting.source,
        locked: setting.locked,
      };
    } else {
      result[key] = setting;
    }
  }

  return result;
}

/**
 * Resolve raw effective value for a JSON-column key (no metadata).
 * Used by services that just need the configured value.
 */
async function getJsonSettingValue(pool, column, key) {
  const result = await getJsonSetting(pool, column, key);
  return result.value;
}

/**
 * Save (merge) keys into a JSONB column. Performs a read-modify-write so
 * that callers can save just the SAML card without wiping OIDC extras.
 * Skips keys that are locked by env var. Encrypts JSON-secret keys.
 */
async function saveJsonColumn(pool, column, payload, userId, options = {}) {
  // Unregistered columns are a programmer error: a route was wired against
  // a JSON column that nobody registered. We surface this loudly because
  // silently dropping the payload makes the system-settings page appear
  // to save successfully while throwing the data on the floor.
  if (!isJsonColumn(column)) {
    throw Object.assign(
      new Error(
        `saveJsonColumn: column '${column}' is not registered. ` +
          `Call systemSettings.registerJsonColumn('${column}', ...) first.`,
      ),
      { code: "JSON_COLUMN_NOT_REGISTERED" },
    );
  }
  if (!payload || typeof payload !== "object") return;
  const envMap = JSON_ENV_MAP[column] || {};
  const secrets = JSON_SECRET_FIELDS[column] || [];

  const row = await getDbRow(pool);
  const current =
    row && row[column] && typeof row[column] === "object"
      ? { ...row[column] }
      : {};

  // Detect unknown keys before mutating. By default we log + drop them
  // (preserving v0.1 behaviour for any drift), but callers can pass
  // { strictKeys: true } to make this a hard error - the route handler
  // wires this on for the admin UI so typos in the JSON payload are
  // caught loudly instead of vanishing.
  const unknownKeys = Object.keys(payload).filter(
    (k) => !Object.prototype.hasOwnProperty.call(envMap, k),
  );
  if (unknownKeys.length > 0) {
    if (options.strictKeys) {
      throw Object.assign(
        new Error(
          `saveJsonColumn: unknown key(s) for '${column}': ${unknownKeys.join(
            ", ",
          )}. Allowed keys: ${Object.keys(envMap).join(", ") || "<none>"}.`,
        ),
        { code: "JSON_COLUMN_UNKNOWN_KEYS", column, unknownKeys },
      );
    }
    logger?.warn?.("saveJsonColumn ignoring unknown keys", {
      column,
      unknownKeys,
    });
  }

  let touched = false;
  for (const [key, rawValue] of Object.entries(payload)) {
    if (!Object.prototype.hasOwnProperty.call(envMap, key)) continue;
    const envName = envMap[key];
    const envVal = process.env[envName];
    if (envVal && envVal.trim()) {
      continue;
    }

    if (secrets.includes(key)) {
      const storageKey = jsonSecretStorageKey(key);
      if (rawValue === undefined) continue;
      if (rawValue === null || rawValue === "") {
        delete current[storageKey];
      } else {
        current[storageKey] = encrypt(String(rawValue));
      }
      delete current[key];
      touched = true;
      continue;
    }

    if (rawValue === null || rawValue === undefined || rawValue === "") {
      if (Object.prototype.hasOwnProperty.call(current, key)) {
        delete current[key];
        touched = true;
      }
      continue;
    }

    current[key] = rawValue;
    touched = true;
  }

  if (!touched) return;

  const params = [JSON.stringify(current)];
  let setClause = `${column} = $1::jsonb, updated_at = NOW()`;
  if (userId) {
    params.push(userId);
    setClause += `, updated_by = $${params.length}`;
  }

  await pool.query(
    `UPDATE system_settings SET ${setClause} WHERE id = 1`,
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
  JSON_ENV_MAP,
  JSON_SECRET_FIELDS,
  registerJsonColumn,
  listRegisteredJsonColumns,
  getSetting,
  getSettingValue,
  getAllSettings,
  saveSettings,
  getJsonSetting,
  getJsonSettingValue,
  getJsonColumn,
  saveJsonColumn,
  isWhatsAppAvailable,
  isSmtpConfigured,
  invalidateCache,
  encrypt,
  decrypt,
  maskSecret,
};
