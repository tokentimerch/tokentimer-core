const winston = require("winston");
const client = require("prom-client");
const { getRuntimeLabels } = require("../config/runtime-labels");
const {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  containsPrivateKeyMaterial,
  redactPrivateKeyMaterial,
  redactGenericSecrets,
} = require("./secretMaterial");

const SERVICE_NAME = getRuntimeLabels().service;

const LOG_FIELD_ORDER = ["level", "message", "service", "timestamp"];
const MAX_REDACT_DEPTH = 8;

const isDev =
  process.env.NODE_ENV === "development" || process.env.NODE_ENV === "test";

/**
 * Normalize client IP from Express req (never log the req object as ip).
 * @param {import("express").Request | string | null | undefined} reqOrIp
 * @returns {string|null}
 */
function resolveClientIp(reqOrIp) {
  if (reqOrIp == null) return null;
  if (typeof reqOrIp === "string") {
    const trimmed = reqOrIp.split(",")[0].trim();
    return trimmed || null;
  }
  const raw =
    reqOrIp.ip ||
    reqOrIp.headers?.["x-forwarded-for"] ||
    reqOrIp.socket?.remoteAddress ||
    reqOrIp.connection?.remoteAddress;
  if (raw == null) return null;
  return String(raw).split(",")[0].trim() || null;
}

// Field-level redaction: any meta key matching one of these names (or
// containing one of these fragments, case/word-separator insensitive) is
// replaced with "[REDACTED]" before the record is serialized.
const REDACT_FIELDS = [
  "password",
  "token",
  "secret",
  "apiKey",
  "api_key",
  "accessKey",
  "access_key",
  "accessKeyId",
  "access_key_id",
  "secretAccessKey",
  "secret_access_key",
  "sessionToken",
  "session_token",
  "authorization",
  "cookie",
  "credentials",
  "privateKey",
  "private_key",
  "client_secret",
  "clientSecret",
];

const REDACT_KEY_PATTERN =
  /password|secret|api[-_]?key|access[-_]?key|authorization|cookie|credential|private[-_]?key|token/i;

function isSensitiveKey(key) {
  return REDACT_KEY_PATTERN.test(String(key));
}

/**
 * Content-based scrub for free-form log strings: private-key material first,
 * then generic secrets. Field-name redaction remains the outer defense layer.
 * @param {string} value
 * @returns {string}
 */
function scrubLogString(value) {
  if (typeof value !== "string") return value;
  if (value.length === 0) return value;

  let scrubbed = redactPrivateKeyMaterial(value);
  // Header-only / non-block matches can survive replace; fail closed.
  if (containsPrivateKeyMaterial(scrubbed)) {
    return PRIVATE_KEY_REDACTION_PLACEHOLDER;
  }
  return redactGenericSecrets(scrubbed);
}

function scrubLogBuffer(value) {
  if (!Buffer.isBuffer(value)) return value;
  if (containsPrivateKeyMaterial(value)) {
    return PRIVATE_KEY_REDACTION_PLACEHOLDER;
  }
  return value;
}

function redactSensitiveFields(value, depth = 0) {
  if (value === null || value === undefined || depth > MAX_REDACT_DEPTH) {
    return value;
  }
  if (typeof value === "string") return scrubLogString(value);
  if (Buffer.isBuffer(value)) return scrubLogBuffer(value);
  if (Array.isArray(value)) {
    return value.map((v) => redactSensitiveFields(v, depth + 1));
  }
  if (typeof value === "object" && !(value instanceof Error)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (isSensitiveKey(k)) {
        out[k] = "[REDACTED]";
      } else {
        out[k] = redactSensitiveFields(v, depth + 1);
      }
    }
    return out;
  }
  return value;
}

function sanitizeLogValue(value) {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === "string") return scrubLogString(value);
  if (t === "number" || t === "boolean") return value;
  if (Buffer.isBuffer(value)) return scrubLogBuffer(value);
  if (value instanceof Error) {
    return {
      message: scrubLogString(String(value.message || "")),
      stack:
        value.stack == null ? value.stack : scrubLogString(String(value.stack)),
      name: value.name,
      code: value.code,
    };
  }
  if (t === "object") {
    if (typeof value.ip === "string" || value.headers || value.socket) {
      return resolveClientIp(value);
    }
    try {
      JSON.stringify(value);
      return redactSensitiveFields(value);
    } catch (_e) {
      return "[Circular or Non-Serializable]";
    }
  }
  return value;
}

function sanitizeLogRecord(record) {
  const out = {};
  for (const [key, value] of Object.entries(record)) {
    if (key === "ip") {
      out[key] = resolveClientIp(value) ?? sanitizeLogValue(value);
      continue;
    }
    if (isSensitiveKey(key) && key !== "message") {
      out[key] = "[REDACTED]";
      continue;
    }
    out[key] = sanitizeLogValue(value);
  }
  return out;
}

function buildOrderedLogRecord(info) {
  const cleaned = sanitizeLogRecord(info);
  const ordered = {};
  for (const key of LOG_FIELD_ORDER) {
    if (cleaned[key] !== undefined) ordered[key] = cleaned[key];
  }
  const skip = new Set([...LOG_FIELD_ORDER, "splat"]);
  const restKeys = Object.keys(cleaned)
    .filter((k) => !skip.has(k))
    .sort();
  for (const key of restKeys) {
    ordered[key] = cleaned[key];
  }
  return ordered;
}

const safeJsonFormat = winston.format((info) => {
  const merged = sanitizeLogRecord(info);
  for (const key of Object.keys(info)) {
    delete info[key];
  }
  Object.assign(info, merged);
  return info;
});

const orderedJsonLineFormat = winston.format.printf((info) =>
  JSON.stringify(buildOrderedLogRecord(info)),
);

const logger = winston.createLogger({
  level: isDev ? "debug" : "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    safeJsonFormat(),
  ),
  defaultMeta: { service: SERVICE_NAME },
  transports: [],
});

if (isDev) {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
      ),
    }),
  );
} else {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        safeJsonFormat(),
        orderedJsonLineFormat,
      ),
    }),
  );
}

let cLogError;
try {
  cLogError = new client.Counter({
    name: "app_log_errors_total",
    help: "Count of error-level log events by service",
    labelNames: ["service"],
  });
} catch (_) {
  /* duplicate registration in dev/hot reload */
}

const origError = logger.error.bind(logger);
logger.error = (...args) => {
  try {
    if (cLogError) cLogError.labels(SERVICE_NAME).inc();
  } catch (_) {}
  return origError(...args);
};

module.exports = {
  logger,
  resolveClientIp,
  buildOrderedLogRecord,
  redactSensitiveFields,
  scrubLogString,
  REDACT_FIELDS,
  LOG_FIELD_ORDER,
};
