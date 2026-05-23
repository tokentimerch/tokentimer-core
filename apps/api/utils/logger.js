const winston = require("winston");
const client = require("prom-client");
const { getRuntimeLabels } = require("../config/runtime-labels");

const SERVICE_NAME = getRuntimeLabels().service;

const LOG_FIELD_ORDER = ["level", "message", "service", "timestamp"];

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

function sanitizeLogValue(value) {
  if (value === null || value === undefined) return value;
  const t = typeof value;
  if (t === "string" || t === "number" || t === "boolean") return value;
  if (value instanceof Error) {
    return {
      message: value.message,
      stack: value.stack,
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
      return value;
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
  LOG_FIELD_ORDER,
};
