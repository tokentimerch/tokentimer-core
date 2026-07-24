"use strict";

// The detector and logging scrubber live in the shared package so worker and
// controller code never depend on the API application's filesystem layout.
const {
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  containsPrivateKeyMaterial,
  redactGenericSecrets,
  redactPrivateKeyMaterial,
} = require("./secret-material");

const MAX_SCRUB_DEPTH = 8;
const REDACT_KEY_PATTERN =
  /password|secret|api[-_]?key|access[-_]?key|authorization|cookie|credential|private[-_]?key|token/i;

function isSensitiveKey(key) {
  return REDACT_KEY_PATTERN.test(String(key));
}

function scrubLogString(value) {
  if (typeof value !== "string" || value.length === 0) return value;

  try {
    const privateKeyScrubbed = redactPrivateKeyMaterial(value);
    if (containsPrivateKeyMaterial(privateKeyScrubbed)) {
      return PRIVATE_KEY_REDACTION_PLACEHOLDER;
    }
    return redactGenericSecrets(privateKeyScrubbed);
  } catch (_error) {
    return GENERIC_SECRET_REDACTION_PLACEHOLDER;
  }
}

function scrubBuffer(value) {
  if (!Buffer.isBuffer(value)) return value;
  if (containsPrivateKeyMaterial(value)) {
    return PRIVATE_KEY_REDACTION_PLACEHOLDER;
  }
  // Binary values cannot be safely interpreted as text without risking a
  // credential leak, so logging them is always fail-closed.
  return GENERIC_SECRET_REDACTION_PLACEHOLDER;
}

function redactSensitiveFields(value, depth = 0, seen = new Set()) {
  if (value === null || value === undefined) return value;
  if (depth >= MAX_SCRUB_DEPTH) {
    return GENERIC_SECRET_REDACTION_PLACEHOLDER;
  }
  if (typeof value === "string") return scrubLogString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return String(value);
  if (Buffer.isBuffer(value)) return scrubBuffer(value);
  if (value instanceof Error) {
    return {
      code: value.code == null ? value.code : scrubLogString(String(value.code)),
      message: scrubLogString(String(value.message || "")),
      name: scrubLogString(String(value.name || "Error")),
      stack:
        value.stack == null ? value.stack : scrubLogString(String(value.stack)),
    };
  }
  if (typeof value !== "object") return GENERIC_SECRET_REDACTION_PLACEHOLDER;
  if (seen.has(value)) return "[REDACTED:circular]";

  seen.add(value);
  let sanitized;
  if (Array.isArray(value)) {
    sanitized = value.map((item) =>
      redactSensitiveFields(item, depth + 1, seen),
    );
  } else {
    sanitized = {};
    for (const [key, item] of Object.entries(value)) {
      sanitized[key] = isSensitiveKey(key)
        ? GENERIC_SECRET_REDACTION_PLACEHOLDER
        : redactSensitiveFields(item, depth + 1, seen);
    }
  }
  seen.delete(value);
  return sanitized;
}

function sanitizeLogValue(value) {
  return redactSensitiveFields(value);
}

function sanitizeLogRecord(record) {
  if (record === null || typeof record !== "object") {
    return sanitizeLogValue(record);
  }

  const sanitized = {};
  for (const [key, value] of Object.entries(record)) {
    sanitized[key] = isSensitiveKey(key) && key !== "message"
      ? GENERIC_SECRET_REDACTION_PLACEHOLDER
      : sanitizeLogValue(value);
  }
  return sanitized;
}

module.exports = {
  MAX_SCRUB_DEPTH,
  containsPrivateKeyMaterial,
  isSensitiveKey,
  redactSensitiveFields,
  sanitizeLogRecord,
  sanitizeLogValue,
  scrubLogString,
};
