"use strict";

/**
 * Agent-local logging boundary.
 *
 * The control plane, transport failures, filesystem paths, and nested errors
 * are all untrusted log inputs. Route every agent error through this module
 * so credentials, generic secrets, and private material never reach stderr.
 */

const {
  containsPrivateKeyMaterial,
  redactGenericSecrets,
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
} = require("../../../log-scrub/secret-material.js");

const AGENT_CREDENTIAL_PATTERN = /\bttagent_[^\s,;"']+/gi;
const BOOTSTRAP_TOKEN_PATTERN = /\b(?:bootstrap|bearer)\s+token\s*[:=]\s*([^\s,;"']+)/gi;
const MAX_LOG_VALUE_LENGTH = 2048;

function bound(value) {
  const stringValue = String(value ?? "");
  return stringValue.length > MAX_LOG_VALUE_LENGTH
    ? `${stringValue.slice(0, MAX_LOG_VALUE_LENGTH)}…[truncated]`
    : stringValue;
}

function scrubString(value) {
  const bounded = bound(value);
  if (containsPrivateKeyMaterial(bounded)) {
    return PRIVATE_KEY_REDACTION_PLACEHOLDER;
  }

  return redactGenericSecrets(bounded)
    .replace(AGENT_CREDENTIAL_PATTERN, "[AGENT_CREDENTIAL_REDACTED]")
    .replace(BOOTSTRAP_TOKEN_PATTERN, "bootstrap token=[REDACTED]");
}

function sanitizeLogValue(value, depth = 0, seen = new WeakSet()) {
  if (depth > 8) return "[REDACTED:max-depth]";
  if (value === null || value === undefined) return value;

  if (typeof value === "string") return scrubString(value);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Buffer.isBuffer(value)) {
    return containsPrivateKeyMaterial(value)
      ? PRIVATE_KEY_REDACTION_PLACEHOLDER
      : `[Buffer ${value.length} bytes]`;
  }

  if (value instanceof Error) {
    const result = {
      name: scrubString(value.name || "Error"),
      message: scrubString(value.message || ""),
    };
    if (value.code !== undefined) result.code = scrubString(value.code);
    if (Number.isInteger(value.status)) result.status = value.status;
    if (value.cause !== undefined) {
      result.cause = sanitizeLogValue(value.cause, depth + 1, seen);
    }
    return result;
  }

  if (typeof value === "object") {
    if (seen.has(value)) return "[REDACTED:circular]";
    seen.add(value);
    const sanitized = Array.isArray(value)
      ? value.map((item) => sanitizeLogValue(item, depth + 1, seen))
      : Object.fromEntries(
        Object.entries(value).map(([key, item]) => [
          scrubString(key),
          sanitizeLogValue(item, depth + 1, seen),
        ]),
      );
    seen.delete(value);
    try {
      return redactGenericSecrets(sanitized);
    } catch (_error) {
      return PRIVATE_KEY_REDACTION_PLACEHOLDER;
    }
  }

  return scrubString(value);
}

function formatAgentLogMessage(message, details) {
  const safeMessage = scrubString(message);
  if (details === undefined) return `tokentimer-agent: ${safeMessage}`;
  return `tokentimer-agent: ${safeMessage} ${JSON.stringify(sanitizeLogValue(details))}`;
}

function createAgentLogger({ sink = (message) => console.error(message) } = {}) {
  if (typeof sink !== "function") {
    throw new TypeError("tokentimer-agent logger sink must be a function");
  }

  return Object.freeze({
    error(message, details) {
      sink(formatAgentLogMessage(message, details));
    },
  });
}

const defaultAgentLogger = createAgentLogger();

module.exports = {
  createAgentLogger,
  defaultAgentLogger,
  sanitizeLogValue,
  formatAgentLogMessage,
};
