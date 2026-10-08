/*
 * VENDORED COPY for self-contained agent distribution.
 * Source of truth: packages/log-scrub/agent-log-text.js (@tokentimer/log-scrub).
 * Refresh with: node packages/agent/scripts/sync-vendor.js
 * Do not edit detection logic here; change the upstream file and re-sync.
 */
"use strict";

/**
 * Scrubber for curated agent execution-console lines.
 * Private key material is a hard reject. Other secrets are redacted, then
 * hidden direction and line-separator characters are stripped.
 */

const {
  containsPrivateKeyMaterial,
  redactGenericSecrets,
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
} = require("./secret-material");

const REDACTED = "[REDACTED]";
const MAX_MESSAGE_BYTES = 1024;
const MAX_FIELD_VALUE_BYTES = 256;
const MAX_FIELDS = 8;
const MAX_FIELDS_BYTES = 1024;

const QUERY_SECRET = /([?&](?:token|key|sig|signature|X-Amz-[A-Za-z0-9-]+)=)[^&\s#]+/gi;
const AUTH_HEADER = /(authorization\s*[:=]\s*(?:bearer\s+)?)(\S+)/gi;
const CONN = /([a-z][a-z0-9+.-]*:\/\/)([^:\s/@]+):([^@\s/]+)@/gi;
const ASSIGNED_SECRET = /((?:pfx|pkcs12|eab)[-_\s]*hmac|eab[-_\s]*key|dns[-_\s]*(?:token|secret|key)|api[-_\s]*key|(?:pfx|pkcs12)[-_\s]*password)\s*[:=]\s*\S+/gi;
const HINT = /password|secret|token|credential|hmac|api[_-]?key/i;
const HIGH_ENTROPY = /\b(?:[A-Za-z0-9+/]{32,}={0,2}|[a-fA-F0-9]{32,})\b/g;
const BIDI_AND_SEPARATORS = /[\u202A-\u202E\u2066-\u2069\u2028\u2029]/g;
const CONTROLS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;
const FIELD_KEY = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;

function utf8Length(value) {
  return Buffer.byteLength(String(value), "utf8");
}

function scrubAgentLogText(value) {
  const original = String(value ?? "");
  if (containsPrivateKeyMaterial(original)) {
    return {
      rejected: true,
      text: PRIVATE_KEY_REDACTION_PLACEHOLDER,
      redactions: 1,
    };
  }

  let text = redactGenericSecrets(original);
  let redactions = text === original ? 0 : 1;
  const next = text
    .replace(QUERY_SECRET, `$1${REDACTED}`)
    .replace(AUTH_HEADER, `$1${REDACTED}`)
    .replace(CONN, `$1$2:${REDACTED}@`)
    .replace(ASSIGNED_SECRET, (match) => {
      const split = match.split(/[:=]/);
      return `${split[0]}=${REDACTED}`;
    });
  if (next !== text) redactions += 1;
  text = next;
  if (HINT.test(text)) {
    const stripped = text.replace(HIGH_ENTROPY, REDACTED);
    if (stripped !== text) redactions += 1;
    text = stripped;
  }
  text = text.replace(/\r\n/g, "\n").replace(BIDI_AND_SEPARATORS, "").replace(CONTROLS, "");
  if (utf8Length(text) > MAX_MESSAGE_BYTES) {
    const buf = Buffer.from(text, "utf8").subarray(0, MAX_MESSAGE_BYTES);
    text = buf.toString("utf8").replace(/\uFFFD$/, "");
    redactions += 1;
  }
  return { rejected: false, text, redactions };
}

function scrubAgentLogFields(fields, reservedNames = new Set()) {
  if (fields == null) return { rejected: false, fields: null, redactions: 0 };
  if (typeof fields !== "object" || Array.isArray(fields)) {
    return { rejected: false, fields: null, redactions: 1 };
  }
  const out = {};
  let redactions = 0;
  for (const [key, value] of Object.entries(fields)) {
    if (Object.keys(out).length >= MAX_FIELDS) {
      redactions += 1;
      break;
    }
    const normalized = String(key).toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!FIELD_KEY.test(key) || reservedNames.has(normalized)) {
      redactions += 1;
      continue;
    }
    if (value !== null && !["string", "number", "boolean"].includes(typeof value)) {
      redactions += 1;
      continue;
    }
    if (typeof value === "string") {
      const scrubbed = scrubAgentLogText(value);
      if (scrubbed.rejected) return { rejected: true, fields: null, redactions: scrubbed.redactions };
      let text = scrubbed.text;
      redactions += scrubbed.redactions;
      if (utf8Length(text) > MAX_FIELD_VALUE_BYTES) {
        text = Buffer.from(text, "utf8").subarray(0, MAX_FIELD_VALUE_BYTES).toString("utf8").replace(/\uFFFD$/, "");
        redactions += 1;
      }
      out[key] = text;
    } else {
      out[key] = value;
    }
  }
  if (utf8Length(JSON.stringify(out)) > MAX_FIELDS_BYTES) {
    return { rejected: false, fields: null, redactions: redactions + 1 };
  }
  return { rejected: false, fields: Object.keys(out).length ? out : null, redactions };
}

module.exports = {
  REDACTED,
  MAX_MESSAGE_BYTES,
  MAX_FIELD_VALUE_BYTES,
  MAX_FIELDS,
  MAX_FIELDS_BYTES,
  scrubAgentLogText,
  scrubAgentLogFields,
};
