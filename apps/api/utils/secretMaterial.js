"use strict";

/**
 * CertOps shared secret-material detector.
 *
 * Zero private-key custody is a structural rule for every TokenTimer control
 * plane (see CONTEXT.md and docs/adr/0001-certops-zero-custody-enforcement.md).
 * This module is the single source of truth for *content-based* detection of
 * private key material. The existing logger (apps/api/utils/logger.js) already
 * redacts by field name; this detector closes the gap where key material
 * appears under an innocent field name, inside arrays, in raw command output,
 * in evidence payloads, or base64-wrapped.
 *
 * Two distinct outcomes, by design:
 *   - private key material  -> REJECT (hard 422 at the API boundary)
 *   - other generic secrets -> REDACT (so legitimate operational output is kept)
 *
 * Scope note (Phase 0): PEM private-key blocks (all common variants) and
 * base64-wrapped PEM are detected here. Binary PKCS#12/PFX (.p12/.pfx) DER
 * sniffing is deliberately deferred to M1 hardening; it cannot be reliably
 * distinguished from a DER certificate cheaply, and M1 adds dedicated fixtures.
 * Do not weaken these patterns without updating tests/unit/secretMaterial.test.js.
 */

const PRIVATE_KEY_REDACTION_PLACEHOLDER = "[PRIVATE_KEY_REDACTED]";
const GENERIC_SECRET_REDACTION_PLACEHOLDER = "[REDACTED]";

// Matches PEM private-key opening lines for PKCS#8 (BEGIN PRIVATE KEY),
// PKCS#1 (BEGIN RSA PRIVATE KEY), SEC1 (BEGIN EC PRIVATE KEY), DSA, OpenSSH,
// and encrypted variants (BEGIN ENCRYPTED PRIVATE KEY / BEGIN RSA ENCRYPTED ...).
// It must NOT match PUBLIC KEY, CERTIFICATE, or CERTIFICATE REQUEST blocks.
const PRIVATE_KEY_PEM_PATTERN = /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/;

// Whole private-key PEM block (header to footer), used for redaction.
const PRIVATE_KEY_PEM_BLOCK_PATTERN =
  /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g;

// Conservative Authorization-header / bearer-token redaction for generic
// secret scrubbing (extended in M2 evidence redaction work).
const AUTHORIZATION_VALUE_PATTERN =
  /\b(Authorization\s*[:=]\s*)(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]+/gi;

const MAX_SCAN_DEPTH = 12;

/**
 * Returns true if the string looks like base64 (and is long enough to plausibly
 * wrap a PEM block). Whitespace is tolerated.
 * @param {string} value
 * @returns {boolean}
 */
function looksBase64(value) {
  if (typeof value !== "string") return false;
  const compact = value.replace(/\s+/g, "");
  if (compact.length < 64) return false;
  return /^[A-Za-z0-9+/]+={0,2}$/.test(compact);
}

/**
 * Detects private key material in a single string, including base64-wrapped PEM.
 * @param {string} value
 * @returns {boolean}
 */
function stringContainsPrivateKey(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (PRIVATE_KEY_PEM_PATTERN.test(value)) return true;

  if (looksBase64(value)) {
    try {
      const decoded = Buffer.from(value.replace(/\s+/g, ""), "base64").toString(
        "utf8",
      );
      if (PRIVATE_KEY_PEM_PATTERN.test(decoded)) return true;
    } catch (_err) {
      // not valid base64 text; ignore
    }
  }
  return false;
}

/**
 * Deep-scans any value (string, array, or object) for private key material.
 * @param {*} value
 * @returns {boolean} true if private key material is detected anywhere
 */
function containsPrivateKeyMaterial(value, depth = 0) {
  if (value === null || value === undefined) return false;
  if (depth > MAX_SCAN_DEPTH) return false;

  if (typeof value === "string") return stringContainsPrivateKey(value);

  if (Buffer.isBuffer(value)) {
    return stringContainsPrivateKey(value.toString("utf8"));
  }

  if (Array.isArray(value)) {
    return value.some((item) => containsPrivateKeyMaterial(item, depth + 1));
  }

  if (typeof value === "object") {
    return Object.values(value).some((item) =>
      containsPrivateKeyMaterial(item, depth + 1),
    );
  }

  return false;
}

/**
 * Replaces any private key PEM blocks found in a string with a redaction
 * placeholder. Returns the input unchanged when it is not a string.
 * @param {*} value
 * @returns {*}
 */
function redactPrivateKeyMaterial(value) {
  if (typeof value !== "string") return value;
  if (PRIVATE_KEY_PEM_PATTERN.test(value)) {
    return value.replace(
      PRIVATE_KEY_PEM_BLOCK_PATTERN,
      PRIVATE_KEY_REDACTION_PLACEHOLDER,
    );
  }
  // Detection sees through base64-wrapped PEM, so redaction must too. The
  // decoded key spans the entire blob, so the whole value is replaced.
  if (looksBase64(value)) {
    try {
      const decoded = Buffer.from(value.replace(/\s+/g, ""), "base64").toString(
        "utf8",
      );
      if (PRIVATE_KEY_PEM_PATTERN.test(decoded)) {
        return PRIVATE_KEY_REDACTION_PLACEHOLDER;
      }
    } catch (_err) {
      // not valid base64 text; ignore
    }
  }
  return value;
}

/**
 * Generic secret redactor for evidence and log contexts (CertOps detector
 * "second mode", plan 3.3 layer 6). Redacts private-key PEM blocks and
 * Authorization/bearer header values. Deep-walks objects and arrays, returning
 * a redacted copy without mutating the input.
 *
 * Phase 0 baseline; the secret pattern set expands in M2 evidence redaction.
 * @param {*} value
 * @returns {*} redacted copy
 */
function redactGenericSecrets(value, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  // Bail with a marker (never the original subtree) so a hostile or accidental
  // deep nesting cannot defeat redaction by sitting below the scan floor.
  if (depth > MAX_SCAN_DEPTH) return "[REDACTED:max-depth]";

  if (typeof value === "string") {
    return redactPrivateKeyMaterial(value).replace(
      AUTHORIZATION_VALUE_PATTERN,
      (_match, prefix, scheme) =>
        `${prefix}${scheme} ${GENERIC_SECRET_REDACTION_PLACEHOLDER}`,
    );
  }

  if (Buffer.isBuffer(value)) {
    return stringContainsPrivateKey(value.toString("utf8"))
      ? PRIVATE_KEY_REDACTION_PLACEHOLDER
      : value;
  }

  if (typeof value === "object") {
    // Path-based cycle guard: a cyclic reference returns a marker, never the
    // original (which could leak unredacted children of an evidence object).
    if (seen.has(value)) return "[REDACTED:circular]";
    seen.add(value);
    let result;
    if (Array.isArray(value)) {
      result = value.map((item) => redactGenericSecrets(item, depth + 1, seen));
    } else {
      result = {};
      for (const [key, item] of Object.entries(value)) {
        result[key] = redactGenericSecrets(item, depth + 1, seen);
      }
    }
    seen.delete(value);
    return result;
  }

  return value;
}

module.exports = {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
  PRIVATE_KEY_PEM_PATTERN,
  containsPrivateKeyMaterial,
  redactPrivateKeyMaterial,
  redactGenericSecrets,
};
