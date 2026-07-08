"use strict";

/**
 * CertOps shared secret-material detector.
 *
 * Zero private-key custody is a structural rule for every TokenTimer control
 * plane (see docs/certops/CONTEXT.md and docs/adr/0001-certops-zero-custody-enforcement.md).
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
 * Scope note: PEM private-key blocks (all common variants), base64-wrapped PEM,
 * and PKCS#12/PFX-like DER bundles are detected here. PKCS#12/PFX detection is
 * intentionally a conservative structural sniff for the PFX version field, not
 * a full ASN.1 parser. Do not weaken these patterns without updating
 * tests/unit/secretMaterial.test.js.
 */

const PRIVATE_KEY_REDACTION_PLACEHOLDER = "[PRIVATE_KEY_REDACTED]";
const GENERIC_SECRET_REDACTION_PLACEHOLDER = "[REDACTED]";

// Matches PEM private-key opening lines for PKCS#8 (BEGIN PRIVATE KEY),
// PKCS#1 (BEGIN RSA PRIVATE KEY), SEC1 (BEGIN EC PRIVATE KEY), DSA, OpenSSH,
// and encrypted variants (BEGIN ENCRYPTED PRIVATE KEY / BEGIN RSA ENCRYPTED ...).
// It must NOT match PUBLIC KEY, CERTIFICATE, or CERTIFICATE REQUEST blocks.
const PRIVATE_KEY_PEM_LABEL_PATTERN = String.raw`(?:[A-Z0-9]+\s+)*PRIVATE\s+KEY`;
const PRIVATE_KEY_PEM_PATTERN = new RegExp(
  String.raw`-----\s*BEGIN\s+${PRIVATE_KEY_PEM_LABEL_PATTERN}\s*-----`,
  "i",
);

// Whole private-key PEM block (header to footer), used for redaction.
const PRIVATE_KEY_PEM_BLOCK_PATTERN = new RegExp(
  String.raw`-----\s*BEGIN\s+${PRIVATE_KEY_PEM_LABEL_PATTERN}\s*-----[\s\S]*?-----\s*END\s+${PRIVATE_KEY_PEM_LABEL_PATTERN}\s*-----`,
  "gi",
);

// Conservative Authorization-header / bearer-token redaction for generic
// secret scrubbing (extended in M2 evidence redaction work).
const AUTHORIZATION_VALUE_PATTERN =
  /\b(Authorization\s*[:=]\s*)(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]+/gi;
const GENERIC_SECRET_ASSIGNMENT_PATTERN =
  /\b(?:password|passwd|credential|secret|api[_-]?key|api[_-]?secret|token[_-]?secret|access[_-]?token|refresh[_-]?token|client[_-]?secret)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi;

const PRIVATE_KEY_FIELD_FRAGMENTS = Object.freeze([
  "privatekey",
  "privatekeypem",
  "encryptedprivatekey",
  "keymaterial",
  "pfxblob",
  "jksblob",
  "tlskey",
  "caprivatekey",
  "rawprivatekey",
  "rawkey",
  "pemprivatekey",
  "privatepem",
  "keypem",
  "pfx",
  "jks",
  "keystore",
]);

const GENERIC_SECRET_FIELD_FRAGMENTS = Object.freeze([
  "password",
  "passwd",
  "credential",
  "secret",
  "tokensecret",
  "apisecret",
  "apikey",
  "authorization",
  "accesstoken",
  "refreshtoken",
  "clientsecret",
]);

const MAX_SCAN_DEPTH = 12;

function normalizeFieldName(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

function fieldNameLooksPrivateKeyMaterial(fieldName) {
  const normalized = normalizeFieldName(fieldName);
  return PRIVATE_KEY_FIELD_FRAGMENTS.some((fragment) =>
    normalized.includes(fragment),
  );
}

function fieldNameLooksGenericSecret(fieldName) {
  const normalized = normalizeFieldName(fieldName);
  return GENERIC_SECRET_FIELD_FRAGMENTS.some((fragment) =>
    normalized.includes(fragment),
  );
}

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
 * Returns the length of a DER TLV header, or null for unsupported encodings.
 * This intentionally supports only definite lengths used by DER.
 * @param {Buffer} value
 * @returns {number|null}
 */
function derHeaderLength(value) {
  if (!Buffer.isBuffer(value) || value.length < 2) return null;
  const lengthByte = value[1];
  if ((lengthByte & 0x80) === 0) return 2;

  const lengthBytes = lengthByte & 0x7f;
  if (lengthBytes === 0 || lengthBytes > 4) return null;
  if (value.length < 2 + lengthBytes) return null;
  return 2 + lengthBytes;
}

/**
 * Detects a PKCS#12/PFX-like DER envelope. PFX begins with an outer SEQUENCE
 * followed by INTEGER 3. X.509 certificates begin with an outer SEQUENCE
 * followed by another SEQUENCE, so this avoids flagging DER certificates.
 * @param {Buffer} value
 * @returns {boolean}
 */
function looksPkcs12Bundle(value) {
  if (!Buffer.isBuffer(value) || value.length < 7) return false;
  if (value[0] !== 0x30) return false;

  const headerLength = derHeaderLength(value);
  if (headerLength === null || value.length < headerLength + 3) return false;

  return (
    value[headerLength] === 0x02 &&
    value[headerLength + 1] === 0x01 &&
    value[headerLength + 2] === 0x03
  );
}

/**
 * Detects the common ASN.1 envelopes used by DER private keys without
 * attempting to parse arbitrary ASN.1. PKCS#8, PKCS#1 RSA, and SEC1 EC keys
 * start with SEQUENCE then INTEGER version 0/1. X.509 certificates start with
 * SEQUENCE then another SEQUENCE, so this deliberately does not flag them.
 * @param {Buffer} value
 * @returns {boolean}
 */
function looksPrivateKeyDer(value) {
  if (!Buffer.isBuffer(value) || value.length < 8 || value[0] !== 0x30) {
    return false;
  }

  const headerLength = derHeaderLength(value);
  if (headerLength === null || value.length < headerLength + 4) return false;
  if (value[headerLength] !== 0x02 || value[headerLength + 1] !== 0x01) {
    return false;
  }

  const version = value[headerLength + 2];
  if (version !== 0x00 && version !== 0x01) return false;

  const nextTag = value[headerLength + 3];
  // PKCS#8 has AlgorithmIdentifier (SEQUENCE), PKCS#1 RSA has a modulus
  // INTEGER, and SEC1 EC has an OCTET STRING after version 1.
  return (
    nextTag === 0x30 ||
    nextTag === 0x02 ||
    (version === 0x01 && nextTag === 0x04)
  );
}

function base64DecodeIfLikely(value) {
  if (!looksBase64(value)) return null;
  try {
    return Buffer.from(value.replace(/\s+/g, ""), "base64");
  } catch (_err) {
    return null;
  }
}

function hexDecodeIfLikely(value) {
  if (typeof value !== "string") return null;
  const compact = value.replace(/\s+/g, "");
  if (compact.length < 64 || compact.length % 2 !== 0) return null;
  if (!/^[a-f0-9]+$/i.test(compact)) return null;
  try {
    return Buffer.from(compact, "hex");
  } catch (_err) {
    return null;
  }
}

function bufferContainsPrivateKey(value) {
  if (!Buffer.isBuffer(value)) return false;
  if (looksPkcs12Bundle(value) || looksPrivateKeyDer(value)) return true;
  return PRIVATE_KEY_PEM_PATTERN.test(value.toString("utf8"));
}

/**
 * Detects private key material in a single string, including base64-wrapped PEM.
 * @param {string} value
 * @returns {boolean}
 */
function stringContainsPrivateKey(value) {
  if (typeof value !== "string" || value.length === 0) return false;
  if (PRIVATE_KEY_PEM_PATTERN.test(value)) return true;

  const hexDecoded = hexDecodeIfLikely(value);
  if (hexDecoded && bufferContainsPrivateKey(hexDecoded)) return true;

  const decoded = base64DecodeIfLikely(value);
  if (decoded) {
    if (bufferContainsPrivateKey(decoded)) return true;
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
  if (depth > MAX_SCAN_DEPTH) return true;

  if (typeof value === "string") return stringContainsPrivateKey(value);

  if (Buffer.isBuffer(value)) {
    return bufferContainsPrivateKey(value);
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
  const decoded = base64DecodeIfLikely(value);
  if (decoded && bufferContainsPrivateKey(decoded)) {
    return PRIVATE_KEY_REDACTION_PLACEHOLDER;
  }
  const hexDecoded = hexDecodeIfLikely(value);
  if (hexDecoded && bufferContainsPrivateKey(hexDecoded)) {
    return PRIVATE_KEY_REDACTION_PLACEHOLDER;
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
function createRedactionReport() {
  return {
    redactionApplied: false,
    redactionCount: 0,
    redactedFields: new Set(),
  };
}

function noteRedaction(report, category = "generic") {
  report.redactionApplied = true;
  report.redactionCount += 1;
  report.redactedFields.add(category);
}

function finalizeRedactionReport(report, value) {
  return {
    value,
    redactionApplied: report.redactionApplied,
    redactionCount: report.redactionCount,
    redactedFields: Array.from(report.redactedFields).sort(),
  };
}

function redactGenericString(value, report) {
  let result = redactPrivateKeyMaterial(value);
  if (result !== value) noteRedaction(report, "private-key");

  result = result.replace(AUTHORIZATION_VALUE_PATTERN, () => {
    noteRedaction(report, "authorization");
    return GENERIC_SECRET_REDACTION_PLACEHOLDER;
  });

  result = result.replace(GENERIC_SECRET_ASSIGNMENT_PATTERN, () => {
    noteRedaction(report, "generic-secret");
    return GENERIC_SECRET_REDACTION_PLACEHOLDER;
  });

  return result;
}

function redactGenericSecretsInternal(value, report, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return value;
  // Bail with a marker (never the original subtree) so a hostile or accidental
  // deep nesting cannot defeat redaction by sitting below the scan floor.
  if (depth > MAX_SCAN_DEPTH) {
    noteRedaction(report, "max-depth");
    return "[REDACTED:max-depth]";
  }

  if (typeof value === "string") {
    return redactGenericString(value, report);
  }

  if (Buffer.isBuffer(value)) {
    if (bufferContainsPrivateKey(value)) {
      noteRedaction(report, "private-key");
      return PRIVATE_KEY_REDACTION_PLACEHOLDER;
    }
    return value;
  }

  if (typeof value === "object") {
    // Path-based cycle guard: a cyclic reference returns a marker, never the
    // original (which could leak unredacted children of an evidence object).
    if (seen.has(value)) {
      noteRedaction(report, "circular");
      return "[REDACTED:circular]";
    }
    seen.add(value);
    let result;
    if (Array.isArray(value)) {
      result = value.map((item) =>
        redactGenericSecretsInternal(item, report, depth + 1, seen),
      );
    } else {
      result = {};
      for (const [key, item] of Object.entries(value)) {
        if (fieldNameLooksGenericSecret(key)) {
          const category = normalizeFieldName(key).includes("authorization")
            ? "authorization"
            : "generic-secret";
          noteRedaction(report, category);
          result[key] = GENERIC_SECRET_REDACTION_PLACEHOLDER;
          continue;
        }
        result[key] = redactGenericSecretsInternal(
          item,
          report,
          depth + 1,
          seen,
        );
      }
    }
    seen.delete(value);
    return result;
  }

  return value;
}

function redactGenericSecretsWithReport(value) {
  const report = createRedactionReport();
  return finalizeRedactionReport(
    report,
    redactGenericSecretsInternal(value, report),
  );
}

function redactGenericSecrets(value) {
  return redactGenericSecretsWithReport(value).value;
}

module.exports = {
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
  PRIVATE_KEY_PEM_PATTERN,
  containsPrivateKeyMaterial,
  looksPrivateKeyDer,
  fieldNameLooksGenericSecret,
  fieldNameLooksPrivateKeyMaterial,
  looksPkcs12Bundle,
  redactPrivateKeyMaterial,
  redactGenericSecrets,
  redactGenericSecretsWithReport,
};
