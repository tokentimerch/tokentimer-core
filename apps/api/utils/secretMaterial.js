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
 * PKCS#8/PKCS#1/SEC1 DER private keys, PKCS#12/PFX-like DER bundles, and JKS
 * keystores (by magic header) are detected here. PKCS#12/PFX detection is
 * intentionally a conservative structural sniff for the PFX version field, not
 * a full ASN.1 parser; JKS detection is likewise a magic-header sniff rather
 * than a full keystore parser; a JKS container is rejected outright since its
 * entire purpose is to hold private key material. Do not weaken these
 * patterns without updating tests/unit/secretMaterial.test.js.
 */

const PRIVATE_KEY_REDACTION_PLACEHOLDER = "[PRIVATE_KEY_REDACTED]";
const GENERIC_SECRET_REDACTION_PLACEHOLDER = "[REDACTED]";
const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

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
  /\b(Authorization\s*[:=]\s*)(?:Bearer|Basic|Token)\s+("[^"]*"|'[^']*'|[^\s,;]+)/gi;
const COOKIE_HEADER_PATTERN =
  /\b((?:Set-)?Cookie\s*:\s*)([^\r\n]*)/gi;
const API_TOKEN_HEADER_PATTERN =
  /\b((?:X[\s_-]?(?:API[\s_-]?Key|Auth[\s_-]?Token))\s*:\s*)("[^"]*"|'[^']*'|[^\s,;]+)/gi;
const GENERIC_SECRET_ASSIGNMENT_PATTERN =
  /\b((?:password|passwd|credential|secret|api[\s_-]?key|api[\s_-]?secret|token(?:[\s_-]?(?:secret|value))?|bearer[\s_-]?token|access[\s_-]?token|refresh[\s_-]?token|client[\s_-]?secret|aws[\s_-]?secret[\s_-]?access[\s_-]?key)\s*[:=]\s*)("[^"]*"|'[^']*'|[^\s,;]+)/gi;

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

const GENERIC_SECRET_FIELD_NAMES = Object.freeze([
  "token",
  "apitoken",
  "authtoken",
  "authorizationtoken",
  "bearertoken",
  "sessiontoken",
  "secrettoken",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "xauthtoken",
  "xapikey",
  "password",
  "passwd",
  "passphrase",
  "credential",
  "credentials",
  "secret",
  "secretkey",
  "rawsecret",
  "tokensecret",
  "tokenvalue",
  "apisecret",
  "apikey",
  "bearer",
  "authorization",
  "cookie",
  "setcookie",
  "cookieheader",
  "accesskey",
  "accesskeyid",
  "accesstoken",
  "refreshtoken",
  "clientsecret",
  "awssecretaccesskey",
]);

// Suffix matching recognizes conventional names such as deploymentPassword
// without treating unrelated words such as secretary or cookiePolicyEnabled as
// secret-bearing fields. Free-form values are checked separately below.
const GENERIC_SECRET_FIELD_SUFFIXES = Object.freeze([
  // A suffix is intentional for common names such as deploymentToken. It does
  // not match tokenization, tokenCount, tokenExpiry, tokenType, secretary,
  // cookiePolicyEnabled, or passwordResetRequired because none end in a
  // secret-bearing semantic token.
  "token",
  "apitoken",
  "authtoken",
  "authorizationtoken",
  "bearertoken",
  "sessiontoken",
  "secrettoken",
  "idtoken",
  "xauthtoken",
  "xapikey",
  "setcookie",
  "cookieheader",
  "password",
  "passwd",
  "passphrase",
  "credential",
  "credentials",
  "secret",
  "secretkey",
  "rawsecret",
  "tokensecret",
  "tokenvalue",
  "apikey",
  "apisecret",
  "accesstoken",
  "refreshtoken",
  "clientsecret",
  "awssecretaccesskey",
]);

const MAX_SCAN_DEPTH = 12;
// These are inspection limits, not acceptance limits. A complete
// EncryptedPrivateKeyInfo that exceeds either limit is suspicious and is
// rejected rather than treated as public data. The parser never allocates from
// a DER length declaration.
const MAX_DER_TLV_LENGTH = 1024 * 1024;
const MAX_DER_CHILDREN = 16;
const MAX_DER_OID_LENGTH = 128;
const DER_CLASSIFICATION = Object.freeze({
  NOT_MATCH: "not_match",
  MATCH: "match",
  SUSPICIOUS_OR_LIMIT_EXCEEDED: "suspicious_or_limit_exceeded",
});

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
  return (
    GENERIC_SECRET_FIELD_NAMES.includes(normalized) ||
    GENERIC_SECRET_FIELD_SUFFIXES.some((suffix) =>
      normalized.endsWith(suffix),
    )
  );
}

/**
 * Returns true if the string looks like base64 and is long enough to plausibly
 * wrap a bounded DER envelope or PEM block. Whitespace is tolerated.
 * @param {string} value
 * @returns {boolean}
 */
function looksBase64(value) {
  if (typeof value !== "string") return false;
  const compact = value.replace(/\s+/g, "");
  if (compact.length < 16) return false;
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
 * Reads one bounded, definite-length DER TLV without allocating from the
 * declared ASN.1 length. This is deliberately not a general ASN.1 parser.
 * @param {Buffer} value
 * @param {number} offset
 * @param {number} boundary
 * @returns {{tag:number, valueStart:number, valueEnd:number, valueLength:number, exceedsInspectionLimit:boolean}|null}
 */
function readDerTlv(value, offset = 0, boundary = value?.length || 0) {
  if (
    !Buffer.isBuffer(value) ||
    !Number.isInteger(offset) ||
    !Number.isInteger(boundary) ||
    offset < 0 ||
    boundary < offset ||
    boundary > value.length ||
    offset + 2 > boundary
  ) {
    return null;
  }

  const lengthByte = value[offset + 1];
  let valueLength;
  let headerLength = 2;
  if ((lengthByte & 0x80) === 0) {
    valueLength = lengthByte;
  } else {
    const lengthBytes = lengthByte & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 4 || offset + 2 + lengthBytes > boundary) {
      return null;
    }
    // DER lengths are minimally encoded: long form cannot start with zero or
    // describe a value that short form could represent.
    if (value[offset + 2] === 0) return null;
    valueLength = 0;
    for (let index = 0; index < lengthBytes; index += 1) {
      valueLength = valueLength * 256 + value[offset + 2 + index];
    }
    if (valueLength < 128) return null;
    headerLength += lengthBytes;
  }

  const valueStart = offset + headerLength;
  const valueEnd = valueStart + valueLength;
  if (valueEnd > boundary || valueEnd < valueStart) return null;
  return {
    tag: value[offset],
    valueStart,
    valueEnd,
    valueLength,
    exceedsInspectionLimit: valueLength > MAX_DER_TLV_LENGTH,
  };
}

function classifyDerOid(value, oid) {
  if (!oid || oid.valueLength < 1) return DER_CLASSIFICATION.NOT_MATCH;

  // Inspect a bounded prefix only. An OID that is syntactically plausible but
  // longer than this defensive bound remains a private-key suspicion; reading
  // the declared value in full is neither needed nor safe.
  const inspectionEnd = Math.min(
    oid.valueEnd,
    oid.valueStart + MAX_DER_OID_LENGTH,
  );
  let atSubidentifierStart = true;
  for (let index = oid.valueStart; index < inspectionEnd; index += 1) {
    const octet = value[index];
    // Base-128 subidentifiers must be minimally encoded: a continuation byte
    // cannot begin with a zero seven-bit group.
    if (atSubidentifierStart && octet === 0x80) {
      return DER_CLASSIFICATION.NOT_MATCH;
    }
    atSubidentifierStart = (octet & 0x80) === 0;
  }
  if (oid.valueLength > MAX_DER_OID_LENGTH) {
    return DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED;
  }
  return atSubidentifierStart
    ? DER_CLASSIFICATION.MATCH
    : DER_CLASSIFICATION.NOT_MATCH;
}

function classifyAlgorithmIdentifier(value, algorithm) {
  const oid = readDerTlv(value, algorithm.valueStart, algorithm.valueEnd);
  if (!oid || oid.tag !== 0x06) {
    return DER_CLASSIFICATION.NOT_MATCH;
  }

  const oidClassification = classifyDerOid(value, oid);
  if (oidClassification === DER_CLASSIFICATION.NOT_MATCH) {
    return DER_CLASSIFICATION.NOT_MATCH;
  }
  let suspicious =
    algorithm.exceedsInspectionLimit ||
    oid.exceedsInspectionLimit ||
    oidClassification === DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED;

  let cursor = oid.valueEnd;
  let childCount = 0;
  while (cursor < algorithm.valueEnd) {
    // The outer encrypted-key shape has already been established by the
    // caller. Do not walk arbitrarily many parameter TLVs: exceeding the
    // inspection budget is suspicious and therefore fails closed.
    if (childCount >= MAX_DER_CHILDREN) {
      return DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED;
    }
    const child = readDerTlv(value, cursor, algorithm.valueEnd);
    if (!child) return DER_CLASSIFICATION.NOT_MATCH;
    if (child.exceedsInspectionLimit) {
      return DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED;
    }
    cursor = child.valueEnd;
    childCount += 1;
  }
  if (cursor !== algorithm.valueEnd) return DER_CLASSIFICATION.NOT_MATCH;
  return suspicious
    ? DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED
    : DER_CLASSIFICATION.MATCH;
}

/**
 * Detects PKCS#8 EncryptedPrivateKeyInfo DER:
 *   SEQUENCE { AlgorithmIdentifier, OCTET STRING }
 * The algorithm identifier may use any syntactically valid DER OID. Limiting
 * recognition to known PBE OIDs would allow encrypted PKCS#8 containers using
 * newer or vendor encryption algorithms to bypass the zero-custody boundary.
 * @param {Buffer} value
 * @returns {"not_match"|"match"|"suspicious_or_limit_exceeded"}
 */
function classifyEncryptedPkcs8Der(value) {
  const outer = readDerTlv(value, 0, value?.length || 0);
  if (!outer || outer.tag !== 0x30 || outer.valueEnd !== value.length) {
    return DER_CLASSIFICATION.NOT_MATCH;
  }

  const algorithm = readDerTlv(value, outer.valueStart, outer.valueEnd);
  if (!algorithm || algorithm.tag !== 0x30) {
    return DER_CLASSIFICATION.NOT_MATCH;
  }

  const encryptedData = readDerTlv(value, algorithm.valueEnd, outer.valueEnd);
  if (
    !encryptedData ||
    encryptedData.tag !== 0x04 ||
    encryptedData.valueLength === 0 ||
    encryptedData.valueEnd !== outer.valueEnd
  ) {
    return DER_CLASSIFICATION.NOT_MATCH;
  }

  const algorithmClassification = classifyAlgorithmIdentifier(value, algorithm);
  if (algorithmClassification === DER_CLASSIFICATION.NOT_MATCH) {
    return DER_CLASSIFICATION.NOT_MATCH;
  }

  if (
    outer.exceedsInspectionLimit ||
    encryptedData.exceedsInspectionLimit ||
    algorithmClassification === DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED
  ) {
    return DER_CLASSIFICATION.SUSPICIOUS_OR_LIMIT_EXCEEDED;
  }
  return DER_CLASSIFICATION.MATCH;
}

function looksEncryptedPkcs8Der(value) {
  return classifyEncryptedPkcs8Der(value) !== DER_CLASSIFICATION.NOT_MATCH;
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

// Java KeyStore (JKS) magic header: 0xFEEDFEED, followed by a 4-byte format
// version (1 or 2 for every JKS format in use) and a 4-byte non-negative
// entry count. JKS containers are rejected outright rather than parsed for a
// private-key entry tag: a JKS keystore's entire purpose is to hold private
// key material (and/or trusted certs), and the zero-custody boundary treats
// the whole container as key material regardless of whether a given instance
// happens to hold only certificate entries at scan time.
const JKS_MAGIC = 0xfeedfeed;

function looksJksKeystore(value) {
  if (!Buffer.isBuffer(value) || value.length < 12) return false;
  if (value.readUInt32BE(0) !== JKS_MAGIC) return false;
  const version = value.readUInt32BE(4);
  if (version !== 1 && version !== 2) return false;
  const entryCount = value.readInt32BE(8);
  return entryCount >= 0;
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
  if (compact.length < 16 || compact.length % 2 !== 0) return null;
  if (!/^[a-f0-9]+$/i.test(compact)) return null;
  try {
    return Buffer.from(compact, "hex");
  } catch (_err) {
    return null;
  }
}

function bufferContainsPrivateKey(value) {
  if (!Buffer.isBuffer(value)) return false;
  if (
    looksPkcs12Bundle(value) ||
    looksPrivateKeyDer(value) ||
    looksEncryptedPkcs8Der(value) ||
    looksJksKeystore(value)
  ) {
    return true;
  }
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

function privateKeyMaterialRejectedError() {
  const error = new Error(
    "Private key material is not accepted in CertOps requests",
  );
  error.code = PRIVATE_KEY_MATERIAL_REJECTED;
  return error;
}

function assertNoPrivateKeyMaterial(
  value,
  depth = 0,
  seen = new WeakSet(),
) {
  if (depth > MAX_SCAN_DEPTH) throw privateKeyMaterialRejectedError();
  if (value === null || value === undefined) return;

  if (typeof value === "string") {
    if (stringContainsPrivateKey(value)) throw privateKeyMaterialRejectedError();
    return;
  }

  if (Buffer.isBuffer(value)) {
    if (bufferContainsPrivateKey(value)) throw privateKeyMaterialRejectedError();
    return;
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) throw privateKeyMaterialRejectedError();
    seen.add(value);
    for (const item of value) {
      assertNoPrivateKeyMaterial(item, depth + 1, seen);
    }
    seen.delete(value);
    return;
  }

  if (typeof value === "object") {
    if (seen.has(value)) throw privateKeyMaterialRejectedError();
    seen.add(value);
    for (const [key, item] of Object.entries(value)) {
      if (fieldNameLooksPrivateKeyMaterial(key)) {
        throw privateKeyMaterialRejectedError();
      }
      assertNoPrivateKeyMaterial(item, depth + 1, seen);
    }
    seen.delete(value);
  }
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
 * Generic-secret-only redactor for evidence and log contexts. Private-key
 * material is rejected before traversal; this helper must never be used as a
 * fallback that converts prohibited key material into accepted data.
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
  let result = value.replace(AUTHORIZATION_VALUE_PATTERN, (_match, prefix) => {
    noteRedaction(report, "authorization");
    return `${prefix}${GENERIC_SECRET_REDACTION_PLACEHOLDER}`;
  });

  result = result.replace(COOKIE_HEADER_PATTERN, (_match, prefix) => {
    noteRedaction(report, "cookie");
    return `${prefix}${GENERIC_SECRET_REDACTION_PLACEHOLDER}`;
  });

  result = result.replace(API_TOKEN_HEADER_PATTERN, (_match, prefix) => {
    noteRedaction(report, "generic-secret");
    return `${prefix}${GENERIC_SECRET_REDACTION_PLACEHOLDER}`;
  });

  result = result.replace(GENERIC_SECRET_ASSIGNMENT_PATTERN, (_match, prefix) => {
    noteRedaction(report, "generic-secret");
    return `${prefix}${GENERIC_SECRET_REDACTION_PLACEHOLDER}`;
  });

  return result;
}

function normalizePossibleRedactedSecret(value) {
  let normalized = String(value || "").trim();
  if (
    (normalized.startsWith('"') && normalized.endsWith('"')) ||
    (normalized.startsWith("'") && normalized.endsWith("'"))
  ) {
    normalized = normalized.slice(1, -1);
  }
  if (normalized === GENERIC_SECRET_REDACTION_PLACEHOLDER) {
    return normalized;
  }

  // A surrounding log sentence may place ordinary punctuation directly after
  // the placeholder. That punctuation is not secret material. Do not remove
  // the placeholder's own closing bracket.
  if (normalized.startsWith(GENERIC_SECRET_REDACTION_PLACEHOLDER)) {
    const suffix = normalized.slice(
      GENERIC_SECRET_REDACTION_PLACEHOLDER.length,
    );
    if (/^[)\]}>,.!?]+$/.test(suffix)) {
      return GENERIC_SECRET_REDACTION_PLACEHOLDER;
    }
  }
  return normalized;
}

function patternContainsUnredactedSecret(value, pattern) {
  pattern.lastIndex = 0;
  let match;
  while ((match = pattern.exec(value))) {
    if (
      normalizePossibleRedactedSecret(match[2]) !==
      GENERIC_SECRET_REDACTION_PLACEHOLDER
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Returns true only when free-form content still contains an unredacted
 * generic secret. Field-name policies remain separate because they are schema
 * decisions; this helper is the single content detector shared by routes and
 * persistence services.
 * @param {*} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {boolean}
 */
function containsGenericSecretMaterial(value, depth = 0, seen = new WeakSet()) {
  if (value === null || value === undefined) return false;
  if (depth > MAX_SCAN_DEPTH) return true;

  if (typeof value === "string") {
    return [
      AUTHORIZATION_VALUE_PATTERN,
      COOKIE_HEADER_PATTERN,
      API_TOKEN_HEADER_PATTERN,
      GENERIC_SECRET_ASSIGNMENT_PATTERN,
    ].some((pattern) => patternContainsUnredactedSecret(value, pattern));
  }

  if (Buffer.isBuffer(value)) return false;

  if (Array.isArray(value)) {
    if (seen.has(value)) return true;
    seen.add(value);
    const found = value.some((item) =>
      containsGenericSecretMaterial(item, depth + 1, seen),
    );
    seen.delete(value);
    return found;
  }

  if (typeof value === "object") {
    if (seen.has(value)) return true;
    seen.add(value);
    const found = Object.values(value).some((item) =>
      containsGenericSecretMaterial(item, depth + 1, seen),
    );
    seen.delete(value);
    return found;
  }

  return false;
}

function assertNoUnredactedGenericSecretMaterial(value) {
  if (containsGenericSecretMaterial(value)) {
    const error = new Error(
      "Generic secret material is not accepted in CertOps public metadata",
    );
    error.code = PRIVATE_KEY_MATERIAL_REJECTED;
    throw error;
  }
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
          const normalizedKey = normalizeFieldName(key);
          const category = normalizedKey.includes("authorization")
            ? "authorization"
            : normalizedKey.includes("cookie")
              ? "cookie"
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
  assertNoPrivateKeyMaterial(value);
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
  PRIVATE_KEY_MATERIAL_REJECTED,
  PRIVATE_KEY_REDACTION_PLACEHOLDER,
  GENERIC_SECRET_REDACTION_PLACEHOLDER,
  PRIVATE_KEY_PEM_PATTERN,
  containsPrivateKeyMaterial,
  assertNoPrivateKeyMaterial,
  assertNoUnredactedGenericSecretMaterial,
  containsGenericSecretMaterial,
  DER_CLASSIFICATION,
  MAX_DER_OID_LENGTH,
  MAX_DER_TLV_LENGTH,
  looksPrivateKeyDer,
  classifyEncryptedPkcs8Der,
  looksEncryptedPkcs8Der,
  looksJksKeystore,
  fieldNameLooksGenericSecret,
  fieldNameLooksPrivateKeyMaterial,
  looksPkcs12Bundle,
  redactPrivateKeyMaterial,
  redactGenericSecrets,
  redactGenericSecretsWithReport,
};
