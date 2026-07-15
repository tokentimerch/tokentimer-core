"use strict";

/**
 * Unicode / homograph-safe certificate identity validation for CN and DNS SANs.
 *
 * Modelled on certctl ValidateUnicodeSafe: reject rather than normalize, so an
 * imported or displayed certificate identity cannot carry a spoofed name.
 *
 * Threats covered:
 * - Bidirectional override / isolate controls (display-order reversal)
 * - Zero-width / invisible formatting characters (hidden content)
 * - C0 / C1 control characters
 * - Mixed-script DNS labels (ASCII Latin mixed with Cyrillic / Greek / etc.)
 *
 * Punycode policy (ACE labels):
 * - Labels that begin with "xn--" (case-insensitive) must be well-formed LDH
 *   ACE: xn-- followed by one or more [a-z0-9-], ASCII only.
 * - Well-formed ACE labels are accepted (they are the wire form of IDNs).
 * - Malformed xn-- labels are rejected.
 * - Pure non-ASCII U-labels remain allowed; the attack we refuse is the MIX
 *   of ASCII and non-ASCII script characters in one label.
 *
 * IP identities are not DNS labels: use assertSafeIpIdentity / validate by
 * SAN type so mixed-script DNS rules are not applied to addresses.
 */

const CERTOPS_UNSAFE_IDENTITY = "CERTOPS_UNSAFE_IDENTITY";

const BIDI_OVERRIDE_OR_ISOLATE = new Set([
  0x202a, // LEFT-TO-RIGHT EMBEDDING
  0x202b, // RIGHT-TO-LEFT EMBEDDING
  0x202c, // POP DIRECTIONAL FORMATTING
  0x202d, // LEFT-TO-RIGHT OVERRIDE
  0x202e, // RIGHT-TO-LEFT OVERRIDE
  0x2066, // LEFT-TO-RIGHT ISOLATE
  0x2067, // RIGHT-TO-LEFT ISOLATE
  0x2068, // FIRST STRONG ISOLATE
  0x2069, // POP DIRECTIONAL ISOLATE
]);

const ZERO_WIDTH_OR_INVISIBLE = new Set([
  0x200b, // ZERO WIDTH SPACE
  0x200c, // ZERO WIDTH NON-JOINER
  0x200d, // ZERO WIDTH JOINER
  0x2060, // WORD JOINER
  0xfeff, // ZERO WIDTH NO-BREAK SPACE / BOM
]);

const ACE_LABEL_PATTERN = /^xn--[a-z0-9-]+$/i;

class CertOpsIdentitySafetyError extends Error {
  constructor(message, code = CERTOPS_UNSAFE_IDENTITY) {
    super(message);
    this.name = "CertOpsIdentitySafetyError";
    this.code = code;
  }
}

function createIdentityError(message) {
  return new CertOpsIdentitySafetyError(message, CERTOPS_UNSAFE_IDENTITY);
}

function isControlCodePoint(codePoint) {
  return codePoint < 0x20 || (codePoint >= 0x7f && codePoint <= 0x9f);
}

function isAsciiCodePoint(codePoint) {
  return codePoint < 0x80;
}

function isScriptBearingCodePoint(codePoint) {
  const char = String.fromCodePoint(codePoint);
  return /\p{L}|\p{Nd}|\p{M}/u.test(char);
}

function formatCodePoint(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * Reject bidi overrides/isolates, zero-width/invisible, and control characters.
 * Does not apply DNS mixed-script rules (safe for IP / URI / email bodies).
 */
function findForbiddenIdentityCharacter(value) {
  if (typeof value !== "string" || value.length === 0) return null;

  let offset = 0;
  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (BIDI_OVERRIDE_OR_ISOLATE.has(codePoint)) {
      return {
        kind: "bidi",
        codePoint,
        offset,
        message:
          `contains bidirectional override/isolate character ${formatCodePoint(codePoint)} ` +
          `at offset ${offset}: refuse (potential reverse-rendering attack)`,
      };
    }
    if (ZERO_WIDTH_OR_INVISIBLE.has(codePoint)) {
      return {
        kind: "zero-width",
        codePoint,
        offset,
        message:
          `contains zero-width/invisible character ${formatCodePoint(codePoint)} ` +
          `at offset ${offset}: refuse (hidden content)`,
      };
    }
    if (isControlCodePoint(codePoint)) {
      return {
        kind: "control",
        codePoint,
        offset,
        message:
          `contains control character ${formatCodePoint(codePoint)} ` +
          `at offset ${offset}: refuse`,
      };
    }
    offset += char.length;
  }

  return null;
}

function isWellFormedAceLabel(label) {
  return ACE_LABEL_PATTERN.test(label);
}

/**
 * Per-label script / ACE policy for DNS identities.
 * Pure non-ASCII labels are allowed; ASCII mixed with non-ASCII script is not.
 */
function validateDnsLabel(label) {
  if (!label) return null;

  if (label.length >= 4 && label.slice(0, 4).toLowerCase() === "xn--") {
    if (!isWellFormedAceLabel(label)) {
      return createIdentityError(
        `DNS label ${JSON.stringify(label)} is not a well-formed punycode ACE label: refuse`,
      );
    }
    return null;
  }

  let hasAscii = false;
  for (const char of label) {
    if (isAsciiCodePoint(char.codePointAt(0))) {
      hasAscii = true;
      break;
    }
  }

  if (!hasAscii) {
    // Pure non-ASCII U-label (genuine IDN). Homograph defense targets the mix.
    return null;
  }

  let offset = 0;
  for (const char of label) {
    const codePoint = char.codePointAt(0);
    if (!isAsciiCodePoint(codePoint) && isScriptBearingCodePoint(codePoint)) {
      return createIdentityError(
        `DNS label ${JSON.stringify(label)} mixes ASCII with non-ASCII script ` +
          `character ${formatCodePoint(codePoint)} at offset ${offset}: refuse ` +
          `(potential IDN homograph)`,
      );
    }
    offset += char.length;
  }

  return null;
}

function validateDnsLabels(name) {
  for (const label of String(name).split(".")) {
    const error = validateDnsLabel(label);
    if (error) return error;
  }
  return null;
}

/**
 * @returns {CertOpsIdentitySafetyError|null}
 */
function checkSafeDnsIdentity(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    return createIdentityError("DNS identity must be a string");
  }
  if (value.length === 0) return null;

  const forbidden = findForbiddenIdentityCharacter(value);
  if (forbidden) return createIdentityError(forbidden.message);

  return validateDnsLabels(value);
}

/**
 * @returns {CertOpsIdentitySafetyError|null}
 */
function checkSafeIpIdentity(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string") {
    return createIdentityError("IP identity must be a string");
  }
  if (value.length === 0) return null;

  const forbidden = findForbiddenIdentityCharacter(value);
  if (forbidden) return createIdentityError(forbidden.message);

  return null;
}

/**
 * Character-safety only (no DNS mixed-script). For URI / email / other SANs.
 * @returns {CertOpsIdentitySafetyError|null}
 */
function checkSafeNonDnsIdentity(value) {
  return checkSafeIpIdentity(value);
}

function assertSafeDnsIdentity(value, { field = "DNS identity" } = {}) {
  const error = checkSafeDnsIdentity(value);
  if (!error) return value;
  throw createIdentityError(`${field} rejected: ${error.message}`);
}

/**
 * Hostname validation for monitor-bridge / endpoint wiring (D8).
 * Same policy as assertSafeDnsIdentity.
 */
function assertSafeHostname(value, { field = "hostname" } = {}) {
  return assertSafeDnsIdentity(value, { field });
}

function assertSafeIpIdentity(value, { field = "IP identity" } = {}) {
  const error = checkSafeIpIdentity(value);
  if (!error) return value;
  throw createIdentityError(`${field} rejected: ${error.message}`);
}

function assertSafeNonDnsIdentity(value, { field = "identity" } = {}) {
  const error = checkSafeNonDnsIdentity(value);
  if (!error) return value;
  throw createIdentityError(`${field} rejected: ${error.message}`);
}

function isSafeDnsIdentity(value) {
  return checkSafeDnsIdentity(value) === null;
}

function isSafeHostname(value) {
  return isSafeDnsIdentity(value);
}

module.exports = {
  CERTOPS_UNSAFE_IDENTITY,
  CertOpsIdentitySafetyError,
  assertSafeDnsIdentity,
  assertSafeHostname,
  assertSafeIpIdentity,
  assertSafeNonDnsIdentity,
  checkSafeDnsIdentity,
  checkSafeIpIdentity,
  checkSafeNonDnsIdentity,
  findForbiddenIdentityCharacter,
  isSafeDnsIdentity,
  isSafeHostname,
  isWellFormedAceLabel,
};
