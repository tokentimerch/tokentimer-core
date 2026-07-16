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
 * - Mixed-script DNS labels: labels mixing ASCII with non-ASCII characters
 *   are rejected, and labels mixing multiple non-ASCII scripts are rejected
 *   (per-script detection modelled on the UTS #39 "Highly Restrictive"
 *   profile), except the standard CJK combinations Han + Hiragana + Katakana
 *   (Japanese), Han + Bopomofo (Chinese), and Han + Hangul (Korean).
 *
 * Punycode policy (ACE labels):
 * - Labels that begin with "xn--" (case-insensitive) must be well-formed LDH
 *   ACE: xn-- followed by one or more [a-z0-9-], ASCII only.
 * - Well-formed ACE labels are accepted (they are the wire form of IDNs).
 * - Malformed xn-- labels are rejected.
 * - Single-script non-ASCII U-labels remain allowed; we refuse the MIX of
 *   ASCII and non-ASCII characters in one label, and the mix of multiple
 *   non-ASCII scripts in one label (CJK combinations above excepted).
 * - DEFERRED hardening: decoding well-formed ACE labels to their underlying
 *   U-label and applying the script rules to the decoded form.
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

// Script=Common and Script=Inherited characters (digits, hyphens,
// punctuation, combining marks) never contribute a script of their own.
const COMMON_OR_INHERITED_SCRIPT = /[\p{Script=Common}\p{Script=Inherited}]/u;

// Complete list of Unicode Script property values recognized by the Node
// runtime's RegExp \p{Script=...} escapes (ECMAScript UnicodeScriptValue,
// Unicode 16 on Node 22: 168 scripts). Enumerated by compiling
// new RegExp(`\\p{Script=NAME}`, "u") for every candidate name and keeping
// the ones that compile; verified exhaustive by checking that every
// script-bearing code point (\p{L}, \p{Nd}, \p{M}) outside Common/Inherited
// matches exactly one of these scripts. Full coverage means a label mixing
// any two distinct scripts is detected: there is no shared "other" bucket
// that unlisted scripts could hide in.
const UNICODE_SCRIPT_NAMES = [
  "Adlam", "Ahom", "Anatolian_Hieroglyphs", "Arabic", "Armenian", "Avestan",
  "Balinese", "Bamum", "Bassa_Vah", "Batak", "Bengali", "Bhaiksuki",
  "Bopomofo", "Brahmi", "Braille", "Buginese", "Buhid", "Canadian_Aboriginal",
  "Carian", "Caucasian_Albanian", "Chakma", "Cham", "Cherokee", "Chorasmian",
  "Coptic", "Cuneiform", "Cypriot", "Cypro_Minoan", "Cyrillic", "Deseret",
  "Devanagari", "Dives_Akuru", "Dogra", "Duployan", "Egyptian_Hieroglyphs",
  "Elbasan", "Elymaic", "Ethiopic", "Garay", "Georgian", "Glagolitic",
  "Gothic", "Grantha", "Greek", "Gujarati", "Gunjala_Gondi", "Gurmukhi",
  "Gurung_Khema", "Han", "Hangul", "Hanifi_Rohingya", "Hanunoo", "Hatran",
  "Hebrew", "Hiragana", "Imperial_Aramaic", "Inscriptional_Pahlavi",
  "Inscriptional_Parthian", "Javanese", "Kaithi", "Kannada", "Katakana",
  "Kawi", "Kayah_Li", "Kharoshthi", "Khitan_Small_Script", "Khmer", "Khojki",
  "Khudawadi", "Kirat_Rai", "Lao", "Latin", "Lepcha", "Limbu", "Linear_A",
  "Linear_B", "Lisu", "Lycian", "Lydian", "Mahajani", "Makasar", "Malayalam",
  "Mandaic", "Manichaean", "Marchen", "Masaram_Gondi", "Medefaidrin",
  "Meetei_Mayek", "Mende_Kikakui", "Meroitic_Cursive", "Meroitic_Hieroglyphs",
  "Miao", "Modi", "Mongolian", "Mro", "Multani", "Myanmar", "Nabataean",
  "Nag_Mundari", "Nandinagari", "New_Tai_Lue", "Newa", "Nko", "Nushu",
  "Nyiakeng_Puachue_Hmong", "Ogham", "Ol_Chiki", "Ol_Onal", "Old_Hungarian",
  "Old_Italic", "Old_North_Arabian", "Old_Permic", "Old_Persian",
  "Old_Sogdian", "Old_South_Arabian", "Old_Turkic", "Old_Uyghur", "Oriya",
  "Osage", "Osmanya", "Pahawh_Hmong", "Palmyrene", "Pau_Cin_Hau", "Phags_Pa",
  "Phoenician", "Psalter_Pahlavi", "Rejang", "Runic", "Samaritan",
  "Saurashtra", "Sharada", "Shavian", "Siddham", "SignWriting", "Sinhala",
  "Sogdian", "Sora_Sompeng", "Soyombo", "Sundanese", "Sunuwar",
  "Syloti_Nagri", "Syriac", "Tagalog", "Tagbanwa", "Tai_Le", "Tai_Tham",
  "Tai_Viet", "Takri", "Tamil", "Tangsa", "Tangut", "Telugu", "Thaana",
  "Thai", "Tibetan", "Tifinagh", "Tirhuta", "Todhri", "Toto", "Tulu_Tigalari",
  "Ugaritic", "Vai", "Vithkuqi", "Wancho", "Warang_Citi", "Yezidi", "Yi",
  "Zanabazar_Square",
];

// Lazily compiled per-script regexes, in UNICODE_SCRIPT_NAMES order. Compiled
// on first use so module load stays cheap.
const SCRIPT_MATCHER_CACHE = new Map();

function scriptMatcher(name) {
  let pattern = SCRIPT_MATCHER_CACHE.get(name);
  if (!pattern) {
    pattern = new RegExp(`\\p{Script=${name}}`, "u");
    SCRIPT_MATCHER_CACHE.set(name, pattern);
  }
  return pattern;
}

// Fail-closed marker for characters whose script cannot be resolved. With the
// complete script list above this is unreachable on current runtimes, but if
// a future Unicode version introduces a script this Node build cannot name,
// any label containing it is REJECTED rather than silently bucketed together
// with other unknown scripts.
const UNRESOLVED_SCRIPT = "Unresolved";

// Per-character script memo: label validation revisits the same characters
// across calls, and a hit avoids the linear scan over ~168 regexes.
const CHARACTER_SCRIPT_CACHE = new Map();
const CHARACTER_SCRIPT_CACHE_MAX = 4096;

// Standard legitimate combinations per the UTS #39 "Highly Restrictive"
// profile. Latin is deliberately NOT allowed alongside these: the ASCII /
// non-ASCII mixing rule below already rejects it, and we keep that stricter
// stance rather than loosen existing behavior.
const ALLOWED_SCRIPT_COMBINATIONS = [
  ["Han", "Hiragana", "Katakana"], // Japanese
  ["Han", "Bopomofo"], // Chinese
  ["Han", "Hangul"], // Korean
];

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

function scriptOfCharacter(char) {
  if (COMMON_OR_INHERITED_SCRIPT.test(char)) return null;

  const cached = CHARACTER_SCRIPT_CACHE.get(char);
  if (cached !== undefined) return cached;

  let script = UNRESOLVED_SCRIPT;
  for (const name of UNICODE_SCRIPT_NAMES) {
    if (scriptMatcher(name).test(char)) {
      script = name;
      break;
    }
  }

  if (CHARACTER_SCRIPT_CACHE.size >= CHARACTER_SCRIPT_CACHE_MAX) {
    CHARACTER_SCRIPT_CACHE.clear();
  }
  CHARACTER_SCRIPT_CACHE.set(char, script);
  return script;
}

function isAllowedScriptCombination(scripts) {
  return ALLOWED_SCRIPT_COMBINATIONS.some(
    (combo) =>
      scripts.size <= combo.length &&
      [...scripts].every((script) => combo.includes(script)),
  );
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
 * Rejects labels mixing ASCII with non-ASCII characters, and labels mixing
 * multiple non-ASCII scripts (standard CJK combinations excepted).
 */
function validateDnsLabel(label) {
  if (!label) return null;

  if (label.length >= 4 && label.slice(0, 4).toLowerCase() === "xn--") {
    if (!isWellFormedAceLabel(label)) {
      return createIdentityError(
        `DNS label ${JSON.stringify(label)} is not a well-formed punycode ACE label: refuse`,
      );
    }
    // Accepted as-is. DEFERRED hardening: decode the ACE label and apply the
    // script rules to the decoded U-label.
    return null;
  }

  let hasAscii = false;
  let hasNonAscii = false;
  for (const char of label) {
    if (isAsciiCodePoint(char.codePointAt(0))) hasAscii = true;
    else hasNonAscii = true;
  }

  if (!hasNonAscii) {
    // Pure ASCII LDH label: no script mixing possible.
    return null;
  }

  if (hasAscii) {
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

  // Pure non-ASCII U-label: allow one script only (Common/Inherited ignored),
  // except the standard CJK combinations. Characters whose script cannot be
  // resolved reject the label outright (fail closed).
  const scripts = new Set();
  for (const char of label) {
    const script = scriptOfCharacter(char);
    if (script === UNRESOLVED_SCRIPT) {
      return createIdentityError(
        `DNS label ${JSON.stringify(label)} contains character ` +
          `${formatCodePoint(char.codePointAt(0))} of unresolved Unicode script: ` +
          `refuse (potential IDN homograph)`,
      );
    }
    if (script) scripts.add(script);
  }

  if (scripts.size > 1 && !isAllowedScriptCombination(scripts)) {
    return createIdentityError(
      `DNS label ${JSON.stringify(label)} mixes multiple Unicode scripts ` +
        `(${[...scripts].sort().join(", ")}): refuse (potential IDN homograph)`,
    );
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
