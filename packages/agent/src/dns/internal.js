"use strict";

/**
 * Shared internals for the DNS-01 solver layer (src/dns). This file is
 * private to the dns module: index.js, hook.js, and the providers/ files
 * require it, and nothing outside src/dns should.
 *
 * Everything here is deliberately dependency-free and side-effect-free so
 * provider implementations stay pure "data in, data out" HTTP/wire builders
 * that tests can drive with injected fakes.
 */

/** Hard cap on any provider-response excerpt carried into results. Mirrors
 * the acme module's OUTPUT_EXCERPT_MAX_CHARS. */
const OUTPUT_EXCERPT_MAX_CHARS = 1024;

/** Marker whose presence anywhere in an excerpt causes the whole excerpt to
 * be replaced, never partially scrubbed (same rule as src/acme). */
const PRIVATE_KEY_MARKER = "PRIVATE KEY";
const REDACTED_EXCERPT_PLACEHOLDER = "[redacted]";

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * Suffix-with-dot-boundary match, identical in spirit to the policy
 * module's isZoneCoveredBy (duplicated, not imported, to keep src/dns
 * self-contained): `recordName` is within `zone` if they are equal or if
 * recordName ends with `.${zone}`. Prevents `evilexample.com` matching a
 * zone of `example.com`.
 *
 * @param {string} recordName
 * @param {string} zone
 * @returns {boolean}
 */
function isRecordNameWithinZone(recordName, zone) {
  const normalizedRecord = recordName.toLowerCase();
  const normalizedZone = zone.toLowerCase();
  return (
    normalizedRecord === normalizedZone ||
    normalizedRecord.endsWith(`.${normalizedZone}`)
  );
}

/**
 * The record name relative to its zone: "" when recordName === zone,
 * otherwise recordName with the trailing `.${zone}` removed. Callers map
 * "" to their provider's apex spelling ("@" for Azure, etc.). Assumes the
 * dot-boundary check already passed.
 *
 * @param {string} recordName
 * @param {string} zone
 * @returns {string}
 */
function relativeRecordName(recordName, zone) {
  if (recordName.toLowerCase() === zone.toLowerCase()) {
    return "";
  }
  return recordName.slice(0, recordName.length - zone.length - 1);
}

/**
 * Builds a bounding + redacting excerpt function closed over the caller's
 * secret strings. DNS provider credentials are takeover-grade (they can
 * redirect a whole zone), so an excerpt containing any credential value --
 * or any PRIVATE KEY marker -- is redacted WHOLESALE, never partially
 * scrubbed, exactly like the acme module treats key material.
 *
 * @param {string[]} secretValues credential strings to redact on sight
 * @returns {(output: unknown) => string}
 */
function makeExcerptRedactor(secretValues) {
  const secrets = (secretValues || []).filter(isNonEmptyString);

  return function boundAndRedactExcerpt(output) {
    let text;
    if (typeof output === "string") {
      text = output;
    } else if (Buffer.isBuffer(output)) {
      text = output.toString("utf8");
    } else if (output === undefined || output === null) {
      text = "";
    } else {
      try {
        text = JSON.stringify(output);
      } catch {
        text = String(output);
      }
    }

    // Redaction is checked on the FULL text (not just the excerpt window)
    // so a secret echoed past the first 1024 chars still triggers it.
    if (text.includes(PRIVATE_KEY_MARKER)) {
      return REDACTED_EXCERPT_PLACEHOLDER;
    }
    if (secrets.some((secret) => text.includes(secret))) {
      return REDACTED_EXCERPT_PLACEHOLDER;
    }

    return text.slice(0, OUTPUT_EXCERPT_MAX_CHARS);
  };
}

/**
 * fetch wrapper with an AbortController timeout, resolving to a plain
 * { status, ok, bodyText } record. Never inspects the body as JSON here;
 * providers parse what they need and always run raw text through their
 * excerpt redactor before surfacing any of it.
 *
 * Throws on network failure / abort; the solver layer in index.js maps
 * those throws to { ok: false } operational results.
 *
 * @param {Function} fetchImpl fetch-shaped implementation
 * @param {string} url
 * @param {object} options fetch options (method, headers, body)
 * @param {number} timeoutMs
 * @returns {Promise<{ status: number, ok: boolean, bodyText: string }>}
 */
async function fetchWithTimeout(fetchImpl, url, options, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new Error(`request timed out after ${timeoutMs} ms`));
  }, timeoutMs);

  try {
    const response = await fetchImpl(url, {
      ...options,
      signal: controller.signal,
    });
    const bodyText = await response.text();
    return {
      status: response.status,
      ok: response.status >= 200 && response.status < 300,
      bodyText,
    };
  } finally {
    clearTimeout(timer);
  }
}

module.exports = {
  OUTPUT_EXCERPT_MAX_CHARS,
  PRIVATE_KEY_MARKER,
  REDACTED_EXCERPT_PLACEHOLDER,
  isNonEmptyString,
  isRecordNameWithinZone,
  relativeRecordName,
  makeExcerptRedactor,
  fetchWithTimeout,
};
