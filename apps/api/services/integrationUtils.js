"use strict";

/**
 * Shared utility functions for integration services
 * Used by vault, gitlab, github, aws, azure, and gcp integrations
 */

/**
 * Try to parse a date value from various formats
 * @param {any} value - Date value to parse
 * @returns {Date|null} Parsed date or null if invalid
 */
function tryParseDate(value) {
  if (!value) return null;
  try {
    const d = new Date(value);
    return isNaN(d.getTime()) ? null : d;
  } catch (_) {
    return null;
  }
}

/**
 * Discover expiration date from an object by checking common field names
 * @param {object} obj - Object to search for expiration fields
 * @returns {Date|null} Found expiration date or null
 */
function discoverExpiryFromObject(obj) {
  if (!obj || typeof obj !== "object") return null;
  const candidates = [
    "expiresAt",
    "expiration",
    "expiry",
    "expires_at",
    "expires_on",
    "expiresOn",
    "valid_to",
    "validTo",
    "valid_until",
    "validUntil",
    "not_after",
    "notAfter",
    "attributes.exp",
    "attributes.expires",
    "expireTime",
  ];
  for (const k of candidates) {
    const v = obj[k];
    const d = tryParseDate(v);
    if (d) return d;
  }
  return null;
}

/**
 * Format a date to YYYY-MM-DD string format
 * @param {Date|string|number} date - Date to format
 * @returns {string|null} Formatted date string or null if invalid
 */
function formatDateYmd(date) {
  if (!date) return null;
  try {
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return null;
    return d.toISOString().slice(0, 10);
  } catch (_) {
    return null;
  }
}

/**
 * Axios options that refuse automatic redirects for credentialed integration
 * requests. Following a 3xx would forward tokens to an unvalidated Location.
 */
const CREDENTIALED_AXIOS_REDIRECTS = Object.freeze({
  maxRedirects: 0,
  beforeRedirect() {
    const err = new Error(
      "Redirect refused for credentialed integration request",
    );
    err.status = 400;
    throw err;
  },
});

function isHttpRedirectStatus(status) {
  return (
    status === 301 ||
    status === 302 ||
    status === 303 ||
    status === 307 ||
    status === 308
  );
}

/**
 * Parse a provider follow-up URL (pagination nextLink, etc.) and require it
 * to stay on the same origin as the configured integration endpoint.
 * Relative URLs resolve against expectedBaseUrl; absolute URLs that leave
 * that origin are rejected.
 *
 * @param {string} candidateUrl
 * @param {string|URL} expectedBaseUrl
 * @param {string} [label]
 * @returns {URL}
 */
function assertSameOriginFollowUp(
  candidateUrl,
  expectedBaseUrl,
  label = "pagination URL",
) {
  let candidate;
  let expected;
  try {
    expected =
      expectedBaseUrl instanceof URL
        ? expectedBaseUrl
        : new URL(String(expectedBaseUrl));
    candidate = new URL(String(candidateUrl), expected);
  } catch (_) {
    const err = new Error(`Invalid ${label}`);
    err.status = 400;
    throw err;
  }

  if (!/^https?:$/.test(candidate.protocol)) {
    const err = new Error(`${label} must be http(s)`);
    err.status = 400;
    throw err;
  }

  if (candidate.username || candidate.password) {
    const err = new Error(`${label} must not include credentials`);
    err.status = 400;
    throw err;
  }

  if (candidate.origin.toLowerCase() !== expected.origin.toLowerCase()) {
    const err = new Error(`${label} left the expected host`);
    err.status = 400;
    throw err;
  }

  return candidate;
}

module.exports = {
  tryParseDate,
  discoverExpiryFromObject,
  formatDateYmd,
  CREDENTIALED_AXIOS_REDIRECTS,
  isHttpRedirectStatus,
  assertSameOriginFollowUp,
};
