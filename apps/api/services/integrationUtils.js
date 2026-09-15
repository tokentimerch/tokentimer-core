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

/**
 * Join an API path onto an integration base URL without dropping a
 * path prefix. `new URL("/api/v4/user", "https://host/gitlab")` becomes
 * `https://host/api/v4/user` because a leading slash is origin-relative.
 * GitLab relative_url_root and GitHub Enterprise `/api/v3` need that
 * prefix kept.
 *
 * @param {string} baseUrl
 * @param {string} apiPath
 * @returns {string}
 */
function joinIntegrationApiUrl(baseUrl, apiPath) {
  const base = new URL(String(baseUrl));
  let suffix = String(apiPath || "");
  if (!suffix.startsWith("/")) suffix = `/${suffix}`;
  if (suffix.startsWith("//")) {
    throw new Error("API path must be a path, not a scheme-relative URL");
  }
  const prefix = base.pathname.replace(/\/+$/, "");
  base.pathname = `${prefix}${suffix}`;
  base.search = "";
  base.hash = "";
  return base.toString();
}

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

const TERMINAL_STATUS_PRECEDENCE = [401, 403, 404];

function throwIfAllScopesFailed(summary, items) {
  if (!Array.isArray(summary) || summary.length === 0) return;
  if (Array.isArray(items) && items.length > 0) return;
  if (!summary.every((s) => s && s.error)) return;

  const statuses = summary
    .map((s) => Number(s.status))
    .filter((n) => Number.isInteger(n) && n > 0);
  const unique = [...new Set(statuses)];
  let status = 502;
  if (unique.length === 1) {
    status = unique[0];
  } else {
    status =
      TERMINAL_STATUS_PRECEDENCE.find((code) => unique.includes(code)) || 502;
  }

  const err = new Error(
    status === 401
      ? "Authentication failed"
      : status === 403
        ? "Permission denied"
        : status === 404
          ? "Not found"
          : "Upstream scan failed",
  );
  err.status = status;
  throw err;
}

module.exports = {
  tryParseDate,
  discoverExpiryFromObject,
  formatDateYmd,
  CREDENTIALED_AXIOS_REDIRECTS,
  joinIntegrationApiUrl,
  isHttpRedirectStatus,
  assertSameOriginFollowUp,
  throwIfAllScopesFailed,
};
