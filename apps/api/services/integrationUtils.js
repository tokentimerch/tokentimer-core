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

module.exports = {
  tryParseDate,
  discoverExpiryFromObject,
  formatDateYmd,
};
