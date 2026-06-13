/**
 * Expiry Bucket Utilities
 *
 * Authoritative backend classification for Control Center stats and expiry
 * bucket counts. Boundaries align with the dashboard expiry bucket contract.
 */

const NEVER_EXPIRES_DATE = "2099-12-31";

/**
 * @param {string} timeZone - IANA timezone identifier
 * @returns {boolean}
 */
function isValidTimeZone(timeZone) {
  try {
    Intl.DateTimeFormat("en-US", { timeZone });
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * @param {string|undefined|null} timezone
 * @returns {string}
 */
function resolveTimeZone(timezone) {
  if (!timezone || timezone === "UTC") {
    return "UTC";
  }
  const trimmed = String(timezone).trim();
  if (!trimmed || trimmed === "UTC") {
    return "UTC";
  }
  return isValidTimeZone(trimmed) ? trimmed : "UTC";
}

/**
 * Calendar date at local midnight in `timeZone`, as a UTC epoch ms value.
 *
 * @param {Date} instant
 * @param {string} timeZone
 * @returns {number}
 */
function calendarMidnightUtcEpoch(instant, timeZone) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(instant);

  const year = Number(parts.find((p) => p.type === "year")?.value);
  const month = Number(parts.find((p) => p.type === "month")?.value);
  const day = Number(parts.find((p) => p.type === "day")?.value);

  return Date.UTC(year, month - 1, day);
}

/**
 * True when an expiry value is a never-expires sentinel (2099-12-31, year 9999, etc.).
 *
 * @param {string|Date|null|undefined} expiry
 * @returns {boolean}
 */
function isNeverExpires(expiry) {
  if (!expiry) return false;

  const expiryStr =
    typeof expiry === "string"
      ? expiry
      : expiry instanceof Date
        ? expiry.toISOString()
        : String(expiry);

  if (!expiryStr || expiryStr === "N/A") {
    return false;
  }

  return (
    expiryStr.startsWith(NEVER_EXPIRES_DATE) ||
    expiryStr.startsWith("9999-")
  );
}

/**
 * Computes days until expiration using calendar dates in the given timezone.
 * Defaults to UTC when timezone is missing or invalid.
 *
 * @param {string|Date|null|undefined} expiration - Expiration date (ISO string or Date)
 * @param {object} [options]
 * @param {string} [options.timezone='UTC'] - IANA timezone (e.g. Europe/Zurich) or UTC
 * @returns {number|null} Days until expiration (negative if expired), or null when
 *   missing, invalid, or never-expires
 *
 * @example
 * computeDaysLeft('2025-12-31', { timezone: 'UTC' })
 * computeDaysLeft('2025-12-31', { timezone: 'Europe/Zurich' })
 */
function computeDaysLeft(expiration, options = {}) {
  if (!expiration) return null;
  if (isNeverExpires(expiration)) return null;

  try {
    const expDate = new Date(expiration);
    if (isNaN(expDate.getTime())) return null;

    const timeZone = resolveTimeZone(options.timezone);
    const expUTC = calendarMidnightUtcEpoch(expDate, timeZone);
    const todayUTC = calendarMidnightUtcEpoch(new Date(), timeZone);
    return Math.round((expUTC - todayUTC) / 86400000);
  } catch (_) {
    return null;
  }
}

/**
 * Maps a day count to an expiry bucket.
 *
 * Boundaries: expired (days < 0), expiring7 (0-7), expiring8To30 (8-30),
 * healthy (days > 30), neverExpires (null from sentinel or missing day count).
 *
 * @param {number|null|undefined} days - Days from {@link computeDaysLeft}
 * @returns {'expired'|'expiring7'|'expiring8To30'|'healthy'|'neverExpires'}
 */
function classifyExpiryBucket(days) {
  if (days === null || days === undefined) {
    return "neverExpires";
  }
  if (days < 0) {
    return "expired";
  }
  if (days <= 7) {
    return "expiring7";
  }
  if (days <= 30) {
    return "expiring8To30";
  }
  return "healthy";
}

module.exports = {
  NEVER_EXPIRES_DATE,
  isNeverExpires,
  resolveTimeZone,
  computeDaysLeft,
  classifyExpiryBucket,
};
