/**
 * Frontend display helpers mirroring the backend expiry bucket contract.
 *
 * NOT authoritative. Use for labels and local display until the API provides
 * an expiry bucket field. Authoritative bucket counts and classifications come
 * from the API.
 */

import { isNeverExpires } from './dateUtils';

/**
 * Computes days until expiry using UTC midnight (matches worker thresholds.js).
 *
 * @param {string|Date|null|undefined} expiry - Expiration date (ISO string or Date)
 * @returns {number|null} Days until expiry (negative if expired), or null when
 *   missing, invalid, or a never-expires sentinel date
 */
export function computeDaysLeftUtc(expiry) {
  if (!expiry) return null;
  if (isNeverExpires(expiry)) return null;

  try {
    const expDate = new Date(expiry);
    if (isNaN(expDate.getTime())) return null;

    const expUTC = Date.UTC(
      expDate.getUTCFullYear(),
      expDate.getUTCMonth(),
      expDate.getUTCDate()
    );
    const now = new Date();
    const todayUTC = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate()
    );
    return Math.round((expUTC - todayUTC) / 86400000);
  } catch (_) {
    return null;
  }
}

/**
 * Maps a day count to an expiry bucket for display.
 *
 * Boundaries: expired (days < 0), expiring7 (0-7), expiring8To30 (8-30),
 * healthy (days > 30), neverExpires (null from sentinel dates).
 *
 * NOT authoritative. Prefer API-provided bucket stats when available.
 *
 * @param {number|null|undefined} days - Days from {@link computeDaysLeftUtc}
 * @returns {'expired'|'expiring7'|'expiring8To30'|'healthy'|'neverExpires'}
 */
export function classifyExpiryBucket(days) {
  if (days === null || days === undefined) {
    return 'neverExpires';
  }
  if (days < 0) {
    return 'expired';
  }
  if (days <= 7) {
    return 'expiring7';
  }
  if (days <= 30) {
    return 'expiring8To30';
  }
  return 'healthy';
}
