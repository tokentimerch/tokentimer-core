/**
 * Threshold Computation Utilities
 *
 * Shared functions for calculating days until expiration and determining
 * which tokens should trigger alerts based on expiration thresholds.
 */

/**
 * Computes the number of days until a given expiration date.
 * Uses UTC midnight to avoid timezone inconsistencies.
 *
 * @param {string|Date|null} expiration - Expiration date (ISO string or Date object)
 * @returns {number|null} Number of days until expiration (negative if expired), or null if invalid
 *
 * @example
 * computeDaysLeft('2025-12-31') // Returns days until Dec 31, 2025
 * computeDaysLeft(new Date('2025-12-31')) // Same result
 * computeDaysLeft(null) // Returns null
 */
function computeDaysLeft(expiration) {
  if (!expiration) return null;
  try {
    const expDate = new Date(expiration);
    if (isNaN(expDate.getTime())) return null;

    // Use UTC midnight to avoid timezone inconsistencies
    const expUTC = Date.UTC(
      expDate.getUTCFullYear(),
      expDate.getUTCMonth(),
      expDate.getUTCDate(),
    );
    const now = new Date();
    const todayUTC = Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
    );
    const diffDays = Math.round((expUTC - todayUTC) / 86400000);
    return diffDays;
  } catch (_) {
    return null;
  }
}

/**
 * Determines which threshold window has been reached based on days until expiration.
 *
 * @param {number|null} daysUntil - Days until expiration (negative if expired)
 * @param {Array<number>} thresholds - Array of threshold days (e.g., [30, 14, 7, 1, 0])
 * @returns {Object|null} Object with thresholdReached and negativeWindow, or null if no threshold matched
 * @property {number} thresholdReached - The threshold that was reached
 * @property {boolean} negativeWindow - True if this is a post-expiration threshold
 *
 * @example
 * findThresholdWindow(13, [30, 14, 7, 1, 0]) // Returns { thresholdReached: 14, negativeWindow: false }
 * findThresholdWindow(-5, [-30, -7, -1, 0]) // Returns { thresholdReached: -7, negativeWindow: true }
 */
function findThresholdWindow(daysUntil, thresholds) {
  if (daysUntil === null || daysUntil === undefined) return null;
  if (!Array.isArray(thresholds) || thresholds.length === 0) return null;

  // Sort thresholds ascending and remove duplicates
  const thresholdsAsc = [...new Set(thresholds)].sort((a, b) => a - b);

  if (daysUntil < 0) {
    // Post-expiration: trigger once per negative window
    const negatives = thresholdsAsc.filter((th) => th < 0);
    if (negatives.length === 0) {
      return null; // User didn't opt into post-expiry alerts
    }

    // Map to the nearest negative threshold that is >= current days (closer to 0)
    let thresholdReached = negatives.find((th) => daysUntil <= th);
    if (thresholdReached === undefined) {
      // More negative than the lowest configured threshold: map to the lowest window once
      thresholdReached = negatives[0];
    }

    return {
      thresholdReached,
      negativeWindow: true,
    };
  } else {
    // Pre-expiration: find the first threshold that daysUntil is <=
    const thresholdReached = thresholdsAsc.find((th) => daysUntil <= th);
    if (thresholdReached === undefined) {
      return null; // No threshold reached yet
    }

    return {
      thresholdReached,
      negativeWindow: false,
    };
  }
}

/**
 * Checks if an imported token's threshold date has already passed (stale check).
 * Used to avoid "catch-up" alerts for thresholds already passed before import.
 *
 * @param {string|Date|null} importedAt - Import date (ISO string or Date object)
 * @param {string|Date|null} expiration - Expiration date (ISO string or Date object)
 * @param {number} thresholdReached - The threshold that was reached
 * @param {boolean} negativeWindow - True if this is a post-expiration threshold
 * @returns {boolean} True if the threshold date has already passed (stale), false otherwise
 */
function isStaleImportThreshold(
  importedAt,
  expiration,
  thresholdReached,
  negativeWindow,
) {
  if (!importedAt || !expiration) return false;

  try {
    const importedAtDate = new Date(importedAt);
    const expDate = new Date(expiration);

    if (isNaN(importedAtDate.getTime()) || isNaN(expDate.getTime())) {
      return false;
    }

    const importedAtDateUTC = Date.UTC(
      importedAtDate.getUTCFullYear(),
      importedAtDate.getUTCMonth(),
      importedAtDate.getUTCDate(),
    );

    let thresholdDateUTC;
    if (negativeWindow) {
      // Post-expiration: threshold date is expiration + abs(threshold)
      thresholdDateUTC = Date.UTC(
        expDate.getUTCFullYear(),
        expDate.getUTCMonth(),
        expDate.getUTCDate() + Math.abs(thresholdReached),
      );
    } else {
      // Pre-expiration: threshold date is expiration - threshold
      thresholdDateUTC = Date.UTC(
        expDate.getUTCFullYear(),
        expDate.getUTCMonth(),
        expDate.getUTCDate() - thresholdReached,
      );
    }

    // If imported after the threshold date, it's stale
    return importedAtDateUTC > thresholdDateUTC;
  } catch (_) {
    return false;
  }
}

export { computeDaysLeft, findThresholdWindow, isStaleImportThreshold };
