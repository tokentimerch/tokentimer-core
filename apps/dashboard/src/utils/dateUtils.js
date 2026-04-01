/**
 * Utility functions for date formatting and handling
 */

const NEVER_EXPIRES_DATE = '2099-12-31';

/**
 * Check if a date represents a "never expires" token
 * @param {string|Date} date - Date to check
 * @returns {boolean} True if date is the special "never expires" date
 */
export function isNeverExpires(date) {
  if (!date) return false;
  const dateStr = typeof date === 'string' ? date : date.toISOString?.();
  if (!dateStr) return false;
  // Check if date starts with 2099-12-31 (handles both date-only and datetime strings)
  return dateStr.startsWith(NEVER_EXPIRES_DATE);
}

/**
 * Format a date for display, showing "Never expires" for far-future dates
 * @param {string|Date} date - Date to format
 * @param {object} options - Formatting options
 * @param {boolean} options.shortFormat - Use short date format (default: false)
 * @param {string} options.neverExpiresText - Custom text for never-expiring tokens (default: "Never expires")
 * @returns {string} Formatted date string
 */
export function formatExpirationDate(date, options = {}) {
  const { shortFormat = false, neverExpiresText = 'Never expires' } = options;

  if (!date || String(date) === 'N/A' || isNeverExpires(date)) {
    return neverExpiresText;
  }

  try {
    const d = new Date(date);
    if (isNaN(d.getTime())) return 'Invalid date';

    if (shortFormat) {
      // Short format: MMM DD, YYYY
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });
    }
    // Full format: Month DD, YYYY
    return d.toLocaleDateString('en-US', {
      month: 'long',
      day: 'numeric',
      year: 'numeric',
    });
  } catch (e) {
    return 'Invalid date';
  }
}

/**
 * Get days until expiration, returns null for never-expiring tokens
 * @param {string|Date} date - Expiration date
 * @returns {number|null} Days until expiration, or null if never expires
 */
export function getDaysUntilExpiration(date) {
  if (!date) return null;

  if (isNeverExpires(date)) {
    return null; // Never expires
  }

  try {
    const expirationDate = new Date(date);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    expirationDate.setHours(0, 0, 0, 0);

    const diffTime = expirationDate - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    return diffDays;
  } catch (e) {
    return null;
  }
}

/**
 * Format relative expiration (e.g., "Expires in 30 days", "Expired 5 days ago")
 * @param {string|Date} date - Expiration date
 * @returns {string} Formatted relative expiration string
 */
export function formatRelativeExpiration(date) {
  if (!date) return 'Unknown';

  if (isNeverExpires(date)) {
    return 'Never expires';
  }

  const days = getDaysUntilExpiration(date);
  if (days === null) return 'Unknown';

  if (days === 0) return 'Expires today';
  if (days === 1) return 'Expires tomorrow';
  if (days === -1) return 'Expired yesterday';
  if (days > 0) return `Expires in ${days} day${days > 1 ? 's' : ''}`;
  return `Expired ${Math.abs(days)} day${Math.abs(days) > 1 ? 's' : ''} ago`;
}

/**
 * Get color scheme based on expiration status
 * @param {string|Date} date - Expiration date
 * @param {object} thresholds - Warning and danger thresholds in days
 * @returns {string} Chakra UI color scheme name
 */
export function getExpirationColorScheme(
  date,
  thresholds = { warning: 30, danger: 7 }
) {
  if (!date) return 'gray';

  if (isNeverExpires(date)) {
    return 'blue'; // Blue for never expires
  }

  const days = getDaysUntilExpiration(date);
  if (days === null) return 'gray';

  if (days < 0) return 'red'; // Expired
  if (days <= thresholds.danger) return 'red'; // Danger zone
  if (days <= thresholds.warning) return 'orange'; // Warning zone
  return 'green'; // Safe
}

export const NEVER_EXPIRES_DATE_VALUE = NEVER_EXPIRES_DATE;
