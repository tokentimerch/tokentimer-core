// Alert threshold presets and validation. Mirrors the server: whole days
// relative to expiry, -365 to 730, where 0 is the expiry day and negative
// values fire after expiry.

import {
  DEFAULT_ALERT_THRESHOLDS,
  MAX_ALERT_THRESHOLD_DAYS,
  MIN_ALERT_THRESHOLD_DAYS,
} from '../../utils/alertThresholds.js';

export const THRESHOLD_MIN = MIN_ALERT_THRESHOLD_DAYS;
export const THRESHOLD_MAX = MAX_ALERT_THRESHOLD_DAYS;

export const THRESHOLD_PRESETS = {
  standard: {
    label: 'Standard',
    description: '30, 14, 7 and 1 day before, and on the day',
    values: [...DEFAULT_ALERT_THRESHOLDS],
  },
  early: {
    label: 'Early warning',
    description: 'Starts two months ahead, for slow renewals',
    values: [60, 30, 14, 7, 1, 0],
  },
  minimal: {
    label: 'Minimal',
    description: 'Only the last week and the day itself',
    values: [7, 1, 0],
  },
};

export function parseThresholds(text) {
  const parts = String(text || '')
    .split(/[\s,;]+/)
    .filter(Boolean);
  const problems = [];
  const values = [];
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n)) {
      problems.push(`"${part}" is not a whole number of days.`);
    } else if (n < THRESHOLD_MIN || n > THRESHOLD_MAX) {
      problems.push(
        `${n} is outside ${THRESHOLD_MIN} to ${THRESHOLD_MAX} days.`
      );
    } else {
      values.push(n);
    }
  }
  const unique = Array.from(new Set(values)).sort((a, b) => b - a);
  if (unique.length === 0 && problems.length === 0) {
    problems.push('Enter at least one number of days.');
  }
  return { values: unique, problems };
}

/** Which preset the current values match, or 'custom'. */
export function matchPreset(values) {
  const key = JSON.stringify([...(values || [])].sort((a, b) => b - a));
  for (const [id, preset] of Object.entries(THRESHOLD_PRESETS)) {
    if (JSON.stringify(preset.values) === key) return id;
  }
  return 'custom';
}

const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

export function describeThresholds(values) {
  return (values || [])
    .map(v => {
      if (v === 0) return 'on the day';
      return v > 0
        ? `${plural(v, 'day')} before`
        : `${plural(-v, 'day')} after`;
    })
    .join(', ');
}
