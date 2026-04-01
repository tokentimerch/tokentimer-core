import { describe, it, expect } from 'vitest';
import {
  isNeverExpires,
  formatExpirationDate,
  getDaysUntilExpiration,
  formatRelativeExpiration,
  getExpirationColorScheme,
  NEVER_EXPIRES_DATE_VALUE,
} from '../../src/utils/dateUtils';

describe('dateUtils', () => {
  it('detects never-expiring date values', () => {
    expect(isNeverExpires(`${NEVER_EXPIRES_DATE_VALUE}T00:00:00Z`)).toBe(true);
    expect(
      isNeverExpires(new Date(`${NEVER_EXPIRES_DATE_VALUE}T00:00:00Z`))
    ).toBe(true);
    expect(isNeverExpires('2026-01-01')).toBe(false);
    expect(isNeverExpires(null)).toBe(false);
  });

  it('formats expiration dates with fallback text and short format', () => {
    expect(formatExpirationDate(null)).toBe('Never expires');
    expect(formatExpirationDate('N/A')).toBe('Never expires');
    expect(formatExpirationDate(`${NEVER_EXPIRES_DATE_VALUE}T12:00:00Z`)).toBe(
      'Never expires'
    );
    expect(formatExpirationDate('invalid-date')).toBe('Invalid date');
    expect(
      formatExpirationDate('2026-12-24T00:00:00Z', { shortFormat: true })
    ).toMatch(/Dec/);
  });

  it('computes days and relative expiration strings', () => {
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(today.getDate() + 1);
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);

    expect(
      getDaysUntilExpiration(`${NEVER_EXPIRES_DATE_VALUE}T00:00:00Z`)
    ).toBeNull();
    expect(formatRelativeExpiration(null)).toBe('Unknown');
    expect(
      formatRelativeExpiration(`${NEVER_EXPIRES_DATE_VALUE}T00:00:00Z`)
    ).toBe('Never expires');
    expect(formatRelativeExpiration(tomorrow.toISOString())).toBe(
      'Expires tomorrow'
    );
    expect(formatRelativeExpiration(yesterday.toISOString())).toBe(
      'Expired yesterday'
    );
  });

  it('returns expected color schemes for expiry thresholds', () => {
    expect(getExpirationColorScheme(null)).toBe('gray');
    expect(
      getExpirationColorScheme(`${NEVER_EXPIRES_DATE_VALUE}T00:00:00Z`)
    ).toBe('blue');

    const far = new Date();
    far.setDate(far.getDate() + 40);
    const warn = new Date();
    warn.setDate(warn.getDate() + 20);
    const danger = new Date();
    danger.setDate(danger.getDate() + 3);
    const expired = new Date();
    expired.setDate(expired.getDate() - 2);

    expect(getExpirationColorScheme(far.toISOString())).toBe('green');
    expect(getExpirationColorScheme(warn.toISOString())).toBe('orange');
    expect(getExpirationColorScheme(danger.toISOString())).toBe('red');
    expect(getExpirationColorScheme(expired.toISOString())).toBe('red');
  });
});
