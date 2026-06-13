import { describe, it, expect } from 'vitest';
import {
  computeDaysLeftUtc,
  classifyExpiryBucket,
} from '../../src/utils/expiryBuckets.js';
import { NEVER_EXPIRES_DATE_VALUE } from '../../src/utils/dateUtils';

describe('expiryBuckets', () => {
  describe('classifyExpiryBucket', () => {
    it.each([
      [-1, 'expired'],
      [0, 'expiring7'],
      [7, 'expiring7'],
      [8, 'expiring8To30'],
      [30, 'expiring8To30'],
      [31, 'healthy'],
    ])('classifies %i days as %s', (days, expected) => {
      expect(classifyExpiryBucket(days)).toBe(expected);
    });

    it('classifies null and undefined as neverExpires', () => {
      expect(classifyExpiryBucket(null)).toBe('neverExpires');
      expect(classifyExpiryBucket(undefined)).toBe('neverExpires');
    });
  });

  describe('computeDaysLeftUtc', () => {
    it('returns null for never-expires sentinel dates', () => {
      expect(computeDaysLeftUtc(NEVER_EXPIRES_DATE_VALUE)).toBeNull();
      expect(
        computeDaysLeftUtc(`${NEVER_EXPIRES_DATE_VALUE}T00:00:00Z`)
      ).toBeNull();
      expect(computeDaysLeftUtc('9999-12-31')).toBeNull();
    });
  });
});
