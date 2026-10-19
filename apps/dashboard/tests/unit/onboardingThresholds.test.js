import { describe, expect, it } from 'vitest';
import {
  THRESHOLD_PRESETS,
  describeThresholds,
  matchPreset,
  parseThresholds,
} from '../../src/components/onboarding/thresholds.js';

describe('parseThresholds', () => {
  it('sorts descending and removes duplicates', () => {
    expect(parseThresholds('1, 30 7,14 7 0').values).toEqual([30, 14, 7, 1, 0]);
  });

  it('accepts negative values for after-expiry reminders', () => {
    expect(parseThresholds('7, 0, -3').values).toEqual([7, 0, -3]);
  });

  it('rejects non-integers and out-of-range values with a reason each', () => {
    const { problems, values } = parseThresholds('10, 2.5, abc, 900, -400');
    expect(values).toEqual([10]);
    expect(problems).toHaveLength(4);
    expect(problems.join(' ')).toMatch(/2\.5/);
    expect(problems.join(' ')).toMatch(/900/);
  });

  it('requires at least one value and caps the count', () => {
    expect(parseThresholds('  ').problems[0]).toMatch(/at least one/);
    const many = Array.from({ length: 13 }, (_, i) => i + 1).join(',');
    expect(parseThresholds(many).problems.join(' ')).toMatch(/at most 12/);
  });
});

describe('presets', () => {
  it('recognises presets regardless of order', () => {
    expect(matchPreset([0, 1, 7, 14, 30])).toBe('standard');
    expect(matchPreset(THRESHOLD_PRESETS.minimal.values)).toBe('minimal');
    expect(matchPreset([5, 3])).toBe('custom');
    expect(matchPreset(undefined)).toBe('custom');
  });

  it('describes values in plain language', () => {
    expect(describeThresholds([30, 0, -2])).toBe(
      '30 days before, on the day, 2 days after'
    );
  });

  it('uses the singular for one day', () => {
    expect(describeThresholds([1, -1])).toBe('1 day before, 1 day after');
    expect(describeThresholds([14, 1, 0])).toBe(
      '14 days before, 1 day before, on the day'
    );
  });
});
