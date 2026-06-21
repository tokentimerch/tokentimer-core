import { describe, expect, it } from 'vitest';
import {
  DEFAULT_ALERT_THRESHOLDS,
  getGroupThresholdInheritHint,
  getThresholdDraftError,
  groupThresholdsCsvForEditor,
  groupHasThresholdOverride,
  groupThresholdsOverrideForSave,
  normalizeThresholds,
  parseThresholdDraft,
  thresholdsEqual,
  thresholdsToCsv,
  validateAlertThresholds,
} from '../../src/utils/alertThresholds.js';

describe('alertThresholds', () => {
  it('normalizes defaults from csv string', () => {
    expect(normalizeThresholds('30,14,7,1,0')).toEqual(DEFAULT_ALERT_THRESHOLDS);
  });

  it('sorts descending and dedupes values', () => {
    expect(normalizeThresholds([7, 30, 7, 14, 30])).toEqual([30, 14, 7]);
  });

  it('ignores empty csv segments instead of treating them as zero', () => {
    expect(normalizeThresholds('30,,14')).toEqual([30, 14]);
  });

  it('filters out-of-range and non-integer values', () => {
    expect(normalizeThresholds([30, 30.5, 900, -400, 0])).toEqual([30, 0]);
  });

  it('validates that at least one threshold remains', () => {
    expect(validateAlertThresholds('')).toEqual({
      ok: false,
      list: [],
      error:
        'Please provide at least one valid threshold between -365 and 730.',
    });
  });

  it('parses draft integers within range only', () => {
    expect(parseThresholdDraft('7')).toBe(7);
    expect(parseThresholdDraft('7.5')).toBeNull();
    expect(parseThresholdDraft('999')).toBeNull();
  });

  it('returns a shared draft error message', () => {
    expect(getThresholdDraftError()).toBe(
      'Use a whole number from -365 to 730.'
    );
  });

  it('serializes normalized arrays to csv', () => {
    expect(thresholdsToCsv([1, 30, 14])).toBe('30,14,1');
  });

  it('compares normalized threshold lists', () => {
    expect(thresholdsEqual('30,14,7', [30, 7, 14])).toBe(true);
    expect(thresholdsEqual('30,14,7', [30, 14, 7, 1])).toBe(false);
  });

  it('describes group inherit vs override state', () => {
    expect(
      getGroupThresholdInheritHint(DEFAULT_ALERT_THRESHOLDS, DEFAULT_ALERT_THRESHOLDS)
    ).toBe('Matches workspace defaults. Saving without changes keeps inheritance.');
    expect(getGroupThresholdInheritHint('14,7', DEFAULT_ALERT_THRESHOLDS)).toBe(
      'Differs from workspace defaults. Saving stores a group override.'
    );
  });

  it('resolves group editor and save override state', () => {
    expect(groupThresholdsCsvForEditor([7, 14], '30,14,7,1,0')).toBe('14,7');
    expect(
      groupThresholdsCsvForEditor(undefined, DEFAULT_ALERT_THRESHOLDS)
    ).toBe('30,14,7,1,0');
    expect(
      groupThresholdsCsvForEditor(undefined, [...DEFAULT_ALERT_THRESHOLDS, -1])
    ).toBe('30,14,7,1,0,-1');
    expect(
      groupThresholdsCsvForEditor(
        DEFAULT_ALERT_THRESHOLDS,
        [...DEFAULT_ALERT_THRESHOLDS, -1]
      )
    ).toBe('30,14,7,1,0');
    expect(
      groupHasThresholdOverride(DEFAULT_ALERT_THRESHOLDS, [
        ...DEFAULT_ALERT_THRESHOLDS,
        -1,
      ])
    ).toBe(true);
    expect(
      groupHasThresholdOverride(undefined, DEFAULT_ALERT_THRESHOLDS)
    ).toBe(false);
    expect(
      groupThresholdsOverrideForSave('14,7', DEFAULT_ALERT_THRESHOLDS)
    ).toEqual([14, 7]);
    expect(
      groupThresholdsOverrideForSave(
        DEFAULT_ALERT_THRESHOLDS,
        DEFAULT_ALERT_THRESHOLDS
      )
    ).toBeNull();
  });
});
