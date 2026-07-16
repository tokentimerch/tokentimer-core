import { describe, it, expect } from 'vitest';

import {
  hasRedactionMarkers,
  redactionCount,
} from '../../src/components/certops/certopsJobsFormat';

describe('hasRedactionMarkers', () => {
  it('recognizes the nested server-owned marker (exact backend shape)', () => {
    expect(
      hasRedactionMarkers({ redaction: { applied: true, count: 2 } })
    ).toBe(true);
  });

  it('recognizes the nested marker via count alone', () => {
    expect(hasRedactionMarkers({ redaction: { count: 3 } })).toBe(true);
  });

  it('does not flag a nested marker that was not applied', () => {
    expect(
      hasRedactionMarkers({ redaction: { applied: false, count: 0 } })
    ).toBe(false);
  });

  it('recognizes the flat legacy executor-path markers', () => {
    expect(hasRedactionMarkers({ redactionApplied: true })).toBe(true);
    expect(hasRedactionMarkers({ redactionCount: 2 })).toBe(true);
  });

  it('recognizes redacted status and boolean markers', () => {
    expect(hasRedactionMarkers({ status: 'redacted' })).toBe(true);
    expect(hasRedactionMarkers({ redacted: true })).toBe(true);
  });

  it('recognizes nested [REDACTED] literals in string values', () => {
    expect(
      hasRedactionMarkers({ detail: { note: 'secret was [REDACTED]' } })
    ).toBe(true);
  });

  it('returns false when neither shape is present', () => {
    expect(hasRedactionMarkers({})).toBe(false);
    expect(hasRedactionMarkers({ other: 'value' })).toBe(false);
    expect(hasRedactionMarkers(null)).toBe(false);
    expect(hasRedactionMarkers(undefined)).toBe(false);
  });
});

describe('redactionCount', () => {
  it('reads the nested metadata.redaction.count (backend shape)', () => {
    expect(redactionCount({ redaction: { applied: true, count: 2 } })).toBe(2);
  });

  it('falls back to the flat legacy metadata.redactionCount', () => {
    expect(redactionCount({ redactionCount: 4 })).toBe(4);
  });

  it('prefers the nested count when both shapes are present', () => {
    expect(
      redactionCount({ redaction: { applied: true, count: 5 }, redactionCount: 1 })
    ).toBe(5);
  });

  it('returns 0 when no count is recorded', () => {
    expect(redactionCount({})).toBe(0);
    expect(redactionCount({ redaction: { applied: true } })).toBe(0);
    expect(redactionCount(null)).toBe(0);
  });
});
