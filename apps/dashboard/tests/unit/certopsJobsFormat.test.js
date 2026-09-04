import { describe, it, expect } from 'vitest';

import {
  eventTypeLabel,
  hasRedactionMarkers,
  jobStatusLabel,
  jobStatusScheme,
  reconciliationAdvisoryText,
  redactionCount,
} from '../../src/components/certops/certopsJobsFormat';

describe('jobStatusLabel / jobStatusScheme', () => {
  it('labels and colors a job stuck needing manual reconciliation', () => {
    expect(jobStatusLabel('orphaned_unknown_effect')).toBe(
      'Needs reconciliation'
    );
    expect(jobStatusScheme('orphaned_unknown_effect')).toBe('red');
  });

  it('falls back to the raw status and gray for a status not yet mapped', () => {
    // dry_run_complete is a real status (same migration as
    // orphaned_unknown_effect) that hits the same unmapped fallback -
    // documents the gap rather than fixing it.
    expect(jobStatusLabel('dry_run_complete')).toBe('dry_run_complete');
    expect(jobStatusScheme('dry_run_complete')).toBe('gray');
  });
});

describe('reconciliationAdvisoryText', () => {
  it('returns the base sentence when no reason is given', () => {
    expect(reconciliationAdvisoryText(null)).toBe(
      "This job's side effects could not be confirmed and need manual review."
    );
    expect(reconciliationAdvisoryText(undefined)).toBe(
      "This job's side effects could not be confirmed and need manual review."
    );
  });

  it('appends the reason slug when one is given', () => {
    expect(
      reconciliationAdvisoryText(
        'lease_expired_after_side_effect_window_agent_unresponsive'
      )
    ).toBe(
      "This job's side effects could not be confirmed and need manual review (reason: lease_expired_after_side_effect_window_agent_unresponsive)."
    );
  });
});

describe('eventTypeLabel', () => {
  it('labels the approval decision event types', () => {
    expect(eventTypeLabel('approval.granted')).toBe('Approval granted');
    expect(eventTypeLabel('approval.rejected')).toBe('Approval rejected');
    expect(eventTypeLabel('approval.invalidated')).toBe(
      'Approval invalidated'
    );
  });

  it('falls back to the raw type string for an unmapped event type', () => {
    expect(eventTypeLabel('job.some_future_event_type_v9')).toBe(
      'job.some_future_event_type_v9'
    );
  });
});

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
      redactionCount({
        redaction: { applied: true, count: 5 },
        redactionCount: 1,
      })
    ).toBe(5);
  });

  it('returns 0 when no count is recorded', () => {
    expect(redactionCount({})).toBe(0);
    expect(redactionCount({ redaction: { applied: true } })).toBe(0);
    expect(redactionCount(null)).toBe(0);
  });
});
