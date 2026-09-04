import { describe, it, expect } from 'vitest';

import {
  eventTypeLabel,
  hasRedactionMarkers,
  jobListAdvisory,
  jobStatusLabel,
  jobStatusScheme,
  pendingReasonLabel,
  reconciliationAdvisoryText,
  staleReasonLabel,
  redactionCount,
  sameOperatorMessage,
  userFacingName,
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

describe('pendingReasonLabel / jobListAdvisory', () => {
  it('maps known pending codes to a short scan label', () => {
    expect(
      pendingReasonLabel({
        code: 'operation_unsupported',
        message: 'The assigned agent has declared support for issue, deploy.',
      })
    ).toBe('Agent cannot run this job');
    expect(
      staleReasonLabel({
        code: 'reconciliation_stale_job_pending',
        message:
          'The job for this change has been waiting to be claimed by the target agent for too long.',
      })
    ).toBe('Claim timed out');
  });

  it('shows Needs review on the closed row and keeps the full text as detail', () => {
    expect(
      jobListAdvisory({
        needsOperatorReconciliation: true,
        errorMessage: 'Lease expired after renew; side effects unknown',
      })
    ).toEqual({
      label: 'Needs review',
      detail: 'Lease expired after renew; side effects unknown',
      tone: 'red',
    });
  });

  it('does not surface an ordinary failed job on the closed row', () => {
    expect(
      jobListAdvisory({
        status: 'failed',
        needsOperatorReconciliation: false,
        errorMessage: 'Deploy target rejected the certificate',
      })
    ).toBeNull();
  });
});

describe('sameOperatorMessage', () => {
  it('treats identical or contained strings as the same explanation', () => {
    expect(
      sameOperatorMessage(
        'Executor did not respond in time.',
        'Executor did not respond in time.'
      )
    ).toBe(true);
    expect(
      sameOperatorMessage(
        'Job failed: Executor did not respond in time.',
        'Executor did not respond in time.'
      )
    ).toBe(true);
    expect(sameOperatorMessage('offline', 'agent retired')).toBe(false);
  });
});

describe('eventTypeLabel', () => {
  it('labels the approval decision event types', () => {
    expect(eventTypeLabel('approval.granted')).toBe('Approval granted');
    expect(eventTypeLabel('approval.rejected')).toBe('Approval rejected');
    expect(eventTypeLabel('approval.invalidated')).toBe('Approval invalidated');
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

describe('userFacingName', () => {
  it('prefers a display name over the raw user id', () => {
    expect(userFacingName(9, 'Alice Admin')).toBe('Alice Admin');
    expect(userFacingName('user-42', '  Bob  ')).toBe('Bob');
  });

  it('falls back to the user id when no display name is available', () => {
    expect(userFacingName(9, null)).toBe('9');
    expect(userFacingName('user-42', '   ')).toBe('user-42');
    expect(userFacingName(null, null)).toBe('');
  });
});
