import { describe, expect, it } from 'vitest';
import { failedPreflightMessage } from '../../src/components/certops/adcsPreflightJob.js';

describe('failedPreflightMessage', () => {
  it('says nothing while the job is still running or has succeeded', () => {
    expect(failedPreflightMessage(null)).toBe('');
    expect(failedPreflightMessage({ status: 'running' })).toBe('');
    expect(failedPreflightMessage({ status: 'succeeded' })).toBe('');
  });

  it('explains an agent refusal that happened before any CA contact', () => {
    const text = failedPreflightMessage({
      status: 'rejected',
      errorCode: 'issuer_not_allowlisted',
    });
    expect(text).toMatch(/before it contacted the CA/);
    expect(text).toMatch(/enrollment rule/);
    expect(text).toMatch(/restart TokenTimerAgent/);
  });

  it('reads the refusal reason from the result metadata when there is no error code', () => {
    const text = failedPreflightMessage({
      status: 'rejected',
      resultMetadata: { rejectionReason: 'issuer_not_allowlisted' },
    });
    expect(text).toMatch(/enrollment rule/);
  });

  it('passes through the code and message of any other failure', () => {
    expect(
      failedPreflightMessage({
        status: 'failed',
        errorCode: 'AGENT_RESULT_FAILED',
        errorMessage: 'boom',
      })
    ).toBe('The agent could not run the check (AGENT_RESULT_FAILED). boom');
  });
});
