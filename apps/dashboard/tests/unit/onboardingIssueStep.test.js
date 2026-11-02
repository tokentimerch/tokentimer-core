import { describe, expect, it } from 'vitest';
import {
  canRequestIssue,
  issueView,
} from '../../src/components/onboarding/certopsIssueStep.jsx';

describe('issueView', () => {
  it('only calls a real succeeded job issued', () => {
    expect(issueView({ status: 'succeeded', mode: 'real' }).done).toBe(true);
    expect(
      issueView({ status: 'succeeded', mode: 'dry_run' }).done
    ).toBeUndefined();
    expect(
      issueView({ status: 'dry_run_complete', mode: 'dry_run' }).failed
    ).toBe(true);
  });

  it('keeps polling while the job is active', () => {
    for (const status of [
      'pending',
      'claimed',
      'running',
      'pending_approval',
    ]) {
      expect(issueView({ status, mode: 'real' }).active).toBe(true);
    }
  });

  it('never invites a retry after an unknown effect', () => {
    const v = issueView({ status: 'orphaned_unknown_effect', mode: 'real' });
    expect(v.noRetry).toBe(true);
    expect(v.failed).toBeUndefined();
  });

  it('offers a retry for failed or blocked jobs', () => {
    expect(issueView({ status: 'failed', mode: 'real' }).failed).toBe(true);
    expect(issueView({ status: 'blocked', mode: 'real' }).failed).toBe(true);
  });
});

describe('canRequestIssue', () => {
  const saved = {
    names: 'a.example.com',
    zone: 'example.com',
    dnsProvider: 'cloudflare',
    certPath: '/x.pem',
  };
  const agents = { live: 1, executionEnabled: true };
  const dryRun = { status: 'dry_run_complete' };

  it('passes when everything is in place', () => {
    expect(canRequestIssue({ agents, dryRun, saved }).ok).toBe(true);
  });

  it('names what is missing', () => {
    const r = canRequestIssue({ agents: { live: 0 }, dryRun: null, saved: {} });
    expect(r.ok).toBe(false);
    expect(r.missing).toEqual([
      'a live agent',
      'execution enabled',
      'a passing dry run',
      'the saved agent configuration',
    ]);
  });

  it('does not accept a dry run that is merely pending', () => {
    expect(
      canRequestIssue({ agents, dryRun: { status: 'pending' }, saved }).ok
    ).toBe(false);
  });
});
