import { describe, expect, it } from 'vitest';
import {
  buildJobTimeline,
  formatClock,
  isJobFinal,
} from '../../src/components/onboarding/jobTimeline.js';

// Shapes copied from a real finished issue job and its agent output.
const job = {
  id: '856f4a24',
  status: 'succeeded',
  createdAt: '2026-10-21T21:38:55.083Z',
  queuedAt: '2026-10-21T21:38:55.163Z',
  startedAt: '2026-10-21T21:39:06.529Z',
  completedAt: '2026-10-21T21:39:11.820Z',
  approvedAt: null,
  errorMessage: null,
};
const agentLines = [
  {
    seq: 1,
    ts: '2026-10-21T21:39:06.562Z',
    level: 'info',
    message:
      'passed signature/replay/clock/policy verification, starting execution',
  },
  {
    seq: 2,
    ts: '2026-10-21T21:39:06.673Z',
    level: 'info',
    message: 'starting ACME order (certbot) against https://ca.example/dir',
  },
  {
    seq: 3,
    ts: '2026-10-21T21:39:11.104Z',
    level: 'info',
    message: 'ACME order succeeded',
  },
  {
    seq: 4,
    ts: '2026-10-21T21:39:11.274Z',
    level: 'info',
    message: 'deploy succeeded at /etc/ssl/x.pem',
  },
  {
    seq: 5,
    ts: '2026-10-21T21:39:11.601Z',
    level: 'info',
    message: 'reload succeeded for service haproxy',
  },
  {
    seq: 6,
    ts: '2026-10-21T21:39:11.607Z',
    level: 'info',
    message: 'verify succeeded (fingerprint abc)',
  },
];
const evidence = [
  {
    id: 'e1',
    evidenceType: 'deployment.updated',
    observedAt: '2026-10-21T21:39:11.274Z',
    metadata: {},
  },
  {
    id: 'e2',
    evidenceType: 'validation.passed',
    observedAt: '2026-10-21T21:39:11.605Z',
    metadata: { summary: 'Served certificate matches' },
  },
];
const log = [
  {
    id: 'l1',
    eventType: 'job.completed',
    createdAt: job.completedAt,
    message: 'Agent reported result: succeeded',
  },
];

const labels = events => events.map(e => e.label);

describe('buildJobTimeline', () => {
  it('lists only what the server recorded, oldest first', () => {
    const events = buildJobTimeline({
      job,
      logEntries: log,
      evidence,
      agentLines,
    });
    expect(labels(events)).toEqual([
      'Request created',
      'Picked up by the agent',
      'Order validated',
      'Certificate written',
      'Deployment updated',
      'Service reloaded',
      'Validation passed',
      'Certificate verified',
      'Finished: Succeeded',
    ]);
    const times = events.map(e => new Date(e.at).getTime());
    expect(times).toEqual([...times].sort((a, b) => a - b));
    expect(events.every(e => e.status !== 'failed')).toBe(true);
  });

  it('does not invent steps that were never logged', () => {
    const events = buildJobTimeline({ job, agentLines: [] });
    expect(labels(events)).toEqual([
      'Request created',
      'Picked up by the agent',
      'Finished: Succeeded',
    ]);
    expect(labels(events).join(' ')).not.toMatch(/DNS|approved|reload/i);
  });

  it('shows the approval with who decided it', () => {
    const events = buildJobTimeline({
      job: {
        ...job,
        approvedAt: '2026-10-21T21:38:58.000Z',
        approvedByDisplayName: 'Ana Lopez',
      },
    });
    const approved = events.find(e => e.id === 'approved');
    expect(approved.detail).toBe('By Ana Lopez');
    expect(labels(events).indexOf('Approved')).toBe(1);
  });

  it('marks a failed job and carries its reason', () => {
    const events = buildJobTimeline({
      job: {
        ...job,
        status: 'failed',
        errorMessage: 'DNS record never appeared',
      },
      agentLines: [
        {
          seq: 1,
          ts: '2026-10-21T21:39:07.000Z',
          level: 'error',
          message: 'certbot exited with code 1',
        },
      ],
    });
    const finished = events[events.length - 1];
    expect(finished.status).toBe('failed');
    expect(finished.detail).toBe('DNS record never appeared');
    expect(events.find(e => e.label === 'Agent reported an error').status).toBe(
      'failed'
    );
  });

  it('ends with a waiting row while the job has not been picked up', () => {
    const events = buildJobTimeline({
      job: { id: 'j', status: 'pending', createdAt: job.createdAt },
    });
    const last = events[events.length - 1];
    expect(last.label).toBe('Waiting for an agent to pick it up');
    expect(last.status).toBe('waiting');
    expect(last.at).toBeNull();
  });

  it('says approval is pending', () => {
    const events = buildJobTimeline({
      job: { id: 'j', status: 'pending_approval', createdAt: job.createdAt },
    });
    expect(events[events.length - 1].label).toBe('Waiting for approval');
  });

  it('shows a running job as active', () => {
    const events = buildJobTimeline({
      job: {
        id: 'j',
        status: 'running',
        createdAt: job.createdAt,
        startedAt: job.startedAt,
      },
    });
    expect(events[events.length - 1].status).toBe('active');
  });

  it('treats a dry run as a success and a rejection as a failure', () => {
    const dry = buildJobTimeline({
      job: { ...job, status: 'dry_run_complete' },
    });
    expect(dry[dry.length - 1].status).toBe('done');
    const rejected = buildJobTimeline({ job: { ...job, status: 'rejected' } });
    expect(rejected[rejected.length - 1].status).toBe('failed');
  });

  it('returns nothing without a job', () => {
    expect(buildJobTimeline({})).toEqual([]);
    expect(buildJobTimeline({ job: null })).toEqual([]);
  });

  it('only lists the first line of each milestone', () => {
    const events = buildJobTimeline({
      job,
      agentLines: [
        ...agentLines,
        {
          seq: 7,
          ts: '2026-10-21T21:39:12.000Z',
          level: 'info',
          message: 'reload succeeded again',
        },
      ],
    });
    expect(labels(events).filter(l => l === 'Service reloaded')).toHaveLength(
      1
    );
  });
});

describe('job final states', () => {
  it.each([
    'succeeded',
    'failed',
    'rejected',
    'cancelled',
    'dry_run_complete',
    'orphaned_unknown_effect',
  ])('%s is final', status => expect(isJobFinal(status)).toBe(true));
  it.each([
    'pending_approval',
    'approved',
    'pending',
    'claimed',
    'running',
    undefined,
  ])('%s is not final', status => expect(isJobFinal(status)).toBe(false));
});

describe('formatClock', () => {
  it('formats a time with seconds and tolerates garbage', () => {
    expect(formatClock('2026-10-21T21:39:11.820Z')).toMatch(
      /\d{1,2}.*\d{2}.*\d{2}/
    );
    expect(formatClock('')).toBe('');
    expect(formatClock('not a date')).toBe('');
  });
});
