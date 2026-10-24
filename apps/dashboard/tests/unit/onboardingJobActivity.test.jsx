import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const api = vi.hoisted(() => ({
  getJob: vi.fn(),
  listJobLog: vi.fn(),
  listJobEvidence: vi.fn(),
  listAgentJobLog: vi.fn(),
}));
vi.mock('../../src/components/certops/certopsJobsApi.js', () => api);
vi.mock('../../src/components/certops/certopsJobsApi', () => api);

import JobActivity, {
  JobTimelineList,
  hideSecretLine,
} from '../../src/components/onboarding/JobActivity.jsx';

const wrap = ui =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>{ui}</DashboardThemeProvider>
    </ChakraProvider>
  );

const doneJob = {
  id: 'j1',
  status: 'succeeded',
  createdAt: '2026-10-21T21:38:55.083Z',
  startedAt: '2026-10-21T21:39:06.529Z',
  completedAt: '2026-10-21T21:39:11.820Z',
};
const agentPage = {
  items: [
    {
      claimId: 'c',
      attempt: 1,
      seq: 1,
      level: 'info',
      message: 'ACME order succeeded',
      ts: '2026-10-21T21:39:11.104Z',
    },
  ],
  hasMore: false,
  nextCursor: 'n',
  logsComplete: true,
  jobStatus: 'succeeded',
  linesVisible: true,
  streams: [{ claimId: 'c', attempt: 1, status: 'final' }],
};

beforeEach(() => {
  api.getJob.mockReset().mockResolvedValue({ job: doneJob });
  api.listJobLog.mockReset().mockResolvedValue({ items: [], pagination: {} });
  api.listJobEvidence
    .mockReset()
    .mockResolvedValue({ items: [], pagination: {} });
  api.listAgentJobLog.mockReset().mockResolvedValue(agentPage);
});
afterEach(() => vi.useRealTimers());

describe('JobTimelineList', () => {
  it('is an ordered list with one item per event, with its time and status', () => {
    wrap(
      <JobTimelineList
        events={[
          {
            id: 'a',
            at: '2026-10-21T21:39:06.000Z',
            label: 'Picked up by the agent',
            status: 'done',
          },
          {
            id: 'b',
            at: '2026-10-21T21:39:11.000Z',
            label: 'Finished: Failed',
            detail: 'boom',
            status: 'failed',
          },
        ]}
      />
    );
    const list = screen.getByRole('list', { name: 'Job timeline' });
    expect(list.tagName).toBe('OL');
    const items = screen.getAllByTestId('timeline-event');
    expect(items).toHaveLength(2);
    expect(items[1]).toHaveAttribute('data-status', 'failed');
    expect(screen.getByText('boom')).toBeVisible();
    expect(items[0].querySelector('time')).toHaveAttribute(
      'datetime',
      '2026-10-21T21:39:06.000Z'
    );
    expect(screen.getByText('Failed')).toBeVisible();
  });

  it('has an empty state', () => {
    wrap(<JobTimelineList events={[]} />);
    expect(screen.getByTestId('timeline-empty')).toBeVisible();
  });

  it('hides a detail that looks like a credential', () => {
    wrap(
      <JobTimelineList
        events={[
          { id: 'x', at: null, label: 'Event', detail: 'AKIAABCDEFGHIJKLMNOP' },
        ]}
      />
    );
    expect(screen.queryByText(/AKIA/)).toBeNull();
    expect(screen.getByText(/line hidden/)).toBeVisible();
  });
});

describe('hideSecretLine', () => {
  it('passes normal text and hides credentials', () => {
    expect(hideSecretLine('deploy succeeded')).toBe('deploy succeeded');
    expect(hideSecretLine('x hvs.CAESIabc')).toMatch(/hidden/);
    expect(hideSecretLine('-----BEGIN RSA PRIVATE KEY-----')).toMatch(/hidden/);
  });
});

describe('JobActivity', () => {
  it('shows the timeline from the real job and the terminal panel', async () => {
    wrap(<JobActivity workspaceId='ws' jobId='j1' />);
    expect(await screen.findByText('Request created')).toBeVisible();
    expect(screen.getByText('Picked up by the agent')).toBeVisible();
    expect(screen.getByText('Finished: Succeeded')).toBeVisible();
    // The ACME line from the agent output became a timeline row too.
    expect(await screen.findByText('Order validated')).toBeVisible();
    expect(screen.getByRole('log', { name: 'Agent output' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Copy output' })).toBeVisible();
  });

  it('shows a loading state, then an error that retries', async () => {
    api.getJob.mockRejectedValue(new Error('network down'));
    wrap(<JobActivity workspaceId='ws' jobId='j1' />);
    expect(await screen.findByTestId('job-activity-error')).toHaveTextContent(
      /network down/
    );
  });

  it('keeps polling a running job and stops once it is final', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    api.getJob
      .mockResolvedValueOnce({ job: { ...doneJob, status: 'running' } })
      .mockResolvedValue({ job: doneJob });
    wrap(<JobActivity workspaceId='ws' jobId='j1' showOutput={false} />);
    await screen.findByText(/Running on the agent/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_500);
    });
    await waitFor(() =>
      expect(screen.getByText('Finished: Succeeded')).toBeVisible()
    );
    const calls = api.getJob.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000);
    });
    expect(api.getJob.mock.calls.length).toBe(calls);
  });

  it('notes when the event list is truncated', async () => {
    api.listJobLog.mockResolvedValue({
      items: [
        { id: 'l', eventType: 'job.created', createdAt: doneJob.createdAt },
      ],
      pagination: { limit: 1, total: 5 },
    });
    wrap(<JobActivity workspaceId='ws' jobId='j1' showOutput={false} />);
    expect(await screen.findByTestId('timeline-truncated')).toHaveTextContent(
      /Showing 1 of 5 events/
    );
  });

  it('can hide the terminal panel', async () => {
    wrap(<JobActivity workspaceId='ws' jobId='j1' showOutput={false} />);
    await screen.findByText('Request created');
    expect(screen.queryByRole('log')).toBeNull();
  });

  it('reads nothing without a job id', () => {
    wrap(<JobActivity workspaceId='ws' jobId='' />);
    expect(api.getJob).not.toHaveBeenCalled();
  });
});
