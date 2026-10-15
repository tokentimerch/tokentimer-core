import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import AgentShellConsole, {
  deliveryLabel,
  formatConsoleLine,
  toneForLine,
} from '../../src/components/certops/AgentShellConsole.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

vi.mock('../../src/components/certops/certopsJobsApi', () => ({
  listAgentJobLog: vi.fn(),
}));

function renderConsole(fetcher, props = {}) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AgentShellConsole
          workspaceId='ws-1'
          jobId='job-1'
          fetcher={fetcher}
          {...props}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

function line(seq, message, overrides = {}) {
  return {
    claimId: 'claim-1',
    attempt: 1,
    seq,
    message,
    ts: `2026-10-06T08:43:5${seq}.000Z`,
    ...overrides,
  };
}

const streaming = [
  {
    claimId: 'claim-1',
    attempt: 1,
    status: 'streaming',
    streamingEnabled: true,
  },
];
const finalStreams = [
  { claimId: 'claim-1', attempt: 1, status: 'final', streamingEnabled: true },
];

afterEach(() => {
  vi.useRealTimers();
});

describe('AgentShellConsole', () => {
  it.each(['status-only', 'forbidden', 'unauthenticated'])(
    'revalidates completed output and withdraws cached text on %s',
    async mode => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const completed = {
        items: [line(1, 'Completed permitted output')],
        nextCursor: 'completed-cursor',
        hasMore: false,
        logsComplete: true,
        jobStatus: 'failed',
        streams: finalStreams,
        linesVisible: true,
      };
      const fetcher = vi.fn().mockResolvedValueOnce(completed);
      if (mode === 'status-only')
        fetcher.mockResolvedValue({
          ...completed,
          items: [],
          linesVisible: false,
        });
      else
        fetcher.mockRejectedValue({
          response: { status: mode === 'forbidden' ? 403 : 401 },
        });
      const onComplete = vi.fn();
      const view = renderConsole(fetcher, {
        onComplete,
        seedLines: ['Previously authorized seed'],
      });
      await screen.findByText(/Completed permitted output/);
      expect(screen.getByText('Failed')).toBeInTheDocument();
      expect(screen.queryByText('Succeeded')).not.toBeInTheDocument();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(14_000);
      });
      expect(fetcher).toHaveBeenCalledTimes(1);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1_100);
      });
      await waitFor(() =>
        expect(document.querySelectorAll('[data-shell-line]')).toHaveLength(0)
      );
      expect(
        screen.queryByText(/Previously authorized seed/)
      ).not.toBeInTheDocument();
      expect(fetcher.mock.calls[1][2].cursor).toBe('completed-cursor');
      expect(onComplete).toHaveBeenCalledTimes(1);
      const callCount = fetcher.mock.calls.length;
      view.unmount();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(30_000);
      });
      expect(fetcher).toHaveBeenCalledTimes(callCount);
    }
  );

  it('reloads discarded completed history after permission restoration without repeating completion', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const completed = {
      items: [line(1, 'Retained completed history')],
      nextCursor: 'c1',
      hasMore: false,
      logsComplete: true,
      jobStatus: 'succeeded',
      streams: finalStreams,
      linesVisible: true,
    };
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(completed)
      .mockResolvedValueOnce({ ...completed, items: [], linesVisible: false })
      .mockResolvedValue(completed);
    const onComplete = vi.fn();
    renderConsole(fetcher, { onComplete });
    await screen.findByText(/Retained completed history/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_100);
    });
    expect(document.querySelectorAll('[data-shell-line]')).toHaveLength(0);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_100);
    });
    await screen.findByText(/Retained completed history/);
    expect(fetcher.mock.calls[2][2].cursor).toBeUndefined();
    expect(document.querySelectorAll('[data-shell-line]')).toHaveLength(1);
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it.each(['status-only', 'forbidden'])(
    'withdraws cached text after an authoritative %s response',
    async mode => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const fetcher = vi.fn().mockResolvedValueOnce({
        items: [line(1, 'Previously authorized output')],
        nextCursor: 'c1',
        hasMore: false,
        logsComplete: false,
        streams: streaming,
        linesVisible: true,
        storageEnabled: true,
      });
      if (mode === 'forbidden')
        fetcher.mockRejectedValue({ response: { status: 403 } });
      else
        fetcher.mockResolvedValue({
          items: [],
          streams: streaming,
          nextCursor: 'c1',
          hasMore: false,
          logsComplete: false,
          linesVisible: false,
        });
      renderConsole(fetcher, { seedLines: ['Previously authorized seed'] });
      await screen.findByText(/Previously authorized output/);
      await act(async () => {
        await vi.advanceTimersByTimeAsync(800);
      });
      await waitFor(() =>
        expect(
          screen.queryByText(/Previously authorized output/)
        ).not.toBeInTheDocument()
      );
      expect(document.querySelectorAll('[data-shell-line]')).toHaveLength(0);
      expect(
        screen.queryByText(/Previously authorized seed/)
      ).not.toBeInTheDocument();
    }
  );

  it('renders the POC terminal chrome and formats agent lines', async () => {
    const fetcher = vi.fn().mockResolvedValue({
      items: [line(1, 'Starting renew')],
      nextCursor: 'c1',
      hasMore: false,
      logsComplete: false,
      streams: streaming,
      storageEnabled: true,
    });

    renderConsole(fetcher);
    await screen.findByText(/tokentimer-agent: Starting renew/);
    expect(screen.getByText('Agent output')).toBeInTheDocument();
    expect(screen.getByText(/HOST\s+tokentimer-agent/)).toBeInTheDocument();
    expect(screen.getByText('Streaming')).toBeInTheDocument();
    expect(screen.queryByText('job-1')).not.toBeInTheDocument();
  });

  it('colors start white, execution blue, success green, failure red', () => {
    expect(toneForLine({ status: 'info', msg: 'Starting renew' })).toBe(
      'neutral'
    );
    expect(
      toneForLine({ status: 'info', msg: 'deploying certificate to /x' })
    ).toBe('info');
    expect(toneForLine({ status: 'info', msg: 'ACME order succeeded' })).toBe(
      'success'
    );
    expect(
      toneForLine({ status: 'error', msg: 'deploy failed: permission denied' })
    ).toBe('danger');
  });

  it('keeps draining after logsComplete when the page cap leaves hasMore', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const pages = Array.from({ length: 6 }, (_, i) => ({
      items: [line(i + 1, `page ${i + 1}`)],
      nextCursor: `c${i + 1}`,
      hasMore: i < 5,
      logsComplete: true,
      jobStatus: 'succeeded',
      streams: finalStreams,
      storageEnabled: true,
    }));
    const fetcher = vi.fn();
    for (const page of pages) fetcher.mockResolvedValueOnce(page);

    renderConsole(fetcher);
    await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(5));
    await screen.findByText(/page 5/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    await screen.findByText(/page 6/);
    expect(fetcher).toHaveBeenCalledTimes(6);
    expect(fetcher.mock.calls[5][2].cursor).toBe('c5');
    expect(screen.getByText('Succeeded')).toBeInTheDocument();
  });

  it('polls from the last cursor and appends only new lines', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce({
        items: [line(1, 'Starting renew')],
        nextCursor: 'c1',
        hasMore: false,
        logsComplete: false,
        streams: streaming,
        storageEnabled: true,
      })
      .mockResolvedValueOnce({
        items: [line(2, 'ACME order succeeded', { level: 'info' })],
        nextCursor: 'c2',
        hasMore: false,
        logsComplete: true,
        jobStatus: 'succeeded',
        streams: finalStreams,
        storageEnabled: true,
      });

    renderConsole(fetcher);
    await screen.findByText(/Starting renew/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1100);
    });
    await screen.findByText(/ACME order succeeded/);

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0][2].cursor).toBeUndefined();
    expect(fetcher.mock.calls[1][2].cursor).toBe('c1');
    expect(screen.getAllByText(/Starting renew/)).toHaveLength(1);
    expect(screen.getByText('Succeeded')).toBeInTheDocument();

    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('shows an error state and keeps retrying', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetcher = vi
      .fn()
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce({
        items: [line(1, 'back')],
        nextCursor: 'c1',
        hasMore: false,
        logsComplete: true,
        jobStatus: 'succeeded',
        streams: finalStreams,
        storageEnabled: true,
      });

    renderConsole(fetcher);
    await waitFor(() =>
      expect(
        screen.getAllByText(/Could not load agent output/).length
      ).toBeGreaterThan(0)
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_100);
    });
    await screen.findByText(/tokentimer-agent: back/);
    expect(screen.getByText('Succeeded')).toBeInTheDocument();
  });

  it('labels a viewer response with delivery status, not only Restricted', () => {
    expect(
      deliveryLabel({
        items: [],
        linesVisible: false,
        streams: streaming,
        storageEnabled: true,
        logsComplete: false,
      })
    ).toBe('Output is streaming (log text requires manager access)');
    expect(
      deliveryLabel({
        items: [],
        linesVisible: false,
        streams: finalStreams,
        storageEnabled: true,
        logsComplete: true,
        jobStatus: 'failed',
      })
    ).toBe('No agent output recorded (log text requires manager access)');
  });

  it('does not claim a finished stream when a terminal job has no retained lines', () => {
    expect(
      deliveryLabel({
        items: [],
        linesVisible: true,
        streams: [],
        storageEnabled: true,
        logsComplete: true,
        jobStatus: 'succeeded',
      })
    ).toBe('No agent output recorded');
    expect(
      deliveryLabel({
        items: [],
        linesVisible: true,
        streams: finalStreams,
        storageEnabled: true,
        logsComplete: true,
        jobStatus: 'succeeded',
      })
    ).toBe('No agent output recorded');
  });

  it('badges abandoned stream with succeeded job as Incomplete, not Failed', async () => {
    const fetcher = vi.fn().mockResolvedValue({
      items: [line(1, 'renew complete')],
      nextCursor: 'c1',
      hasMore: false,
      logsComplete: true,
      jobStatus: 'succeeded',
      streams: [
        {
          claimId: 'claim-old',
          attempt: 1,
          status: 'abandoned',
          streamingEnabled: true,
        },
      ],
      storageEnabled: true,
    });
    renderConsole(fetcher);
    await screen.findByText('Incomplete');
    expect(screen.queryByText('Failed')).not.toBeInTheDocument();
    expect(screen.queryByText('Succeeded')).not.toBeInTheDocument();
  });

  it('badges failed jobs as Failed even when the log stream is final', () => {
    const fetcher = vi.fn().mockResolvedValue({
      items: [line(1, 'deploy failed')],
      nextCursor: 'c1',
      hasMore: false,
      logsComplete: true,
      jobStatus: 'failed',
      streams: finalStreams,
      storageEnabled: true,
    });
    renderConsole(fetcher);
    return screen.findByText('Failed');
  });

  it('formats bare messages into the agent logger line shape', () => {
    expect(
      formatConsoleLine({
        message: 'Starting noop',
        ts: '2026-10-06T08:43:53.000Z',
        claimId: 'c',
        seq: 1,
      }).msg
    ).toBe('2026-10-06T08:43:53.000Z tokentimer-agent: Starting noop');
  });

  it('keeps repeated lines distinct when claim identifiers are redacted', () => {
    const event = {
      message: 'Starting noop',
      ts: '2026-10-06T08:43:53.000Z',
      attempt: 1,
      seq: 1,
    };
    expect(formatConsoleLine(event).id).not.toBe(
      formatConsoleLine({ ...event, seq: 2 }).id
    );
    expect(formatConsoleLine(event).id).not.toBe(
      formatConsoleLine({ ...event, attempt: 2 }).id
    );
    expect(formatConsoleLine(event).id).toBe(
      formatConsoleLine({ ...event }).id
    );
  });
});
