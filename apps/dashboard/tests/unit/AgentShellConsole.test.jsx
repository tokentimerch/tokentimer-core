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

function renderConsole(fetcher) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AgentShellConsole workspaceId='ws-1' jobId='job-1' fetcher={fetcher} />
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
    expect(
      toneForLine({ status: 'info', msg: 'ACME order succeeded' })
    ).toBe('success');
    expect(
      toneForLine({ status: 'error', msg: 'deploy failed: permission denied' })
    ).toBe('danger');
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
    ).toBe('Stream complete (log text requires manager access)');
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
});
