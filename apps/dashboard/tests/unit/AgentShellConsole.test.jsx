import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import AgentShellConsole, {
  deliveryLabel,
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

function line(seq, message) {
  return { claimId: 'claim-1', attempt: 1, seq, message };
}

const streaming = [{ claimId: 'claim-1', attempt: 1, status: 'streaming', streamingEnabled: true }];
const finalStreams = [{ claimId: 'claim-1', attempt: 1, status: 'final', streamingEnabled: true }];

afterEach(() => {
  vi.useRealTimers();
});

describe('AgentShellConsole', () => {
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
        items: [line(2, 'ACME order succeeded')],
        nextCursor: 'c2',
        hasMore: false,
        logsComplete: true,
        streams: finalStreams,
        storageEnabled: true,
      });

    renderConsole(fetcher);
    await screen.findByText('Starting renew');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1100);
    });
    await screen.findByText('ACME order succeeded');

    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0][2].cursor).toBeUndefined();
    expect(fetcher.mock.calls[1][2].cursor).toBe('c1');
    expect(screen.getAllByText('Starting renew')).toHaveLength(1);
    expect(screen.getByRole('status')).toHaveTextContent('Stream complete');

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
        streams: finalStreams,
        storageEnabled: true,
      });

    renderConsole(fetcher);
    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(
        'Could not load agent output'
      )
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_100);
    });
    await screen.findByText('back');
    expect(screen.getByRole('status')).toHaveTextContent('Stream complete');
  });

  it('labels a viewer response without showing lines', () => {
    expect(
      deliveryLabel({ items: [], linesVisible: false, streams: [], storageEnabled: true })
    ).toBe('You need manager access to view agent output');
  });
});
