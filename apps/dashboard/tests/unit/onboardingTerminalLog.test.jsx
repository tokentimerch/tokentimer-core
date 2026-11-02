import { describe, expect, it, vi, afterEach } from 'vitest';
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import AgentShellConsole from '../../src/components/certops/AgentShellConsole.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

vi.mock('../../src/components/certops/certopsJobsApi', () => ({
  listAgentJobLog: vi.fn(),
}));

function mount(fetcher, props = {}) {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <AgentShellConsole
          workspaceId='ws-1'
          jobId='job-1'
          fetcher={fetcher}
          title='Agent output'
          {...props}
        />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

const line = (seq, message, extra = {}) => ({
  claimId: 'c1',
  attempt: 1,
  seq,
  level: 'info',
  step: 'acme',
  message,
  ts: `2026-10-21T21:39:0${seq}.000Z`,
  redacted: false,
  ...extra,
});

const finished = items => ({
  items,
  hasMore: false,
  nextCursor: 'n',
  logsComplete: true,
  jobStatus: 'succeeded',
  linesVisible: true,
  storageEnabled: true,
  streams: [{ claimId: 'c1', attempt: 1, status: 'final' }],
});

afterEach(() => {
  vi.useRealTimers();
});

describe('AgentShellConsole presentation options', () => {
  it('is a labelled polite log region a keyboard can reach', async () => {
    mount(vi.fn().mockResolvedValue(finished([line(1, 'Starting renew')])));
    const log = await screen.findByRole('log', { name: 'Agent output' });
    expect(log).toHaveAttribute('aria-live', 'polite');
    expect(log).toHaveAttribute('tabindex', '0');
    expect(within(log).getByText(/Starting renew/)).toBeInTheDocument();
  });

  it('shows line numbers only when asked', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(finished([line(1, 'one'), line(2, 'two')]));
    const { unmount } = mount(fetcher);
    await screen.findByText(/one/);
    expect(screen.queryAllByTestId('shell-line-number')).toHaveLength(0);
    unmount();
    mount(fetcher, { lineNumbers: true });
    await screen.findByText(/two/);
    const numbers = screen.getAllByTestId('shell-line-number');
    expect(numbers.map(n => n.textContent)).toEqual(['1', '2']);
    expect(numbers[0]).toHaveAttribute('aria-hidden', 'true');
  });

  it('copies the output without the line numbers', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    mount(
      vi
        .fn()
        .mockResolvedValue(finished([line(1, 'first'), line(2, 'second')])),
      { copyable: true, lineNumbers: true }
    );
    await screen.findByText(/second/);
    fireEvent.click(screen.getByRole('button', { name: 'Copy output' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const copied = writeText.mock.calls[0][0];
    expect(copied.split('\n')).toHaveLength(2);
    expect(copied).toMatch(/tokentimer-agent: first/);
    expect(copied).not.toMatch(/^1 /);
  });

  it('offers no copy button without output or without the option', async () => {
    mount(vi.fn().mockResolvedValue(finished([line(1, 'x')])));
    await screen.findByText(/x/);
    expect(screen.queryByRole('button', { name: 'Copy output' })).toBeNull();
  });

  it('collapses and expands the output', async () => {
    mount(vi.fn().mockResolvedValue(finished([line(1, 'visible line')])), {
      collapsible: true,
    });
    await screen.findByText(/visible line/);
    const toggle = screen.getByRole('button', { name: 'Collapse output' });
    expect(toggle).toHaveAttribute('aria-expanded', 'true');
    fireEvent.click(toggle);
    const expand = screen.getByRole('button', { name: 'Expand output' });
    expect(expand).toHaveAttribute('aria-expanded', 'false');
    expect(screen.getByRole('log', { hidden: true })).not.toBeVisible();
    fireEvent.click(expand);
    expect(screen.getByRole('log')).toBeVisible();
  });

  it('hides a line that looks like a credential, on screen and in the copy', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, { clipboard: { writeText } });
    const guard = msg =>
      /ttboot_/.test(msg) ? '[line hidden: it looked like a credential]' : msg;
    mount(
      vi
        .fn()
        .mockResolvedValue(
          finished([line(1, 'token ttboot_abc123'), line(2, 'fine')])
        ),
      { copyable: true, lineGuard: guard }
    );
    await screen.findByText(/fine/);
    expect(screen.queryByText(/ttboot_abc123/)).toBeNull();
    expect(screen.getByText(/line hidden/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Copy output' }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    expect(writeText.mock.calls[0][0]).not.toMatch(/ttboot_/);
  });

  it('says when values were removed before storage', async () => {
    mount(
      vi
        .fn()
        .mockResolvedValue(
          finished([line(1, 'token [REDACTED]', { redacted: true })])
        )
    );
    expect(await screen.findByTestId('shell-redaction-note')).toHaveTextContent(
      /removed before this output was stored/
    );
  });

  it('shows the truncation note when the limit was reached', async () => {
    const payload = finished([line(1, 'only line')]);
    payload.streams = [
      { claimId: 'c1', attempt: 1, status: 'final', truncated: true },
    ];
    mount(vi.fn().mockResolvedValue(payload));
    expect(await screen.findByText('Log limit reached')).toBeInTheDocument();
  });

  it('stops polling once the output is complete when asked to', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetcher = vi.fn().mockResolvedValue(finished([line(1, 'done')]));
    mount(fetcher, { stopWhenComplete: true });
    await screen.findByText(/done/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000);
    });
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it('keeps revalidating by default', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const fetcher = vi.fn().mockResolvedValue(finished([line(1, 'done')]));
    mount(fetcher);
    await screen.findByText(/done/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(16_000);
    });
    expect(fetcher.mock.calls.length).toBeGreaterThan(1);
  });

  it('keeps polling while a job is still running', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const running = {
      items: [line(1, 'working')],
      hasMore: false,
      nextCursor: 'n',
      logsComplete: false,
      jobStatus: 'running',
      linesVisible: true,
      streams: [{ claimId: 'c1', attempt: 1, status: 'streaming' }],
    };
    const fetcher = vi.fn().mockResolvedValue(running);
    mount(fetcher, { stopWhenComplete: true });
    await screen.findByText(/working/);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3_000);
    });
    expect(fetcher.mock.calls.length).toBeGreaterThan(2);
  });

  it('reports its lines to the parent', async () => {
    const onItems = vi.fn();
    mount(vi.fn().mockResolvedValue(finished([line(1, 'hello')])), {
      onItems,
    });
    await screen.findByText(/hello/);
    await waitFor(() =>
      expect(onItems).toHaveBeenLastCalledWith([
        expect.objectContaining({ message: 'hello' }),
      ])
    );
  });
});
