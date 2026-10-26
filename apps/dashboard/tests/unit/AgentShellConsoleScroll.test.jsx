import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import AgentShellConsole from '../../src/components/certops/AgentShellConsole.jsx';

const page = seq => ({
  items: [{ claimId: 'claim', attempt: 1, seq, message: `Output ${seq}` }],
  nextCursor: `cursor-${seq}`,
  hasMore: false,
  logsComplete: false,
  linesVisible: true,
  streams: [{ claimId: 'claim', attempt: 1, status: 'streaming' }],
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('live agent output scroll ownership', () => {
  it.each(['following', 'reading', 'collapsed'])(
    'polls without scrolling the wizard or stealing focus while %s',
    async mode => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      // scrollIntoView also moves the enclosing wizard/page in a real browser.
      const ancestorScroll = vi
        .spyOn(Element.prototype, 'scrollIntoView')
        .mockImplementation(() => {});
      const fetcher = vi
        .fn()
        .mockResolvedValueOnce(page(1))
        .mockResolvedValue(page(2));
      render(
        <ChakraProvider>
          <DashboardThemeProvider>
            <button>Continue setup</button>
            <AgentShellConsole
              workspaceId='ws'
              jobId='job'
              fetcher={fetcher}
              pollMs={1000}
              collapsible
            />
          </DashboardThemeProvider>
        </ChakraProvider>
      );
      await screen.findByText(/Output 1/);
      const log = screen.getByRole('log');
      Object.defineProperties(log, {
        scrollHeight: { configurable: true, value: 900 },
        clientHeight: { configurable: true, value: 200 },
      });
      log.scrollTop = mode === 'reading' ? 123 : 700;
      fireEvent.scroll(log);
      if (mode === 'collapsed')
        fireEvent.click(
          screen.getByRole('button', { name: 'Collapse output' })
        );
      const next = screen.getByRole('button', { name: 'Continue setup' });
      next.focus();
      const originalLog = log;
      Object.defineProperty(log, 'scrollHeight', { value: 1100 });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1100);
      });
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(screen.getByRole('log', { hidden: true })).toBe(originalLog);
      expect(ancestorScroll).not.toHaveBeenCalled();
      expect(next).toHaveFocus();
      expect(log.scrollTop).toBe(
        mode === 'following' ? 1100 : mode === 'reading' ? 123 : 700
      );
    }
  );
});
