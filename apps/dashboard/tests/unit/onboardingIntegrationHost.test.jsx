import { useCallback, useMemo, useState } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';

import { IntegrationStep } from '../../src/components/onboarding/integrationStep.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

// The modal is stubbed: the step only cares when it opens and closes.
vi.mock('../../src/components/ImportTokensModal.jsx', () => ({
  default: ({ isOpen, onClose }) =>
    isOpen ? <button onClick={onClose}>close-modal</button> : null,
}));

const CAPABILITIES = {
  items: [
    { id: 'integrations.github', state: 'ready' },
    { id: 'autosync.github', state: 'ready' },
  ],
};

const connection = (id, extra = {}) => ({
  id,
  provider: 'github',
  name: 'github',
  enabled: true,
  frequency: 'daily',
  lastSyncAt: null,
  lastStatus: null,
  lastItems: null,
  failures: 0,
  running: false,
  nextSyncAt: '2030-01-02T09:00:00.000Z',
  ...extra,
});

const summaryOf = (assets, items) => ({
  assets: { total: assets },
  autoSync: { items },
});

/**
 * Mirrors the real page: every refresh stores a new summary, which gives the
 * step a new ctx object. A step that re-subscribes on ctx loops forever.
 */
function Harness({ server, refreshSpy }) {
  const [summary, setSummary] = useState(server.summary);
  const refresh = useCallback(() => {
    refreshSpy();
    const next = JSON.parse(JSON.stringify(server.summary));
    setSummary(next);
    return Promise.resolve(next);
  }, [server, refreshSpy]);
  const ctx = useMemo(
    () => ({
      workspaceId: 'ws-1',
      session: { progress: {}, operationRefs: {}, intent: {} },
      summary,
      capabilities: CAPABILITIES,
      docs: () => [],
      refresh,
      skip: vi.fn(),
      controller: { update: vi.fn().mockResolvedValue(undefined) },
    }),
    [summary, refresh]
  );
  return (
    <ChakraProvider>
      <DashboardThemeProvider>
        <IntegrationStep ctx={ctx} />
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

async function startSync() {
  fireEvent.click(screen.getByRole('button', { name: 'GitHub' }));
  fireEvent.click(screen.getByLabelText('Keep in sync'));
  fireEvent.click(
    screen.getByRole('button', { name: 'Connect and keep in sync' })
  );
  await screen.findByText('close-modal');
}

describe('integration step host', () => {
  it('reads the server at a steady pace instead of looping on every refresh', async () => {
    const server = { summary: summaryOf(0, []) };
    const refreshSpy = vi.fn();
    render(<Harness server={server} refreshSpy={refreshSpy} />);
    await startSync();
    await new Promise(r => setTimeout(r, 400));
    expect(refreshSpy.mock.calls.length).toBeLessThan(6);
  });

  it('reports a saved connection once the dialog is closed', async () => {
    const server = { summary: summaryOf(0, []) };
    render(<Harness server={server} refreshSpy={vi.fn()} />);
    await startSync();
    server.summary = summaryOf(4, [connection('a')]);
    fireEvent.click(screen.getByText('close-modal'));
    await waitFor(() => {
      expect(screen.getByTestId('outcome')).toHaveTextContent('4 assets added');
      expect(screen.getByTestId('outcome')).toHaveTextContent(
        'Connection "github" saved'
      );
    });
  });

  it('says so when a connection was removed and a new one saved', async () => {
    const server = { summary: summaryOf(4, [connection('a')]) };
    render(<Harness server={server} refreshSpy={vi.fn()} />);
    await startSync();
    server.summary = summaryOf(4, [connection('b')]);
    fireEvent.click(screen.getByText('close-modal'));
    await waitFor(() => {
      expect(screen.getByTestId('outcome')).toHaveTextContent(
        'Connection "github" removed'
      );
      expect(screen.getByTestId('outcome')).toHaveTextContent(
        'Connection "github" saved'
      );
    });
  });

  it('says the connection was removed when none is left', async () => {
    const server = { summary: summaryOf(4, [connection('a')]) };
    render(<Harness server={server} refreshSpy={vi.fn()} />);
    await startSync();
    server.summary = summaryOf(4, []);
    fireEvent.click(screen.getByText('close-modal'));
    await waitFor(() => {
      expect(screen.getByTestId('outcome')).toHaveTextContent(
        'Connection "github" removed'
      );
    });
  });
});
