import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChakraProvider } from '@chakra-ui/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import CertopsQuickstartCard from '../../src/components/onboarding/CertopsQuickstartCard.jsx';
import {
  quickstartLabel,
  quickstartMode,
} from '../../src/components/onboarding/certopsQuickstartRules.js';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { canManageMock, workspaceRef, errorMock } = vi.hoisted(() => ({
  canManageMock: vi.fn(),
  workspaceRef: { id: 'ws-1' },
  errorMock: vi.fn(),
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: canManageMock,
}));
vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: workspaceRef.id }),
}));
vi.mock('../../src/utils/toast.js', () => ({
  showError: errorMock,
  showSuccess: vi.fn(),
}));

const session = (over = {}) => ({
  revision: 3,
  status: 'in_progress',
  intent: {},
  progress: {},
  ...over,
});

function makeApi(current) {
  return {
    getSession: vi.fn().mockResolvedValue(current),
    putSession: vi.fn().mockImplementation((_w, _f, body) =>
      Promise.resolve({
        ...current,
        ...body,
        revision: current.revision + 1,
      })
    ),
    resetSession: vi.fn().mockResolvedValue(true),
  };
}

function Where() {
  const l = useLocation();
  return <div data-testid='where'>{l.pathname + l.search}</div>;
}

const show = api =>
  render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter initialEntries={['/certops/settings']}>
          <Routes>
            <Route
              path='*'
              element={
                <>
                  <CertopsQuickstartCard api={api} />
                  <Where />
                </>
              }
            />
          </Routes>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );

describe('quickstartMode', () => {
  it('maps every session state to one action', () => {
    expect(quickstartMode(null)).toBe('start');
    expect(quickstartMode(session())).toBe('start');
    expect(
      quickstartMode(session({ intent: { goal: 'certops_observe' } }))
    ).toBe('continue');
    expect(quickstartMode(session({ intent: { goal: 'monitor_https' } }))).toBe(
      'switch'
    );
    expect(quickstartMode(session({ status: 'completed' }))).toBe('restart');
    expect(quickstartMode(session({ status: 'dismissed' }))).toBe('restart');
  });

  it('only says continue while a certificate goal is under way', () => {
    expect(
      quickstartLabel(session({ intent: { goal: 'certops_automate' } }))
    ).toBe('Continue the CertOps quickstart');
    expect(quickstartLabel(session({ status: 'completed' }))).toBe(
      'Start the CertOps quickstart'
    );
    expect(quickstartLabel(null)).toBe('Start the CertOps quickstart');
  });
});

describe('CertopsQuickstartCard', () => {
  beforeEach(() => {
    canManageMock.mockReset();
    canManageMock.mockReturnValue(true);
    errorMock.mockReset();
    workspaceRef.id = 'ws-1';
  });

  it('is always there for a manager, even for a fresh session', async () => {
    const api = makeApi(session());
    show(api);
    expect(
      await screen.findByRole('button', {
        name: 'Start the CertOps quickstart',
      })
    ).toBeTruthy();
    expect(api.getSession).toHaveBeenCalledWith('ws-1', 'mega');
  });

  it('renders nothing for someone who cannot manage CertOps', async () => {
    canManageMock.mockReturnValue(false);
    const api = makeApi(session());
    show(api);
    await new Promise(r => setTimeout(r, 30));
    expect(screen.queryByTestId('certops-quickstart-card')).toBeNull();
    expect(api.getSession).not.toHaveBeenCalled();
  });

  it('continues the active certificate session without touching it', async () => {
    const api = makeApi(session({ intent: { goal: 'certops_observe' } }));
    show(api);
    fireEvent.click(
      await screen.findByRole('button', {
        name: 'Continue the CertOps quickstart',
      })
    );
    await waitFor(() =>
      expect(screen.getByTestId('where').textContent).toBe(
        '/onboarding?area=certops'
      )
    );
    expect(api.resetSession).not.toHaveBeenCalled();
    expect(api.putSession).not.toHaveBeenCalled();
  });

  it.each(['completed', 'dismissed'])(
    'restarts the guide cleanly when it was %s',
    async status => {
      const api = makeApi(session({ status }));
      show(api);
      fireEvent.click(
        await screen.findByRole('button', {
          name: 'Start the CertOps quickstart',
        })
      );
      await waitFor(() =>
        expect(screen.getByTestId('where').textContent).toBe(
          '/onboarding?area=certops'
        )
      );
      expect(api.resetSession).toHaveBeenCalledWith('ws-1', 'mega');
    }
  );

  it('drops only the goal when another goal is under way', async () => {
    const api = makeApi(
      session({
        intent: { goal: 'monitor_https' },
        progress: { imported: ['a'], verified: true },
      })
    );
    show(api);
    fireEvent.click(await screen.findByText('Start the CertOps quickstart'));
    await waitFor(() => expect(api.putSession).toHaveBeenCalledTimes(1));
    const body = api.putSession.mock.calls[0][2];
    expect(body.intent.goal).toBe('');
    expect(body.progress.imported).toEqual(['a']);
    expect(body.expectedRevision).toBe(3);
    expect(api.resetSession).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByTestId('where').textContent).toBe(
        '/onboarding?area=certops'
      )
    );
  });

  it('stays on the page and reports when the restart fails', async () => {
    const api = makeApi(session({ status: 'completed' }));
    api.resetSession.mockRejectedValue(new Error('nope'));
    show(api);
    fireEvent.click(await screen.findByText('Start the CertOps quickstart'));
    await waitFor(() => expect(errorMock).toHaveBeenCalledWith('nope'));
    expect(screen.getByTestId('where').textContent).toBe('/certops/settings');
  });
});
