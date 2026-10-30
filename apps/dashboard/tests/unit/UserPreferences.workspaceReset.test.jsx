import { ChakraProvider } from '@chakra-ui/react';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';
import UserPreferences from '../../src/pages/UserPreferences.jsx';
import {
  WorkspaceProvider,
  useWorkspace,
} from '../../src/utils/WorkspaceContext.jsx';
import { readLastWorkspaceId } from '../../src/utils/lastWorkspacePreference.js';

const { workspaceListMock, resetSessionMock, showErrorMock } = vi.hoisted(
  () => ({
    workspaceListMock: vi.fn(),
    resetSessionMock: vi.fn(),
    showErrorMock: vi.fn(),
  })
);

// Keep the actual page actions, router and workspace restoration. Only the
// surrounding chrome and remote I/O are replaced for this route regression.
vi.mock('../../src/components/DashboardPageLayout', () => ({
  default: ({ children }) => children,
}));
vi.mock('../../src/components/SEO.jsx', () => ({ default: () => null }));
vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: { list: workspaceListMock },
}));
vi.mock('../../src/utils/onboardingApi.js', () => ({
  onboardingAPI: { resetSession: resetSessionMock },
}));
vi.mock('../../src/utils/toast.js', () => ({ showError: showErrorMock }));

const ACCOUNT_ID = 'owner-with-two-workspaces';
const CHOSEN_WORKSPACE = '11111111-1111-4111-8111-111111111111';
const NEWER_WORKSPACE = '22222222-2222-4222-8222-222222222222';

function RouteState() {
  const { workspaceId } = useWorkspace();
  const location = useLocation();
  return (
    <>
      <output data-testid='active-workspace'>{workspaceId || ''}</output>
      <output data-testid='active-route'>
        {location.pathname}
        {location.search}
      </output>
    </>
  );
}

function renderPreferences() {
  return render(
    <ChakraProvider>
      <DashboardThemeProvider>
        <MemoryRouter
          initialEntries={[`/preferences?workspace=${CHOSEN_WORKSPACE}`]}
        >
          <WorkspaceProvider accountId={ACCOUNT_ID}>
            <RouteState />
            <Routes>
              <Route
                path='/preferences'
                element={<UserPreferences session={{ id: ACCOUNT_ID }} />}
              />
              <Route path='/onboarding' element={<h1>Setup guide</h1>} />
            </Routes>
          </WorkspaceProvider>
        </MemoryRouter>
      </DashboardThemeProvider>
    </ChakraProvider>
  );
}

describe('Preferences setup reset workspace continuity', () => {
  beforeEach(() => {
    localStorage.clear();
    workspaceListMock.mockReset().mockResolvedValue({
      // The API lists newest first. The explicit URL chooses the older
      // workspace, so dropping it would restore the other workspace.
      items: [
        { id: NEWER_WORKSPACE, name: 'New empty workspace', role: 'admin' },
        { id: CHOSEN_WORKSPACE, name: 'Verified workspace', role: 'admin' },
      ],
    });
    resetSessionMock.mockReset();
    showErrorMock.mockReset();
  });

  afterEach(cleanup);

  it('resets and reopens the selected workspace with no saved workspace preference', async () => {
    let finishReset;
    resetSessionMock.mockImplementationOnce(
      () =>
        new Promise(resolve => {
          finishReset = resolve;
        })
    );
    renderPreferences();

    await waitFor(() => expect(workspaceListMock).toHaveBeenCalledTimes(2));
    expect(screen.getByTestId('active-workspace')).toHaveTextContent(
      CHOSEN_WORKSPACE
    );
    // URL deep links now become the remembered workspace so a later bare
    // /onboarding navigation cannot snap back to another workspace.
    expect(readLastWorkspaceId(ACCOUNT_ID)).toBe(CHOSEN_WORKSPACE);

    fireEvent.click(screen.getByRole('button', { name: 'Start over' }));
    expect(resetSessionMock).toHaveBeenCalledExactlyOnceWith(
      CHOSEN_WORKSPACE,
      'mega'
    );
    expect(screen.getByTestId('active-route')).toHaveTextContent(
      `/preferences?workspace=${CHOSEN_WORKSPACE}`
    );
    expect(screen.queryByRole('heading', { name: 'Setup guide' })).toBeNull();

    await act(async () => {
      finishReset(true);
    });

    // Let the real provider's pathname-triggered API restoration settle;
    // merely observing the first render after navigate would miss the bug.
    await waitFor(() => expect(workspaceListMock).toHaveBeenCalledTimes(3));
    expect(screen.getByRole('heading', { name: 'Setup guide' })).toBeVisible();
    expect(screen.getByTestId('active-route').textContent).toBe(
      `/onboarding?workspace=${CHOSEN_WORKSPACE}`
    );
    expect(screen.getByTestId('active-workspace').textContent).toBe(
      CHOSEN_WORKSPACE
    );
    expect(showErrorMock).not.toHaveBeenCalled();
  });

  it('keeps the selected workspace and Preferences open when reset fails', async () => {
    resetSessionMock.mockRejectedValueOnce(new Error('Reset unavailable'));
    renderPreferences();

    await waitFor(() => expect(workspaceListMock).toHaveBeenCalledTimes(2));
    fireEvent.click(screen.getByRole('button', { name: 'Start over' }));

    await waitFor(() =>
      expect(showErrorMock).toHaveBeenCalledExactlyOnceWith('Reset unavailable')
    );
    expect(resetSessionMock).toHaveBeenCalledExactlyOnceWith(
      CHOSEN_WORKSPACE,
      'mega'
    );
    expect(screen.getByTestId('active-route').textContent).toBe(
      `/preferences?workspace=${CHOSEN_WORKSPACE}`
    );
    expect(screen.getByTestId('active-workspace').textContent).toBe(
      CHOSEN_WORKSPACE
    );
    expect(screen.queryByRole('heading', { name: 'Setup guide' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Start over' })).toBeEnabled();
  });
});
