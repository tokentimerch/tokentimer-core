import { useState } from 'react';
import { ChakraProvider } from '@chakra-ui/react';
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router';
import { HelmetProvider } from 'react-helmet-async';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Workspaces from '../../src/pages/Workspaces.jsx';
import { DashboardThemeProvider } from '../../src/hooks/useDashboardTheme.js';

const { listMembers, listInvitations } = vi.hoisted(() => ({
  listMembers: vi.fn(),
  listInvitations: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => {
    const [workspaceId, selectWorkspace] = useState('ws-a');
    return { workspaceId, selectWorkspace };
  },
}));
vi.mock('../../src/components/DashboardPageLayout', () => ({
  default: ({ children }) => <main>{children}</main>,
}));
vi.mock('../../src/utils/apiClient', () => ({
  default: {
    get: vi.fn(async () => ({
      data: { plan: 'oss', manualInvitesDisabled: true },
    })),
  },
  API_ENDPOINTS: { ACCOUNT_PLAN: '/plan', AUTH_FEATURES: '/auth-features' },
  workspaceAPI: {
    list: vi.fn(async () => ({
      items: [
        { id: 'ws-a', name: 'Alpha', role: 'workspace_manager' },
        { id: 'ws-b', name: 'Beta', role: 'workspace_manager' },
      ],
    })),
    listMembers,
    listInvitations,
  },
  adminAPI: {},
}));

function deferred() {
  let resolve;
  const promise = new Promise(done => {
    resolve = done;
  });
  return { promise, resolve };
}
function show() {
  return render(
    <HelmetProvider>
      <MemoryRouter>
        <ChakraProvider>
          <DashboardThemeProvider>
            <Workspaces session={{ isAdmin: true }} />
          </DashboardThemeProvider>
        </ChakraProvider>
      </MemoryRouter>
    </HelmetProvider>
  );
}
const member = name => ({
  user_id: name,
  display_name: name,
  email: `${name}@example.test`,
  role: 'workspace_manager',
});

describe('workspace member loading', () => {
  beforeEach(() => {
    listMembers.mockReset();
    listInvitations.mockReset().mockResolvedValue({ items: [] });
  });
  afterEach(cleanup);

  it('shows members from the initial URL selection without switching workspaces', async () => {
    const request = deferred();
    listMembers.mockReturnValue(request.promise);
    show();
    await waitFor(() =>
      expect(listMembers).toHaveBeenCalledWith('ws-a', 100, 0)
    );
    await waitFor(() =>
      expect(screen.getByText('workspace_manager')).toBeTruthy()
    );
    await act(async () => {});
    await act(async () => request.resolve({ items: [member('Alpha member')] }));
    await waitFor(() =>
      expect(screen.getAllByText('Alpha member').length).toBeGreaterThan(0)
    );
    expect(listInvitations).toHaveBeenCalledWith('ws-a', 100, 0);
  });

  it('does not let a late previous-workspace response overwrite the selected members', async () => {
    const alpha = deferred();
    listMembers.mockImplementation(id =>
      id === 'ws-a'
        ? alpha.promise
        : Promise.resolve({ items: [member('Beta member')] })
    );
    show();
    await waitFor(() =>
      expect(listMembers).toHaveBeenCalledWith('ws-a', 100, 0)
    );
    fireEvent.change(
      screen.getByRole('combobox', { name: 'Workspace', exact: true }),
      { target: { value: 'ws-b' } }
    );
    await waitFor(() =>
      expect(screen.getAllByText('Beta member').length).toBeGreaterThan(0)
    );
    await act(async () => alpha.resolve({ items: [member('Alpha member')] }));
    expect(screen.queryByText('Alpha member')).toBeNull();
    expect(screen.getAllByText('Beta member').length).toBeGreaterThan(0);
  });
});
