import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';

import RequireManagerRoute from '../../src/components/RequireManagerRoute.jsx';

const { workspaceGetMock, workspaceListMock, useWorkspaceMock } = vi.hoisted(
  () => ({
    workspaceGetMock: vi.fn(),
    workspaceListMock: vi.fn(),
    useWorkspaceMock: vi.fn(),
  })
);

vi.mock('../../src/utils/apiClient', () => ({
  default: {},
  workspaceAPI: {
    get: workspaceGetMock,
    list: workspaceListMock,
  },
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

const session = { isAdmin: false };

// Multi-workspace fixture: manager in workspace A (id 1), viewer in B (id 2).
const WORKSPACES = {
  1: { id: 1, name: 'Workspace A', role: 'workspace_manager' },
  2: { id: 2, name: 'Workspace B', role: 'viewer' },
};

function renderGuard({ scope, activeWorkspaceId, guardSession = session }) {
  useWorkspaceMock.mockReturnValue({
    workspaceId: activeWorkspaceId,
    selectWorkspace: vi.fn(),
  });
  workspaceGetMock.mockImplementation(async id => WORKSPACES[id] || null);
  workspaceListMock.mockResolvedValue({ items: Object.values(WORKSPACES) });

  return render(
    <MemoryRouter initialEntries={['/certops/operations']}>
      <Routes>
        <Route
          path='/certops/*'
          element={
            <RequireManagerRoute session={guardSession} scope={scope}>
              <div>CertOps content</div>
            </RequireManagerRoute>
          }
        />
        <Route path='/dashboard' element={<div>Dashboard fallback</div>} />
        <Route path='/login' element={<div>Login page</div>} />
      </Routes>
    </MemoryRouter>
  );
}

describe('RequireManagerRoute (active-workspace scope for /certops/*)', () => {
  beforeEach(() => {
    workspaceGetMock.mockReset();
    workspaceListMock.mockReset();
    useWorkspaceMock.mockReset();
  });

  it('denies /certops when the ACTIVE workspace role is viewer, even though the user manages another workspace', async () => {
    renderGuard({ scope: 'active-workspace', activeWorkspaceId: 2 });

    await waitFor(() =>
      expect(screen.getByText('Dashboard fallback')).toBeInTheDocument()
    );
    expect(screen.queryByText('CertOps content')).not.toBeInTheDocument();
    expect(workspaceGetMock).toHaveBeenCalledWith(2);
  });

  it('renders /certops when the ACTIVE workspace role is manager', async () => {
    renderGuard({ scope: 'active-workspace', activeWorkspaceId: 1 });

    await waitFor(() =>
      expect(screen.getByText('CertOps content')).toBeInTheDocument()
    );
    expect(workspaceGetMock).toHaveBeenCalledWith(1);
  });

  it('keeps any-workspace semantics by default: viewer-active user with a manager role elsewhere passes', async () => {
    renderGuard({ scope: undefined, activeWorkspaceId: 2 });

    await waitFor(() =>
      expect(screen.getByText('CertOps content')).toBeInTheDocument()
    );
    expect(workspaceListMock).toHaveBeenCalled();
    expect(workspaceGetMock).not.toHaveBeenCalled();
  });

  it('allows system admins regardless of active workspace role', async () => {
    renderGuard({
      scope: 'active-workspace',
      activeWorkspaceId: 2,
      guardSession: { isAdmin: true },
    });

    await waitFor(() =>
      expect(screen.getByText('CertOps content')).toBeInTheDocument()
    );
    expect(workspaceGetMock).not.toHaveBeenCalled();
  });

  it('redirects to /login when there is no session', async () => {
    renderGuard({
      scope: 'active-workspace',
      activeWorkspaceId: 1,
      guardSession: null,
    });

    await waitFor(() =>
      expect(screen.getByText('Login page')).toBeInTheDocument()
    );
  });
});
