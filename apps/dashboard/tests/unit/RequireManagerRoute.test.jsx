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

  it('fails closed on workspace switch: hides children immediately while the new workspace check is in flight, then redirects', async () => {
    // Manager of workspace A passes; the role lookup for workspace B is a
    // controllable promise so we can assert the in-flight state.
    let resolveWorkspaceB;
    workspaceGetMock.mockImplementation(id => {
      if (id === 1) return Promise.resolve(WORKSPACES[1]);
      return new Promise(resolve => {
        resolveWorkspaceB = resolve;
      });
    });
    workspaceListMock.mockResolvedValue({ items: Object.values(WORKSPACES) });
    useWorkspaceMock.mockReturnValue({
      workspaceId: 1,
      selectWorkspace: vi.fn(),
    });

    const view = render(
      <MemoryRouter initialEntries={['/certops/operations']}>
        <Routes>
          <Route
            path='/certops/*'
            element={
              <RequireManagerRoute session={session} scope='active-workspace'>
                <div>CertOps content</div>
              </RequireManagerRoute>
            }
          />
          <Route path='/dashboard' element={<div>Dashboard fallback</div>} />
          <Route path='/login' element={<div>Login page</div>} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() =>
      expect(screen.getByText('CertOps content')).toBeInTheDocument()
    );

    // Switch the active workspace to B (viewer role, resolves later).
    useWorkspaceMock.mockReturnValue({
      workspaceId: 2,
      selectWorkspace: vi.fn(),
    });
    view.rerender(
      <MemoryRouter initialEntries={['/certops/operations']}>
        <Routes>
          <Route
            path='/certops/*'
            element={
              <RequireManagerRoute session={session} scope='active-workspace'>
                <div>CertOps content</div>
              </RequireManagerRoute>
            }
          />
          <Route path='/dashboard' element={<div>Dashboard fallback</div>} />
          <Route path='/login' element={<div>Login page</div>} />
        </Routes>
      </MemoryRouter>
    );

    // Children must be hidden IMMEDIATELY, before the workspace B check
    // resolves, and there must be no premature redirect either.
    expect(screen.queryByText('CertOps content')).not.toBeInTheDocument();
    expect(screen.queryByText('Dashboard fallback')).not.toBeInTheDocument();
    expect(workspaceGetMock).toHaveBeenCalledWith(2);

    resolveWorkspaceB(WORKSPACES[2]);

    await waitFor(() =>
      expect(screen.getByText('Dashboard fallback')).toBeInTheDocument()
    );
    expect(screen.queryByText('CertOps content')).not.toBeInTheDocument();
  });

  it('clears prior authorization when the workspaceId becomes temporarily falsy', async () => {
    workspaceGetMock.mockImplementation(async id => WORKSPACES[id] || null);
    workspaceListMock.mockResolvedValue({ items: Object.values(WORKSPACES) });
    useWorkspaceMock.mockReturnValue({
      workspaceId: 1,
      selectWorkspace: vi.fn(),
    });

    // Fresh element per render: passing an identical element reference to
    // rerender() would let React bail out of re-rendering.
    const guard = () => (
      <MemoryRouter initialEntries={['/certops/operations']}>
        <Routes>
          <Route
            path='/certops/*'
            element={
              <RequireManagerRoute session={session} scope='active-workspace'>
                <div>CertOps content</div>
              </RequireManagerRoute>
            }
          />
          <Route path='/dashboard' element={<div>Dashboard fallback</div>} />
          <Route path='/login' element={<div>Login page</div>} />
        </Routes>
      </MemoryRouter>
    );

    const view = render(guard());
    await waitFor(() =>
      expect(screen.getByText('CertOps content')).toBeInTheDocument()
    );

    useWorkspaceMock.mockReturnValue({
      workspaceId: null,
      selectWorkspace: vi.fn(),
    });
    view.rerender(guard());

    // Prior grant no longer applies: loading state (no children, no redirect).
    expect(screen.queryByText('CertOps content')).not.toBeInTheDocument();
    expect(screen.queryByText('Dashboard fallback')).not.toBeInTheDocument();
  });
});
