import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router';

import {
  WorkspaceProvider,
  useWorkspace,
} from '../../src/utils/WorkspaceContext.jsx';
import {
  LAST_WORKSPACE_LEGACY_KEY,
  writeLastWorkspaceId,
} from '../../src/utils/lastWorkspacePreference.js';

const { workspaceListMock } = vi.hoisted(() => ({
  workspaceListMock: vi.fn(),
}));

vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: {
    list: workspaceListMock,
  },
}));

const WS_A = { id: 'ws-a', name: 'Alpha' };
const WS_B = { id: 'ws-b', name: 'Beta' };
const WS_FROZEN = { id: 'ws-frozen', name: 'Frozen', is_frozen: true };

function Probe() {
  const { workspaceId, selectWorkspace } = useWorkspace();
  const location = useLocation();
  return (
    <div>
      <span data-testid='ws'>{workspaceId || ''}</span>
      <span data-testid='search'>{location.search}</span>
      <button type='button' onClick={() => selectWorkspace('ws-b')}>
        pick-b
      </button>
    </div>
  );
}

function renderProvider({ path = '/dashboard', accountId = 'user-a' } = {}) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <WorkspaceProvider accountId={accountId}>
        <Probe />
      </WorkspaceProvider>
    </MemoryRouter>
  );
}

describe('WorkspaceProvider last-workspace restore', () => {
  beforeEach(() => {
    localStorage.clear();
    workspaceListMock.mockReset();
    workspaceListMock.mockResolvedValue({ items: [WS_A, WS_B, WS_FROZEN] });
  });

  it('restores the last workspace this account used when the URL has none', async () => {
    writeLastWorkspaceId('user-a', 'ws-b');
    renderProvider({ path: '/dashboard' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );
  });

  it('lets an explicit URL workspace win over the stored last workspace', async () => {
    writeLastWorkspaceId('user-a', 'ws-b');
    renderProvider({ path: '/dashboard?workspace=ws-a' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-a')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-a'
    );
  });

  it('falls back to another accessible workspace when last is gone or frozen', async () => {
    writeLastWorkspaceId('user-a', 'ws-frozen');
    renderProvider({ path: '/dashboard' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-a')
    );
  });

  it('falls back when the URL workspace is inaccessible, even if it is still stored', async () => {
    writeLastWorkspaceId('user-a', 'ws-b');
    renderProvider({ path: '/dashboard?workspace=ws-frozen' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
  });

  it('still restores after a first-login landing (email verification success)', async () => {
    writeLastWorkspaceId('user-a', 'ws-b');
    renderProvider({ path: '/dashboard?first_login=true' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
  });

  it('does not restore another account last workspace (OAuth and email share this path)', async () => {
    writeLastWorkspaceId('user-a', 'ws-b');
    localStorage.setItem(LAST_WORKSPACE_LEGACY_KEY, 'ws-b');
    renderProvider({ path: '/dashboard', accountId: 'user-b' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-a')
    );
    expect(screen.getByTestId('ws').textContent).not.toBe('ws-b');
  });

  it('still restores from the session cache when account id is not passed yet', async () => {
    localStorage.setItem(LAST_WORKSPACE_LEGACY_KEY, 'ws-b');
    renderProvider({ path: '/dashboard', accountId: null });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
  });

  it('claims a pre-namespace leftover for this account on first restore', async () => {
    localStorage.setItem(LAST_WORKSPACE_LEGACY_KEY, 'ws-b');
    renderProvider({ path: '/dashboard', accountId: 'user-a' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
  });

  it('keeps a workspace the user just selected while a restore fetch is still in flight', async () => {
    let releaseList;
    workspaceListMock.mockImplementation(
      () =>
        new Promise(resolve => {
          releaseList = () => resolve({ items: [WS_A, WS_B, WS_FROZEN] });
        })
    );
    writeLastWorkspaceId('user-a', 'ws-a');
    renderProvider({ path: '/dashboard' });

    fireEvent.click(screen.getByRole('button', { name: 'pick-b' }));
    expect(screen.getByTestId('ws').textContent).toBe('ws-b');
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );

    releaseList();

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );
  });

  it('keeps a later selector click after restore has already settled', async () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    renderProvider({ path: '/dashboard' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-a')
    );

    fireEvent.click(screen.getByRole('button', { name: 'pick-b' }));

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );
  });

  it('does not roll the URL back to the previous workspace after the selector is used', async () => {
    let releaseList;
    workspaceListMock.mockImplementation(
      () =>
        new Promise(resolve => {
          releaseList = () => resolve({ items: [WS_A, WS_B, WS_FROZEN] });
        })
    );
    writeLastWorkspaceId('user-a', 'ws-a');
    renderProvider({ path: '/dashboard?workspace=ws-a' });

    fireEvent.click(screen.getByRole('button', { name: 'pick-b' }));
    expect(screen.getByTestId('ws').textContent).toBe('ws-b');
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );

    releaseList();

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );
  });

  it('resets inventory list filters when switching workspace on the dashboard', async () => {
    writeLastWorkspaceId('user-a', 'ws-a');
    renderProvider({
      path: '/dashboard?workspace=ws-a&section=prod&status=critical&q=acme',
    });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-a')
    );

    fireEvent.click(screen.getByRole('button', { name: 'pick-b' }));

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );
    expect(screen.getByTestId('search').textContent).not.toContain(
      'status=critical'
    );
    expect(screen.getByTestId('search').textContent).not.toContain(
      'section=prod'
    );
    expect(screen.getByTestId('search').textContent).not.toContain('q=acme');
  });

  it('keeps inventory filters when first injecting a workspace into the URL', async () => {
    writeLastWorkspaceId('user-a', 'ws-b');
    renderProvider({ path: '/dashboard?status=critical' });

    await waitFor(() =>
      expect(screen.getByTestId('ws').textContent).toBe('ws-b')
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'workspace=ws-b'
    );
    expect(screen.getByTestId('search').textContent).toContain(
      'status=critical'
    );
  });
});
