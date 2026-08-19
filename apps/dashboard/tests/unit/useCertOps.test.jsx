import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const {
  useWorkspaceMock,
  loadCertOpsInventoryIndexMock,
  getManagedCertificatesForTokenMock,
  getCertificateInstancesMock,
  probeCertOpsEnabledMock,
  getCachedCertOpsEnabledMock,
  invalidateCertOpsInventoryCacheMock,
  getWorkspaceCertOpsPauseStateMock,
  updateWorkspaceCertOpsPauseStateMock,
  workspaceAPIGetMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  loadCertOpsInventoryIndexMock: vi.fn(),
  getManagedCertificatesForTokenMock: vi.fn(),
  getCertificateInstancesMock: vi.fn(),
  probeCertOpsEnabledMock: vi.fn(),
  // Always "no cache entry yet" by default so existing tests keep exercising
  // the async probe path; the caching behavior itself has its own tests.
  getCachedCertOpsEnabledMock: vi.fn().mockReturnValue(null),
  invalidateCertOpsInventoryCacheMock: vi.fn(),
  getWorkspaceCertOpsPauseStateMock: vi.fn(),
  updateWorkspaceCertOpsPauseStateMock: vi.fn(),
  workspaceAPIGetMock: vi.fn().mockResolvedValue({ role: 'admin' }),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: { get: workspaceAPIGetMock },
}));

vi.mock('../../src/components/certops/certopsApi', () => ({
  loadCertOpsInventoryIndex: loadCertOpsInventoryIndexMock,
  getManagedCertificatesForToken: getManagedCertificatesForTokenMock,
  getCertificateInstances: getCertificateInstancesMock,
  probeCertOpsEnabled: probeCertOpsEnabledMock,
  getCachedCertOpsEnabled: getCachedCertOpsEnabledMock,
  invalidateCertOpsInventoryCache: invalidateCertOpsInventoryCacheMock,
  getWorkspaceCertOpsPauseState: getWorkspaceCertOpsPauseStateMock,
  updateWorkspaceCertOpsPauseState: updateWorkspaceCertOpsPauseStateMock,
}));

import {
  useCertOpsAvailability,
  useWorkspaceCertOps,
  useCertOpsForToken,
  useCertOpsIsWorkspaceAdmin,
  useCertOpsWorkspaceKillSwitch,
} from '../../src/components/certops/useCertOps.js';

describe('useCertOpsAvailability cached-verdict revalidation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    getCachedCertOpsEnabledMock.mockReturnValue(null);
  });

  it('surfaces a probe failure as an error when there is no cached verdict', async () => {
    probeCertOpsEnabledMock.mockRejectedValue(
      Object.assign(new Error('network down'), {
        response: { status: 500, data: { error: 'Internal error' } },
      })
    );

    const { result } = renderHook(() => useCertOpsAvailability());

    await waitFor(() => expect(result.current.error).toBe('Internal error'));
    expect(result.current.ready).toBe(true);
    expect(result.current.enabled).toBe(null);
  });

  it('keeps serving a cached enabled verdict through a failed revalidation', async () => {
    getCachedCertOpsEnabledMock.mockReturnValue({ enabled: true });
    probeCertOpsEnabledMock.mockRejectedValue(
      Object.assign(new Error('network down'), {
        response: { status: 503, data: { error: 'Service unavailable' } },
      })
    );

    const { result } = renderHook(() => useCertOpsAvailability());

    expect(result.current.ready).toBe(true);
    expect(result.current.enabled).toBe(true);
    await waitFor(() => expect(probeCertOpsEnabledMock).toHaveBeenCalled());
    // The failed revalidation must not tear down the working verdict: the
    // gated screens' own requests are what surface a real outage.
    expect(result.current.ready).toBe(true);
    expect(result.current.enabled).toBe(true);
    expect(result.current.error).toBe(null);
  });

  it('does not let a cached disabled verdict mask a revalidation outage as "feature off"', async () => {
    getCachedCertOpsEnabledMock.mockReturnValue({ enabled: false });
    probeCertOpsEnabledMock.mockRejectedValue(
      Object.assign(new Error('network down'), {
        response: { status: 503, data: { error: 'Service unavailable' } },
      })
    );

    const { result } = renderHook(() => useCertOpsAvailability());

    // Cached verdict is served first...
    expect(result.current.enabled).toBe(false);
    // ...but once revalidation fails, only a 404 may mean disabled, so the
    // outage must surface as an error instead of "CertOps is not enabled".
    await waitFor(() =>
      expect(result.current.error).toBe('Service unavailable')
    );
    expect(result.current.ready).toBe(true);
    expect(result.current.enabled).toBe(null);
  });

  it('replaces a cached disabled verdict when revalidation resolves enabled', async () => {
    getCachedCertOpsEnabledMock.mockReturnValue({ enabled: false });
    probeCertOpsEnabledMock.mockResolvedValue({ enabled: true });

    const { result } = renderHook(() => useCertOpsAvailability());

    expect(result.current.enabled).toBe(false);
    await waitFor(() => expect(result.current.enabled).toBe(true));
    expect(result.current.error).toBe(null);
  });
});

describe('useWorkspaceCertOps fail-closed resolution', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    probeCertOpsEnabledMock.mockResolvedValue({ enabled: true });
  });

  it('is not resolved while the inventory is loading', async () => {
    let resolveLoad;
    loadCertOpsInventoryIndexMock.mockImplementation(
      () =>
        new Promise(resolve => {
          resolveLoad = resolve;
        })
    );

    const { result } = renderHook(() => useWorkspaceCertOps());

    await waitFor(() => expect(result.current.enabled).toBe(true));
    expect(result.current.loading).toBe(true);
    expect(result.current.resolved).toBe(false);

    resolveLoad({ byTokenId: new Map(), items: [] });
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.resolved).toBe(true);
    expect(result.current.error).toBe('');
  });

  it('stays unresolved with an error when the inventory fetch fails', async () => {
    loadCertOpsInventoryIndexMock.mockRejectedValue(
      Object.assign(new Error('boom'), {
        response: { status: 500, data: { error: 'Internal error' } },
      })
    );

    const { result } = renderHook(() => useWorkspaceCertOps());

    await waitFor(() => expect(result.current.error).toBe('Internal error'));
    expect(result.current.loading).toBe(false);
    expect(result.current.resolved).toBe(false);
    expect(result.current.byTokenId.size).toBe(0);
  });

  it('resolves immediately when CertOps is disabled (nothing is managed)', async () => {
    probeCertOpsEnabledMock.mockResolvedValue({ enabled: false });

    const { result } = renderHook(() => useWorkspaceCertOps());

    await waitFor(() => expect(result.current.enabled).toBe(false));
    expect(result.current.resolved).toBe(true);
    expect(loadCertOpsInventoryIndexMock).not.toHaveBeenCalled();
  });
});

describe('useCertOpsForToken instance error handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    probeCertOpsEnabledMock.mockResolvedValue({ enabled: true });
    getManagedCertificatesForTokenMock.mockResolvedValue([
      { id: 'cert-1', status: 'active' },
    ]);
  });

  it('treats 404 as instances unavailable without an error', async () => {
    getCertificateInstancesMock.mockRejectedValue(
      Object.assign(new Error('not found'), { response: { status: 404 } })
    );

    const { result } = renderHook(() => useCertOpsForToken(42));

    await waitFor(() =>
      expect(result.current.instancesAvailable).toBe(false)
    );
    expect(result.current.instancesError).toBe('');
  });

  it('surfaces non-404 instance failures as instancesError instead of an empty list', async () => {
    getCertificateInstancesMock.mockRejectedValue(
      Object.assign(new Error('server error'), {
        response: { status: 500, data: { error: 'Internal error' } },
      })
    );

    const { result } = renderHook(() => useCertOpsForToken(42));

    await waitFor(() =>
      expect(result.current.instancesError).toBe('Internal error')
    );
    expect(result.current.instances).toEqual([]);
  });

  it('returns instances with no error on success', async () => {
    getCertificateInstancesMock.mockResolvedValue({
      items: [{ id: 'inst-1' }],
    });

    const { result } = renderHook(() => useCertOpsForToken(42));

    await waitFor(() =>
      expect(result.current.instances).toEqual([{ id: 'inst-1' }])
    );
    expect(result.current.instancesAvailable).toBe(true);
    expect(result.current.instancesError).toBe('');
  });
});

describe('useCertOpsIsWorkspaceAdmin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('is true only for the admin role', async () => {
    workspaceAPIGetMock.mockResolvedValue({ role: 'admin' });

    const { result } = renderHook(() => useCertOpsIsWorkspaceAdmin());

    await waitFor(() => expect(result.current).toBe(true));
  });

  it('is false for workspace_manager and viewer roles', async () => {
    workspaceAPIGetMock.mockResolvedValue({ role: 'workspace_manager' });

    const { result } = renderHook(() => useCertOpsIsWorkspaceAdmin());

    await waitFor(() => expect(workspaceAPIGetMock).toHaveBeenCalled());
    expect(result.current).toBe(false);
  });

  it('is false when the workspace lookup fails', async () => {
    workspaceAPIGetMock.mockRejectedValue(new Error('boom'));

    const { result } = renderHook(() => useCertOpsIsWorkspaceAdmin());

    await waitFor(() => expect(workspaceAPIGetMock).toHaveBeenCalled());
    expect(result.current).toBe(false);
  });
});

describe('useCertOpsWorkspaceKillSwitch', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
  });

  it('loads the workspace pause state', async () => {
    getWorkspaceCertOpsPauseStateMock.mockResolvedValue({
      workspaceId: 'ws-1',
      certOpsPaused: false,
      certOpsEnabled: true,
      certOpsActive: true,
    });

    const { result } = renderHook(() => useCertOpsWorkspaceKillSwitch());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.certOpsPaused).toBe(false);
    expect(result.current.certOpsActive).toBe(true);
    expect(result.current.error).toBe('');
  });

  it('surfaces a load failure', async () => {
    getWorkspaceCertOpsPauseStateMock.mockRejectedValue(
      Object.assign(new Error('boom'), {
        response: { data: { error: 'Internal error' } },
      })
    );

    const { result } = renderHook(() => useCertOpsWorkspaceKillSwitch());

    await waitFor(() => expect(result.current.error).toBe('Internal error'));
    expect(result.current.loading).toBe(false);
  });

  it('setPaused calls the update endpoint and applies the returned state', async () => {
    getWorkspaceCertOpsPauseStateMock.mockResolvedValue({
      workspaceId: 'ws-1',
      certOpsPaused: false,
      certOpsEnabled: true,
      certOpsActive: true,
    });
    updateWorkspaceCertOpsPauseStateMock.mockResolvedValue({
      workspaceId: 'ws-1',
      certOpsPaused: true,
      certOpsEnabled: true,
      certOpsActive: false,
      changed: true,
    });

    const { result } = renderHook(() => useCertOpsWorkspaceKillSwitch());
    await waitFor(() => expect(result.current.loading).toBe(false));

    await result.current.setPaused(true, 'incident');

    expect(updateWorkspaceCertOpsPauseStateMock).toHaveBeenCalledWith('ws-1', {
      certOpsPaused: true,
      reason: 'incident',
    });
    await waitFor(() => expect(result.current.certOpsPaused).toBe(true));
    expect(result.current.certOpsActive).toBe(false);
  });
});
