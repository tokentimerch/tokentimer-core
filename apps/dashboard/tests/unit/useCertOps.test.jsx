import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const {
  useWorkspaceMock,
  loadCertOpsInventoryIndexMock,
  getManagedCertificatesForTokenMock,
  getCertificateInstancesMock,
  probeCertOpsEnabledMock,
  invalidateCertOpsInventoryCacheMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  loadCertOpsInventoryIndexMock: vi.fn(),
  getManagedCertificatesForTokenMock: vi.fn(),
  getCertificateInstancesMock: vi.fn(),
  probeCertOpsEnabledMock: vi.fn(),
  invalidateCertOpsInventoryCacheMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/utils/apiClient', () => ({
  workspaceAPI: { get: vi.fn().mockResolvedValue({ role: 'admin' }) },
}));

vi.mock('../../src/components/certops/certopsApi', () => ({
  loadCertOpsInventoryIndex: loadCertOpsInventoryIndexMock,
  getManagedCertificatesForToken: getManagedCertificatesForTokenMock,
  getCertificateInstances: getCertificateInstancesMock,
  probeCertOpsEnabled: probeCertOpsEnabledMock,
  invalidateCertOpsInventoryCache: invalidateCertOpsInventoryCacheMock,
}));

import {
  useWorkspaceCertOps,
  useCertOpsForToken,
} from '../../src/components/certops/useCertOps.js';

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
