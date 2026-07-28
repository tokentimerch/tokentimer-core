import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const {
  useWorkspaceMock,
  useCertOpsCanManageMock,
  useCertOpsEnabledMock,
  listApiTokensMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  useCertOpsEnabledMock: vi.fn(),
  listApiTokensMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsCanManage: useCertOpsCanManageMock,
  useCertOpsEnabled: useCertOpsEnabledMock,
}));

vi.mock('../../src/components/certops/certopsTokensApi', async () => {
  const actual = await vi.importActual(
    '../../src/components/certops/certopsTokensApi'
  );
  return {
    ...actual,
    listApiTokens: listApiTokensMock,
  };
});

import { useCertOpsControllerClusters } from '../../src/components/certops/useCertOpsControllerClusters.js';

function token(overrides = {}) {
  return {
    id: 'tok-1',
    status: 'active',
    scopes: ['certops:observations:write'],
    controllerClusterId: 'cluster-a',
    expiresAt: null,
    ...overrides,
  };
}

describe('useCertOpsControllerClusters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
    useCertOpsCanManageMock.mockReturnValue(true);
    useCertOpsEnabledMock.mockReturnValue(true);
  });

  it('returns distinct cluster ids from active, controller-scoped tokens', async () => {
    listApiTokensMock.mockResolvedValue({
      items: [
        token({ id: 'tok-1', controllerClusterId: 'cluster-a' }),
        token({ id: 'tok-2', controllerClusterId: 'cluster-a' }),
        token({
          id: 'tok-3',
          controllerClusterId: 'cluster-b',
          scopes: ['certops:provision:execute'],
        }),
      ],
    });

    const { result } = renderHook(() => useCertOpsControllerClusters());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.clusters.sort()).toEqual(['cluster-a', 'cluster-b']);
  });

  it('excludes revoked and expired tokens', async () => {
    listApiTokensMock.mockResolvedValue({
      items: [
        token({ id: 'tok-revoked', status: 'revoked', controllerClusterId: 'cluster-revoked' }),
        token({
          id: 'tok-expired',
          controllerClusterId: 'cluster-expired',
          expiresAt: new Date(Date.now() - 60000).toISOString(),
        }),
        token({ id: 'tok-active', controllerClusterId: 'cluster-active' }),
      ],
    });

    const { result } = renderHook(() => useCertOpsControllerClusters());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.clusters).toEqual(['cluster-active']);
  });

  it('excludes tokens without a controller scope even if a clusterId is set', async () => {
    listApiTokensMock.mockResolvedValue({
      items: [
        token({
          id: 'tok-no-scope',
          controllerClusterId: 'cluster-x',
          scopes: ['certops:read'],
        }),
      ],
    });

    const { result } = renderHook(() => useCertOpsControllerClusters());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.clusters).toEqual([]);
  });

  it('does not fetch for a non-manager viewer', () => {
    useCertOpsCanManageMock.mockReturnValue(false);

    renderHook(() => useCertOpsControllerClusters());

    expect(listApiTokensMock).not.toHaveBeenCalled();
  });

  it('surfaces a load failure as an error, with an empty cluster list', async () => {
    listApiTokensMock.mockRejectedValue(
      Object.assign(new Error('boom'), {
        response: { data: { error: 'Internal error' } },
      })
    );

    const { result } = renderHook(() => useCertOpsControllerClusters());

    await waitFor(() => expect(result.current.error).toBe('Internal error'));
    expect(result.current.clusters).toEqual([]);
  });
});
