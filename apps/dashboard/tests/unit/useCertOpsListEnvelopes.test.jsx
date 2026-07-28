import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

const {
  useWorkspaceMock,
  useCertOpsEnabledMock,
  useCertOpsCanManageMock,
  listAgentsMock,
  listBootstrapTokensMock,
  listApiTokensMock,
} = vi.hoisted(() => ({
  useWorkspaceMock: vi.fn(),
  useCertOpsEnabledMock: vi.fn(),
  useCertOpsCanManageMock: vi.fn(),
  listAgentsMock: vi.fn(),
  listBootstrapTokensMock: vi.fn(),
  listApiTokensMock: vi.fn(),
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: useWorkspaceMock,
}));

vi.mock('../../src/components/certops/useCertOps.js', () => ({
  useCertOpsEnabled: useCertOpsEnabledMock,
  useCertOpsCanManage: useCertOpsCanManageMock,
}));

vi.mock('../../src/components/certops/certopsAgentsApi', () => ({
  listAgents: listAgentsMock,
  listBootstrapTokens: listBootstrapTokensMock,
}));

vi.mock('../../src/components/certops/certopsTokensApi', () => ({
  listApiTokens: listApiTokensMock,
}));

vi.mock('../../src/components/certops/certopsJobsApi', () => ({
  listJobs: vi.fn(),
  listJobLog: vi.fn(),
  listJobEvidence: vi.fn(),
  getJob: vi.fn(),
}));

import {
  useCertOpsAgents,
  useCertOpsBootstrapTokens,
} from '../../src/components/certops/useCertOpsAgents.js';
import { useCertOpsApiTokens } from '../../src/components/certops/useCertOpsJobs.js';

/** The envelope the server sends when the caller requested no page. */
function envelope(items) {
  return {
    items,
    pagination: { limit: null, offset: 0, total: items.length },
  };
}

const CASES = [
  {
    label: 'useCertOpsAgents',
    hook: useCertOpsAgents,
    listMock: listAgentsMock,
    itemsKey: 'agents',
    row: { id: 'row-1', agentId: 'agent-1', name: 'dc1-edge' },
    errorMessage: 'Could not load certificate operations agents.',
  },
  {
    label: 'useCertOpsBootstrapTokens',
    hook: useCertOpsBootstrapTokens,
    listMock: listBootstrapTokensMock,
    itemsKey: 'tokens',
    row: { id: 'bt-1', name: 'dc1-edge', status: 'active' },
    errorMessage: 'Could not load agent bootstrap tokens.',
  },
  {
    label: 'useCertOpsApiTokens',
    hook: useCertOpsApiTokens,
    listMock: listApiTokensMock,
    itemsKey: 'tokens',
    row: { id: 'tok-1', name: 'certbot-prod', status: 'active' },
    errorMessage: 'Could not load certificate operations API tokens.',
  },
];

describe.each(CASES)(
  '$label list envelope',
  ({ hook, listMock, itemsKey, row, errorMessage }) => {
    beforeEach(() => {
      vi.clearAllMocks();
      useWorkspaceMock.mockReturnValue({ workspaceId: 'ws-1' });
      useCertOpsEnabledMock.mockReturnValue(true);
      useCertOpsCanManageMock.mockReturnValue(true);
    });

    it('reads items and carries the unpaginated total', async () => {
      listMock.mockResolvedValue(envelope([row]));

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.loading).toBe(false));
      expect(result.current[itemsKey]).toEqual([row]);
      expect(result.current.pagination).toEqual({
        limit: null,
        offset: 0,
        total: 1,
      });
      expect(result.current.error).toBe('');
    });

    it('keeps a truncated page total distinct from the rows on hand', async () => {
      listMock.mockResolvedValue({
        items: [row],
        pagination: { limit: 1, offset: 0, total: 57 },
      });

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.loading).toBe(false));
      expect(result.current[itemsKey]).toHaveLength(1);
      expect(result.current.pagination.total).toBe(57);
    });

    it('stays loading with no pagination until the response arrives', async () => {
      let resolveList;
      listMock.mockImplementation(
        () =>
          new Promise(resolve => {
            resolveList = resolve;
          })
      );

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.loading).toBe(true));
      expect(result.current[itemsKey]).toEqual([]);
      expect(result.current.pagination).toBeNull();

      resolveList(envelope([row]));
      await waitFor(() => expect(result.current.loading).toBe(false));
      expect(result.current.pagination.total).toBe(1);
    });

    it('reports a failure as an error rather than an empty list with a zero total', async () => {
      listMock.mockRejectedValue(
        Object.assign(new Error('boom'), {
          response: { status: 500, data: { error: 'Internal error' } },
        })
      );

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.error).toBe('Internal error'));
      expect(result.current.loading).toBe(false);
      expect(result.current[itemsKey]).toEqual([]);
      expect(result.current.pagination).toBeNull();
    });

    it('falls back to a readable message when the failure carries no detail', async () => {
      listMock.mockRejectedValue({});

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.error).toBe(errorMessage));
    });

    it('does not call the manager-only endpoint for a viewer, and reports no total', async () => {
      useCertOpsCanManageMock.mockReturnValue(false);

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.loading).toBe(false));
      expect(listMock).not.toHaveBeenCalled();
      expect(result.current[itemsKey]).toEqual([]);
      expect(result.current.pagination).toBeNull();
      expect(result.current.error).toBe('');
    });

    it('reports no total while CertOps availability is unresolved', async () => {
      useCertOpsEnabledMock.mockReturnValue(null);

      const { result } = renderHook(() => hook());

      await waitFor(() => expect(result.current.enabled).toBeNull());
      expect(listMock).not.toHaveBeenCalled();
      expect(result.current.pagination).toBeNull();
    });
  }
);
