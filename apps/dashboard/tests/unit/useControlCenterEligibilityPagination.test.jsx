import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useControlCenterData } from '../../src/hooks/useControlCenterData.js';

const { getMock, getTokensMock, selectWorkspaceMock, workspaceState } =
  vi.hoisted(() => ({
    getMock: vi.fn(),
    getTokensMock: vi.fn(),
    selectWorkspaceMock: vi.fn(),
    workspaceState: { id: 'ws-1' },
  }));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({
    workspaceId: workspaceState.id,
    selectWorkspace: selectWorkspaceMock,
  }),
}));

vi.mock('../../src/utils/apiClient', () => ({
  default: { get: getMock },
  API_ENDPOINTS: {
    ALERT_QUEUE: '/queue',
    ALERT_STATS: '/stats',
    ACCOUNT_PLAN: '/plan',
    WORKSPACE_CONTROL_CENTER_ALERT_ACTIVITY: id => `/activity/${id}`,
    WORKSPACE_CONTROL_CENTER_ALERT_ELIGIBILITY_SUMMARY: id =>
      `/eligibility-summary/${id}`,
  },
  tokenAPI: { getTokens: getTokensMock },
  alertAPI: { requeueAlerts: vi.fn() },
  workspaceAPI: { listMembers: vi.fn().mockResolvedValue({ items: [] }) },
  formatDate: value => String(value),
}));

describe('Control Center eligibility paging', () => {
  beforeEach(() => {
    workspaceState.id = 'ws-1';
    getMock.mockReset();
    getTokensMock.mockReset();
    getMock.mockImplementation(async url => {
      if (url.startsWith('/api/v1/workspaces?')) {
        return {
          data: {
            items: [
              { id: 'ws-1', name: 'Workspace', role: 'admin' },
              { id: 'ws-2', name: 'Second', role: 'admin' },
            ],
          },
        };
      }
      if (url === '/eligibility-summary/ws-2') {
        return {
          data: {
            total: 3,
            counts: { outside_threshold: 1, due: 1, suppressed: 1 },
          },
        };
      }
      if (url.startsWith('/eligibility-summary/')) {
        return {
          data: {
            total: 14,
            counts: { outside_threshold: 11, due: 2, suppressed: 1 },
          },
        };
      }
      if (url === '/queue') return { data: { alerts: [] } };
      if (url === '/stats') return { data: { byChannel: [], monthUsage: 0 } };
      if (url === '/plan') return { data: { plan: 'oss' } };
      if (url.startsWith('/activity/')) {
        return { data: { items: [], pagination: { hasMore: false } } };
      }
      return { data: {} };
    });
    getTokensMock.mockImplementation(
      async ({ workspace_id, limit, offset }) => ({
        total: workspace_id === 'ws-2' ? 3 : 14,
        items: Array.from(
          {
            length: Math.max(
              0,
              Math.min(limit, (workspace_id === 'ws-2' ? 3 : 14) - offset)
            ),
          },
          (_, index) => ({
            id: offset + index + 1,
            alert_state: { eligibility: { status: 'outside_threshold' } },
          })
        ),
      })
    );
  });

  it('resets to the first server page when the workspace changes', async () => {
    const { result, rerender } = renderHook(() => useControlCenterData());
    await waitFor(() =>
      expect(result.current.eligibilityAssets).toHaveLength(10)
    );
    act(() => result.current.changeEligibilityPage({ limit: 10, offset: 10 }));
    await waitFor(() => expect(result.current.eligibilityOffset).toBe(10));
    workspaceState.id = 'ws-2';
    rerender();
    await waitFor(() =>
      expect(result.current.selectedWorkspaceId).toBe('ws-2')
    );
    await waitFor(() =>
      expect(result.current.eligibilityAssets).toHaveLength(3)
    );
    expect(getTokensMock).toHaveBeenLastCalledWith({
      workspace_id: 'ws-2',
      limit: 10,
      offset: 0,
      sort: 'expiration_asc',
    });
    expect(result.current.eligibilitySummary).toEqual({
      outside_threshold: 1,
      due: 1,
      suppressed: 1,
    });
  });

  it('does not append an in-flight A load-more page after switching to B', async () => {
    const existingGet = getMock.getMockImplementation();
    let resolveOldPage;
    let aRequests = 0;
    getMock.mockImplementation(url => {
      if (url === '/activity/ws-1') {
        ++aRequests;
        if (aRequests === 1) {
          return Promise.resolve({
            data: { items: [{ id: 'a:1' }], pagination: { hasMore: true } },
          });
        }
        return new Promise(resolve => {
          resolveOldPage = resolve;
        });
      }
      if (url === '/activity/ws-2') {
        return Promise.resolve({
          data: { items: [{ id: 'b:1' }], pagination: { hasMore: false } },
        });
      }
      return existingGet(url);
    });
    const { result, rerender } = renderHook(() => useControlCenterData());
    await waitFor(() =>
      expect(result.current.alertActivity.map(item => item.id)).toEqual(['a:1'])
    );
    act(() => {
      result.current.loadMoreAlertActivity();
    });
    await waitFor(() => expect(resolveOldPage).toBeTypeOf('function'));
    act(() => {
      workspaceState.id = 'ws-2';
      rerender();
    });
    await waitFor(() =>
      expect(result.current.alertActivity.map(item => item.id)).toEqual(['b:1'])
    );
    await act(async () => {
      resolveOldPage({
        data: { items: [{ id: 'a:2' }], pagination: { hasMore: false } },
      });
    });
    expect(result.current.alertActivity.map(item => item.id)).toEqual(['b:1']);
    expect(result.current.alertActivityError).toBe('');
  });

  it('falls back to the existing paginated token API when the new summary route is 404', async () => {
    const existingGet = getMock.getMockImplementation();
    getMock.mockImplementation(url =>
      url.startsWith('/eligibility-summary/')
        ? Promise.reject({ response: { status: 404 } })
        : existingGet(url)
    );
    const { result } = renderHook(() => useControlCenterData());
    await waitFor(() =>
      expect(result.current.eligibilityAssets).toHaveLength(10)
    );
    expect(result.current.error).toBe('');
    expect(result.current.eligibilitySummary).toEqual({
      outside_threshold: 14,
      due: 0,
      suppressed: 0,
    });
    expect(getTokensMock).toHaveBeenCalledWith({
      workspace_id: 'ws-1',
      limit: 500,
      offset: 0,
    });
    expect(result.current.eligibilityTotal).toBe(14);
  });

  it('requests only the server page while keeping whole-workspace counters', async () => {
    const { result } = renderHook(() => useControlCenterData());
    await waitFor(() =>
      expect(result.current.eligibilityAssets).toHaveLength(10)
    );
    expect(getTokensMock).toHaveBeenCalledWith({
      workspace_id: 'ws-1',
      limit: 10,
      offset: 0,
      sort: 'expiration_asc',
    });
    expect(result.current.eligibilitySummary).toEqual({
      outside_threshold: 11,
      due: 2,
      suppressed: 1,
    });

    act(() => result.current.changeEligibilityPage({ limit: 10, offset: 10 }));
    await waitFor(() =>
      expect(result.current.eligibilityAssets).toHaveLength(4)
    );
    expect(getTokensMock).toHaveBeenLastCalledWith({
      workspace_id: 'ws-1',
      limit: 10,
      offset: 10,
      sort: 'expiration_asc',
    });
    expect(result.current.eligibilitySummary.due).toBe(2);

    act(() => result.current.changeEligibilityPage({ limit: 20, offset: 0 }));
    await waitFor(() =>
      expect(result.current.eligibilityAssets).toHaveLength(14)
    );
    expect(getTokensMock).toHaveBeenLastCalledWith({
      workspace_id: 'ws-1',
      limit: 20,
      offset: 0,
      sort: 'expiration_asc',
    });
    expect(
      getMock.mock.calls.filter(([url]) =>
        url.startsWith('/eligibility-summary/')
      )
    ).toHaveLength(1);
  });
});
