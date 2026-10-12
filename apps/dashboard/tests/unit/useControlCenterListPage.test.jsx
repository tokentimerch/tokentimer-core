import { renderHook, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { useControlCenterListPage } from '../../src/hooks/useControlCenterStats.js';

const { getMock, workspaceIdRef } = vi.hoisted(() => ({
  getMock: vi.fn(),
  workspaceIdRef: { current: 'workspace-1' },
}));

vi.mock('../../src/utils/apiClient.js', () => ({
  default: { get: getMock },
}));

vi.mock('../../src/utils/WorkspaceContext.jsx', () => ({
  useWorkspace: () => ({ workspaceId: workspaceIdRef.current }),
}));

beforeEach(() => {
  getMock.mockReset();
  workspaceIdRef.current = 'workspace-1';
});

it('shows the stats seed on the first paint without waiting for a reseed', () => {
  const seed = {
    items: [
      { id: 1, name: 'Perpetual key' },
      { id: 2, name: 'Retainer' },
    ],
    hasMore: false,
  };

  const { result, rerender } = renderHook(
    ({ seed: nextSeed }) =>
      useControlCenterListPage(
        id => `/api/v1/workspaces/${id}/never-expires`,
        nextSeed
      ),
    {
      initialProps: {
        seed: { items: [], hasMore: false },
      },
    }
  );

  expect(result.current.items).toEqual([]);

  rerender({ seed });

  expect(result.current.items).toEqual(seed.items);
  expect(result.current.hasMore).toBe(false);
  expect(getMock).not.toHaveBeenCalled();
});

it('appends pages from the list endpoint when loading more', async () => {
  getMock.mockResolvedValue({
    data: {
      items: [{ id: 3, name: 'Third' }],
      hasMore: false,
    },
  });

  const seed = {
    items: [
      { id: 1, name: 'First' },
      { id: 2, name: 'Second' },
    ],
    hasMore: true,
  };

  const { result } = renderHook(() =>
    useControlCenterListPage(
      id => `/api/v1/workspaces/${id}/never-expires`,
      seed
    )
  );

  expect(result.current.items).toHaveLength(2);

  await result.current.loadMore();

  await waitFor(() => {
    expect(result.current.items.map(item => item.id)).toEqual([1, 2, 3]);
  });
  expect(result.current.hasMore).toBe(false);
  expect(getMock).toHaveBeenCalledWith(
    '/api/v1/workspaces/workspace-1/never-expires',
    expect.objectContaining({
      params: { limit: 20, offset: 2 },
    })
  );
});
