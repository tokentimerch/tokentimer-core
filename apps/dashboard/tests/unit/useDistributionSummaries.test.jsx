import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import useDistributionSummaries from '../../src/components/certops/useDistributionSummaries.js';
const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../src/utils/apiClient', () => ({ default: { get } }));
beforeEach(() => {
  get.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

it('batches the visible page and relates groups only by authoritative IDs', async () => {
  const certificates = Array.from({ length: 60 }, (_, i) => ({
    id: `cert-${i}`,
    identityId: `identity-${i}`,
    commonName: 'same.example',
  }));
  get.mockResolvedValue({
    data: {
      groups: [
        {
          id: 'group',
          current_identity_id: 'identity-1',
          managed_certificate_id: 'source-1',
          summary: { total: 5, verified: 3, pending: 2 },
        },
      ],
    },
  });
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', certificates)
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(get).toHaveBeenCalledTimes(1);
  expect(get.mock.calls[0][1].params.identityIds.split(',')).toHaveLength(60);
  expect(result.current.getSummary(certificates[1])).toMatchObject({
    total: 5,
    verified: 3,
    status: 'partial',
  });
  expect(result.current.getSummary(certificates[0]).status).toBe(
    'not_distributed'
  );
  expect(
    result.current.getSummary({
      id: 'source-1',
      expectedIdentityId: 'old-identity',
    }).status
  ).toBe('not_distributed');
});

it('does not mistake a failed read for not distributed and hides previous workspace data', async () => {
  get
    .mockResolvedValueOnce({ data: { groups: [] } })
    .mockRejectedValueOnce(new Error('offline'));
  const { result, rerender } = renderHook(
    ({ workspace }) => useDistributionSummaries(workspace, [{ id: 'cert' }]),
    { initialProps: { workspace: 'workspace-a' } }
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  rerender({ workspace: 'workspace-b' });
  expect(result.current.getSummary({ id: 'cert' })).toBeNull();
  await waitFor(() =>
    expect(result.current.error).toBe('Deployment status unavailable')
  );
  expect(result.current.getSummary({ id: 'cert' })).toBeNull();
});

it('refreshes current verification rather than retaining a historic green badge', async () => {
  const certificate = { id: 'cert' };
  const group = {
    managed_certificate_id: 'cert',
    summary: { total: 1, verified: 1 },
  };
  get.mockResolvedValue({ data: { groups: [group] } });
  vi.useFakeTimers();
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [certificate])
  );
  await act(async () => {});
  get.mockResolvedValue({
    data: {
      groups: [{ ...group, summary: { total: 1, verified: 0, stale: 1 } }],
    },
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(30_000);
  });
  expect(result.current.getSummary(certificate)).toMatchObject({
    verified: 0,
    status: 'stale',
  });
});
