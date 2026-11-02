import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import useDistributionSummaries from '../../src/components/certops/useDistributionSummaries.js';
const { get } = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock('../../src/utils/apiClient', () => ({ default: { get } }));
const cert = { id: 'cert', identityId: 'identity' };
const group = (summary = { total: 3, verified: 3 }) => ({
  id: 'group',
  current_identity_id: 'identity',
  managed_certificate_id: 'cert',
  summary,
});
const response = (groups = [group()], extra = {}) => ({
  data: { groups, evaluated_at: new Date().toISOString(), ...extra },
});
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const flush = async () => {
  await act(async () => {});
};
beforeEach(() => {
  get.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

it('batches 60 certificates and matches only authoritative IDs including rotated identity guards', async () => {
  const certificates = Array.from({ length: 60 }, (_, i) => ({
    id: `cert-${i}`,
    identityId: `identity-${i}`,
    commonName: 'same.example',
  }));
  get.mockResolvedValue(
    response([
      {
        ...group({ total: 5, verified: 3, pending: 2 }),
        current_identity_id: 'identity-1',
        managed_certificate_id: 'source-1',
      },
    ])
  );
  const { result, rerender } = renderHook(
    ({ items }) => useDistributionSummaries('workspace', items),
    { initialProps: { items: certificates } }
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
  rerender({ items: [...certificates].reverse() });
  expect(get).toHaveBeenCalledTimes(1);
});

it('bounds each batch at 200 IDs without per-certificate reads', async () => {
  get.mockResolvedValue(response([]));
  const { result } = renderHook(() =>
    useDistributionSummaries(
      'workspace',
      Array.from({ length: 401 }, (_, i) => ({ id: `cert-${i}` }))
    )
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(get).toHaveBeenCalledTimes(3);
  expect(
    get.mock.calls.map(
      ([, config]) => config.params.managedCertificateIds.split(',').length
    )
  ).toEqual([200, 200, 1]);
});

it('keeps the previous summary during manual refresh and coalesces overlapping reads', async () => {
  get.mockResolvedValueOnce(response());
  const pending = deferred();
  get.mockReturnValueOnce(pending.promise);
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  let first, second;
  act(() => {
    first = result.current.refresh();
    second = result.current.refresh();
  });
  await flush();
  expect(first).toBe(second);
  expect(get).toHaveBeenCalledTimes(2);
  expect(result.current.refreshing).toBe(true);
  expect(result.current.loading).toBe(false);
  expect(result.current.getSummary(cert)).toMatchObject({
    total: 3,
    verified: 3,
    status: 'verified',
  });
  await act(async () =>
    pending.resolve(response([group({ total: 3, verified: 1, pending: 2 })]))
  );
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 1,
    status: 'partial',
  });
});

it('retains cached data on refresh failure, marks it unconfirmed, and recovers', async () => {
  get
    .mockResolvedValueOnce(response())
    .mockRejectedValueOnce(new Error('offline'));
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  await act(async () => result.current.refresh());
  expect(result.current.error).toBe('Deployment status unavailable');
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 3,
    staleData: true,
  });
  get.mockResolvedValue(
    response([group({ total: 3, verified: 0, failed: 3 })])
  );
  await act(async () => result.current.refresh());
  expect(result.current.error).toBe('');
  expect(result.current.getSummary(cert)).toMatchObject({
    status: 'failed',
    staleData: false,
  });
});

it('does not mistake an initial failure for not distributed', async () => {
  get.mockRejectedValue(new Error('forbidden'));
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.error).toBe('Deployment status unavailable');
  expect(result.current.getSummary(cert)).toBeNull();
});

it('never exposes another workspace or certificate scope and drops late responses', async () => {
  const old = deferred();
  get.mockReturnValueOnce(old.promise).mockResolvedValue(response([]));
  const { result, rerender } = renderHook(
    ({ workspace, items }) => useDistributionSummaries(workspace, items),
    { initialProps: { workspace: 'a', items: [cert] } }
  );
  await flush();
  const oldSignal = get.mock.calls[0][1].signal;
  rerender({ workspace: 'b', items: [cert] });
  expect(oldSignal.aborted).toBe(true);
  expect(result.current.getSummary(cert)).toBeNull();
  await waitFor(() => expect(result.current.loading).toBe(false));
  await act(async () => old.resolve(response()));
  expect(result.current.getSummary(cert).status).toBe('not_distributed');
  const next = deferred();
  get.mockReturnValueOnce(next.promise);
  rerender({ workspace: 'b', items: [{ id: 'other' }] });
  expect(result.current.getSummary(cert)).toBeNull();
  await act(async () => next.resolve(response([])));
  rerender({ workspace: null, items: [cert] });
  expect(result.current.getSummary(cert)).toBeNull();
  expect(result.current.loading).toBe(false);
});

it('polls without clearing data and does not overlap automatic/manual requests', async () => {
  vi.useFakeTimers();
  get.mockResolvedValueOnce(response());
  const pending = deferred();
  get.mockReturnValueOnce(pending.promise);
  const { result, unmount } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await flush();
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(result.current.loading).toBe(false);
  expect(result.current.getSummary(cert)).not.toBeNull();
  act(() => {
    result.current.refresh();
    result.current.refresh();
  });
  await act(async () => vi.advanceTimersByTimeAsync(60_000));
  expect(get).toHaveBeenCalledTimes(2);
  const signal = get.mock.calls[1][1].signal;
  unmount();
  expect(signal.aborted).toBe(true);
  await act(async () => pending.resolve(response()));
  await vi.advanceTimersByTimeAsync(60_000);
  expect(get).toHaveBeenCalledTimes(2);
});

it('expires exactly the affected verified counts between polls, including certificate expiry and server clock skew', async () => {
  vi.useFakeTimers();
  vi.setSystemTime('2026-10-19T12:00:00Z');
  const serverTime = Date.now() - 3600_000;
  get.mockResolvedValue(
    response(
      [
        group({
          total: 3,
          verified: 3,
          verification_expirations: [
            serverTime + 5000,
            serverTime + 10000,
            serverTime + 60000,
          ],
        }),
      ],
      { evaluated_at: new Date(serverTime).toISOString() }
    )
  );
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await flush();
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 3,
    status: 'verified',
  });
  await act(async () => vi.advanceTimersByTimeAsync(5000));
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 2,
    stale: 1,
    status: 'stale',
  });
  await act(async () => vi.advanceTimersByTimeAsync(5000));
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 1,
    stale: 2,
    status: 'stale',
  });
  expect(get).toHaveBeenCalledTimes(1);
});

it('expires file installation evidence separately from live service verification', async () => {
  vi.useFakeTimers();
  const now = Date.now();
  get.mockResolvedValue(
    response([
      group({
        total: 2,
        verified: 1,
        installed: 1,
        verification_expirations: [now + 20000],
        installation_expirations: [now + 5000],
      }),
    ])
  );
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await flush();
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 1,
    installed: 1,
    status: 'completed',
  });
  await act(async () => vi.advanceTimersByTimeAsync(5000));
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 1,
    installed: 0,
    stale: 1,
    status: 'stale',
  });
});

it('never promotes backend non-convergence even with a successful historical job', async () => {
  get.mockResolvedValue(
    response([
      group({
        total: 1,
        verified: 0,
        pending: 1,
        verification_expirations: [],
      }),
    ])
  );
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await waitFor(() => expect(result.current.loading).toBe(false));
  expect(result.current.getSummary(cert)).toMatchObject({
    verified: 0,
    status: 'pending',
  });
});

it('fails closed for older servers without freshness metadata when refresh hangs', async () => {
  vi.useFakeTimers();
  get.mockResolvedValueOnce(response());
  const pending = deferred();
  get.mockReturnValueOnce(pending.promise);
  const { result } = renderHook(() =>
    useDistributionSummaries('workspace', [cert])
  );
  await flush();
  await act(async () => vi.advanceTimersByTimeAsync(30_000));
  expect(result.current.getSummary(cert).status).toBe('unavailable');
});

it('pauses hidden-tab polling and revalidates once when it becomes visible', async () => {
  vi.useFakeTimers();
  const visibility = vi.spyOn(document, 'visibilityState', 'get');
  visibility.mockReturnValue('hidden');
  get.mockResolvedValue(response([]));
  renderHook(() => useDistributionSummaries('workspace', [cert]));
  await flush();
  await act(async () => vi.advanceTimersByTimeAsync(90_000));
  expect(get).toHaveBeenCalledTimes(1);
  visibility.mockReturnValue('visible');
  await act(async () => document.dispatchEvent(new Event('visibilitychange')));
  expect(get).toHaveBeenCalledTimes(2);
  await act(async () => document.dispatchEvent(new Event('visibilitychange')));
  expect(get).toHaveBeenCalledTimes(2);
});

it.each([401, 403, 404])(
  'discards cached metadata after HTTP %i instead of treating it as an access grant',
  async status => {
    get
      .mockResolvedValueOnce(response())
      .mockRejectedValueOnce({ response: { status } });
    const { result } = renderHook(() =>
      useDistributionSummaries('workspace', [cert])
    );
    await waitFor(() => expect(result.current.loading).toBe(false));
    await act(async () => result.current.refresh());
    expect(result.current.getSummary(cert)).toBeNull();
    expect(result.current.error).toBe('Deployment status unavailable');
  }
);
