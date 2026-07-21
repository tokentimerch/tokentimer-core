import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import apiClient, { API_ENDPOINTS } from '../utils/apiClient.js';
import { useWorkspace } from '../utils/WorkspaceContext.jsx';

/**
 * @typedef {'loading'|'refreshing'|'error'|'partial'|'empty'|'unauthorized'} ControlCenterStatus
 */

/** @type {ReadonlyArray<ControlCenterStatus>} */
export const CONTROL_CENTER_STATUSES = Object.freeze([
  'loading',
  'refreshing',
  'error',
  'partial',
  'empty',
  'unauthorized',
]);

/**
 * @typedef {object} ControlCenterStatsBuckets
 * @property {number} healthy
 * @property {number} neverExpires
 * @property {number} expiring7
 * @property {number} expiring8To30
 * @property {number} expired
 * @property {number} critical
 */

/**
 * @typedef {object} ControlCenterStatsSource
 * @property {string} key
 * @property {string} name
 * @property {number} count
 */

/**
 * @typedef {object} ControlCenterNeedsAttentionItem
 * @property {number} id
 * @property {string} name
 * @property {string} type
 * @property {string} category
 * @property {string|null} expiresAt
 * @property {number|null} [daysLeft]
 * @property {string} [bucket]
 */

/**
 * @typedef {object} ControlCenterStatsData
 * @property {number} totalAssets
 * @property {ControlCenterStatsBuckets} buckets
 * @property {ControlCenterStatsSource[]} sources
 * @property {ControlCenterNeedsAttentionItem[]} needsAttention
 * @property {string} generatedAt
 * @property {boolean} isComplete
 */
/**
 * @param {{
 *   isLoading: boolean,
 *   isRefreshing: boolean,
 *   isError: boolean,
 *   isUnauthorized: boolean,
 *   isPartial: boolean,
 *   isEmpty: boolean,
 * }} flags
 * @returns {ControlCenterStatus | null}
 */
function resolveControlCenterStatus(flags) {
  if (flags.isUnauthorized) return 'unauthorized';
  if (flags.isError) return 'error';
  if (flags.isLoading) return 'loading';
  if (flags.isRefreshing) return 'refreshing';
  if (flags.isPartial) return 'partial';
  if (flags.isEmpty) return 'empty';
  return null;
}

/**
 * Fetch workspace-scoped Control Center stats from the API.
 *
 * @returns {{
 *   data: ControlCenterStatsData | null,
 *   status: ControlCenterStatus | null,
 *   isLoading: boolean,
 *   isRefreshing: boolean,
 *   isError: boolean,
 *   isPartial: boolean,
 *   isEmpty: boolean,
 *   isUnauthorized: boolean,
 *   error: string | null,
 *   refetch: () => Promise<void>,
 * }}
 */
export function useControlCenterStats() {
  const { workspaceId } = useWorkspace();
  const [data, setData] = useState(
    /** @type {ControlCenterStatsData | null} */ (null)
  );
  const [error, setError] = useState(/** @type {string | null} */ (null));
  const [isUnauthorized, setIsUnauthorized] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const loadGenerationRef = useRef(0);

  const fetchStats = useCallback(
    async (isRefresh = false) => {
      if (!workspaceId) {
        setData(null);
        setError(null);
        setIsUnauthorized(false);
        setIsLoading(false);
        setIsRefreshing(false);
        return;
      }

      const generation = ++loadGenerationRef.current;

      try {
        if (isRefresh) {
          setIsRefreshing(true);
        } else {
          setIsLoading(true);
        }
        setError(null);
        setIsUnauthorized(false);

        const response = await apiClient.get(
          API_ENDPOINTS.WORKSPACE_CONTROL_CENTER_STATS(workspaceId),
          { _suppressLog: isRefresh }
        );

        if (generation !== loadGenerationRef.current) return;

        setData(response?.data ?? null);
      } catch (err) {
        if (generation !== loadGenerationRef.current) return;

        const httpStatus = err?.response?.status;
        const message =
          err?.response?.data?.error ||
          err?.message ||
          'Failed to load control center stats';

        if (httpStatus === 403) {
          setIsUnauthorized(true);
          setError(message);
          setData(null);
          return;
        }

        setIsUnauthorized(false);
        setError(message);
        if (!isRefresh) {
          setData(null);
        }
      } finally {
        if (generation === loadGenerationRef.current) {
          setIsLoading(false);
          setIsRefreshing(false);
        }
      }
    },
    [workspaceId]
  );

  useEffect(() => {
    fetchStats(false);
  }, [fetchStats]);

  const isError = Boolean(error) && !isUnauthorized;
  const isPartial = Boolean(data && data.isComplete === false);
  const isEmpty =
    Boolean(data) &&
    !isLoading &&
    !isRefreshing &&
    !isError &&
    !isUnauthorized &&
    Number(data?.totalAssets) === 0;

  const status = useMemo(
    () =>
      resolveControlCenterStatus({
        isLoading,
        isRefreshing,
        isError,
        isUnauthorized,
        isPartial,
        isEmpty,
      }),
    [isLoading, isRefreshing, isError, isUnauthorized, isPartial, isEmpty]
  );

  const refetch = useCallback(() => fetchStats(true), [fetchStats]);

  return {
    data,
    status,
    isLoading,
    isRefreshing,
    isError,
    isPartial,
    isEmpty,
    isUnauthorized,
    error,
    refetch,
  };
}

const PAGINATED_LIST_PAGE_SIZE = 20;

/**
 * Infinite-scroll pagination for a Control Center list endpoint (e.g.
 * perpetual assets or scopes/privileges) that returns `{ items, total,
 * hasMore }`. Seeds its initial page from the values already embedded in
 * the aggregate `/control-center/stats` payload so the list renders
 * immediately, without an extra round trip on first paint.
 *
 * @param {(workspaceId: string) => string} endpointFn
 * @param {{ items: Array<object>, hasMore: boolean }} seed
 * @returns {{
 *   items: Array<object>,
 *   hasMore: boolean,
 *   isLoadingMore: boolean,
 *   error: string | null,
 *   loadMore: () => Promise<void>,
 * }}
 */
export function useControlCenterListPage(endpointFn, seed) {
  const { workspaceId } = useWorkspace();
  const [items, setItems] = useState(seed.items);
  const [hasMore, setHasMore] = useState(seed.hasMore);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [error, setError] = useState(/** @type {string | null} */ (null));
  const seedKeyRef = useRef(null);
  const inFlightRef = useRef(false);

  // Re-seed whenever the underlying stats payload changes (e.g. a manual
  // refresh, or switching workspaces) rather than on every render, so
  // in-progress infinite-scroll pagination isn't reset by unrelated
  // re-renders.
  const seedKey = `${workspaceId || ''}:${seed.items.length}:${seed.hasMore}`;
  if (seedKeyRef.current !== seedKey) {
    seedKeyRef.current = seedKey;
    if (items !== seed.items) {
      setItems(seed.items);
      setHasMore(seed.hasMore);
      setError(null);
    }
  }

  const loadMore = useCallback(async () => {
    if (!workspaceId || inFlightRef.current || !hasMore) return;
    inFlightRef.current = true;
    setIsLoadingMore(true);
    setError(null);
    try {
      const response = await apiClient.get(endpointFn(workspaceId), {
        params: { limit: PAGINATED_LIST_PAGE_SIZE, offset: items.length },
        _suppressLog: true,
      });
      const page = response?.data || {};
      const nextItems = Array.isArray(page.items) ? page.items : [];
      setItems(prev => {
        const seen = new Set(prev.map(item => item.id));
        const deduped = nextItems.filter(item => !seen.has(item.id));
        return [...prev, ...deduped];
      });
      setHasMore(Boolean(page.hasMore));
    } catch (err) {
      const message =
        err?.response?.data?.error ||
        err?.message ||
        'Failed to load more items';
      setError(message);
    } finally {
      inFlightRef.current = false;
      setIsLoadingMore(false);
    }
  }, [workspaceId, hasMore, items.length, endpointFn]);

  return { items, hasMore, isLoadingMore, error, loadMore };
}
