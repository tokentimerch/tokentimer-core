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
