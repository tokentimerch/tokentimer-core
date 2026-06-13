import { useMemo } from 'react';
import {
  classifyExpiryBucket,
  computeDaysLeftUtc,
} from '../utils/expiryBuckets';

/**
 * @typedef {object} LoadedAssetMetrics
 * @property {number} total - Count used for inventory filter chips (loaded when incomplete).
 * @property {number} loaded - Assets currently loaded in the client.
 * @property {number} pending - Assets not yet loaded when the batch is incomplete.
 * @property {boolean} isComplete - Whether all workspace assets are loaded locally.
 * @property {number} workspaceTotal - Server-side total from category counts.
 * @property {number} expiring7
 * @property {number} expiring30
 * @property {number} critical
 * @property {number} expired
 * @property {number} healthy
 * @property {number} neverExpires
 * @property {number} dueSoon
 */

/**
 * Derive display metrics from loaded token records for inventory UI only.
 * When {@link LoadedAssetMetrics.isComplete} is false, counts reflect loaded assets.
 *
 * @param {Array<object>} [tokens] - Loaded token or asset records.
 * @param {{
 *   categoryCounts?: Record<string, number>,
 *   categoryHasMore?: Record<string, boolean>,
 *   categoryLoading?: Record<string, boolean>,
 * }} [options]
 * @returns {LoadedAssetMetrics}
 */
export function useLoadedAssetMetrics(tokens = [], options = {}) {
  const {
    categoryCounts = {},
    categoryHasMore = {},
    categoryLoading = {},
  } = options;

  return useMemo(() => {
    const loadedTokens = Array.isArray(tokens) ? tokens.filter(Boolean) : [];
    const loaded = loadedTokens.length;

    const workspaceTotal = Object.values(categoryCounts).reduce(
      (sum, count) => sum + (Number(count) || 0),
      0
    );

    const hasMore = Object.values(categoryHasMore).some(Boolean);
    const isLoading = Object.values(categoryLoading).some(Boolean);
    const isComplete =
      !hasMore &&
      !isLoading &&
      (workspaceTotal === 0 || loaded >= workspaceTotal);

    let expiring7 = 0;
    let expiring30 = 0;
    let critical = 0;
    let expired = 0;
    let healthy = 0;
    let neverExpires = 0;

    for (const token of loadedTokens) {
      const bucket = classifyExpiryBucket(computeDaysLeftUtc(token.expiresAt));
      switch (bucket) {
        case 'expired':
          expired += 1;
          critical += 1;
          break;
        case 'expiring7':
          expiring7 += 1;
          critical += 1;
          break;
        case 'expiring8To30':
          expiring30 += 1;
          break;
        case 'healthy':
          healthy += 1;
          break;
        case 'neverExpires':
          neverExpires += 1;
          break;
        default:
          break;
      }
    }

    const total = isComplete ? Math.max(workspaceTotal, loaded) : loaded;
    const pending = isComplete ? 0 : Math.max(workspaceTotal - loaded, 0);

    return {
      total,
      loaded,
      pending,
      isComplete,
      workspaceTotal,
      expiring7,
      expiring30,
      critical,
      expired,
      healthy,
      neverExpires,
      dueSoon: expiring7 + expiring30,
    };
  }, [tokens, categoryCounts, categoryHasMore, categoryLoading]);
}
