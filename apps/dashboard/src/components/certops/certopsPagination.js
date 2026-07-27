/**
 * Truncation caption helper for CertOps lists that are deliberately capped.
 *
 * These endpoints return `pagination: { limit, offset, total }`, where a null
 * limit means the caller requested no page and the whole result set is present.
 *
 * Use this only where the cap is the intended design and the extra rows are not
 * meant to be reachable in place: the recent-activity feeds inside a
 * certificate's timeline and an evidence bundle, which are context for the
 * record in view, not browsable lists. A list an operator is expected to work
 * through gets a real page control (DashboardPagination) instead, because a
 * caption tells them rows exist without offering any way to see them.
 */

/**
 * Human-readable truncation summary for a paginated list, or null when the
 * list is not truncated (nothing to indicate).
 *
 * - When the API reports a `total` greater than the shown count:
 *   "Showing 20 of 57 jobs".
 * - When the API reports `hasMore: true`, or the page came back full
 *   (shown >= limit, so more items may exist beyond this page):
 *   "Showing first 20 jobs".
 *
 * @param {{ shown: number, pagination: { limit?: number, offset?: number, total?: number, hasMore?: boolean }|null|undefined, noun: string }} options
 * @returns {string|null}
 */
export function truncationSummary({ shown, pagination, noun }) {
  if (!pagination || !Number.isFinite(shown) || shown <= 0) return null;

  const total = Number(pagination.total);
  if (Number.isFinite(total) && total > shown) {
    return `Showing ${shown} of ${total} ${noun}`;
  }

  const limit = Number(pagination.limit);
  const pageIsFull = Number.isFinite(limit) && limit > 0 && shown >= limit;
  if (pagination.hasMore === true || (!Number.isFinite(total) && pageIsFull)) {
    return `Showing first ${shown} ${noun}`;
  }

  return null;
}
