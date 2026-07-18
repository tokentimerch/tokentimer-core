/**
 * Truncation display helpers for paginated CertOps read APIs (M2).
 *
 * The job/log/evidence endpoints return `pagination: { limit, offset }` and
 * may later grow `total` / `hasMore`. Load-more is explicitly deferred; these
 * helpers only decide whether to render a "Showing X of Y" style indicator.
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
