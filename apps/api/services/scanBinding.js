"use strict";

/**
 * Shared import-time helper: binds client-submitted import items to the
 * scan that actually discovered them, so a token's provenance always comes
 * from what the backend recorded during the scan (see integrationScans.js)
 * rather than from fields the client echoes back on the import request.
 *
 * Every provider's import route follows the same shape: build a
 * `{sourceKind, sourceObjectId}` pair per raw item, look those pairs up
 * against `integration_scan_items` for the submitted `scan_id`, and only
 * attribute source_* fields on the ones that match a real recorded row.
 * An item that doesn't match (no scan_id supplied, wrong scan_id, or the
 * item simply wasn't part of that scan) is imported the same way imports
 * always worked before this feature -- unattributed, and therefore never a
 * cleanup candidate. This is the deliberate "don't guess" behavior for
 * ambiguous/legacy-shaped imports.
 */

const { getScan, lookupScanItems } = require("./integrationScans");

/**
 * @param {Object} params
 * @param {string|null} params.scanId - Client-submitted scan_id, if any.
 * @param {string} params.workspaceId
 * @param {string} params.provider
 * @param {Array<{sourceKind: string, sourceObjectId: string}>} params.pairs - One entry per raw import item, in the same order.
 * @returns {Promise<{scan: Object|null, resolveForItem: (index: number) => (Object|null)}>}
 *   `resolveForItem(i)` returns the source_* fields to spread onto that
 *   item's token payload, or null if the item could not be bound.
 */
async function bindImportItemsToScan({ scanId, workspaceId, provider, pairs }) {
  if (!scanId || typeof scanId !== "string") {
    return { scan: null, resolveForItem: () => null };
  }
  const scan = await getScan({ scanId, workspaceId, provider });
  if (!scan) {
    return { scan: null, resolveForItem: () => null };
  }
  const recordedByKey = await lookupScanItems(scanId, pairs);
  return {
    scan,
    resolveForItem(index) {
      const pair = pairs[index];
      if (!pair) return null;
      const key = `${pair.sourceKind}::${pair.sourceObjectId}`;
      const recordedDimensions = recordedByKey.get(key);
      if (recordedDimensions === undefined) return null;
      return {
        source_provider: provider,
        source_instance: scan.source_instance,
        source_owner_key: scan.source_owner_key,
        source_kind: pair.sourceKind,
        source_dimensions: recordedDimensions,
        source_object_id: pair.sourceObjectId,
        source_observed_at: scan.started_at,
      };
    },
  };
}

module.exports = { bindImportItemsToScan };
