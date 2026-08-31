/**
 * Match the dashboard: always forward scan_id so import can attribute
 * provenance even when this run skips cleanup. Without it, cleanup-off
 * imports stay unattributed and a later cleanup-on run used to insert
 * a duplicate the cleanup engine could never reach.
 */
export function buildAutoSyncImportBody({ items, scanId, cleanup }) {
  return {
    items: Array.isArray(items) ? items : [],
    ...(scanId ? { scan_id: scanId } : {}),
    ...(cleanup ? { cleanup } : {}),
  };
}

/**
 * GitLab's PAT list still returns revoked tokens. Cleanup keys off "was this
 * id in the scan", so a cleanup-on sync that also sends includeRevoked:true
 * will keep every token the user just revoked. Force that filter off for
 * the discovery pass that cleanup will consume.
 */
export function gitlabFiltersForAutoSync(filters, cleanupObsolete) {
  const next = {
    ...(filters && typeof filters === "object" ? filters : {}),
  };
  if (cleanupObsolete) {
    next.includeRevoked = false;
  }
  return next;
}
