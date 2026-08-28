/**
 * Obsolete-token cleanup for integration imports and auto-sync.
 *
 * Cleanup runs against a backend-persisted `integration_scans` row (see
 * integrationScans.js), never against frontend-reconstructed
 * `scannedSources`/`scannedLocations`. The scan record is the single
 * authoritative statement of what was actually, completely scanned.
 *
 * Safety rules (all enforced inside one DB transaction):
 *   - The scan must exist, belong to this workspace/provider, be completed,
 *     and not already have been consumed by an earlier cleanup. The claim
 *     (`UPDATE ... WHERE cleanup_consumed_at IS NULL RETURNING`) is atomic,
 *     so a scan_id can drive at most one destructive cleanup even under
 *     concurrent requests.
 *   - Cleanup is refused unless the scan reports at least one *complete*
 *     sub-scope. "Complete" means fully enumerated, not "found something":
 *     a scan that legitimately finds zero items in a fully-scanned scope
 *     still cleans up everything in that scope, because that is a true
 *     obsolete-everything result. A sub-scope reported truncated/errored is
 *     never used as a deletion basis.
 *   - Candidate tokens are scoped by provider + instance + owner key (never
 *     just a provider prefix), so a second AWS account / Key Vault / GitHub
 *     Enterprise host / etc. in the same workspace is never touched by a
 *     scan of a different instance.
 *   - Candidate selection uses a NOT EXISTS anti-join against
 *     integration_scan_items for this scan_id (no giant IN-lists), so it
 *     scales with "how many tokens exist", not "how many locations were
 *     scanned".
 *   - Observation fence: a token is never deleted if its
 *     `source_observed_at` is newer than the cleanup-driving scan's
 *     `started_at`. This stops a stale/slow scan's cleanup from deleting
 *     something a newer, faster, concurrent scan just (re)discovered.
 *   - Legacy tokens (imported before per-instance provenance existed) have
 *     `source_provider IS NULL` and can never match any scope filter here,
 *     so they are structurally excluded from this cleanup path forever --
 *     not a "best effort", a hard exclusion by construction.
 *
 * Known, deliberate limitation: legacy tokens are never adopted into a new
 * scan's provenance by guessing. If a legacy token's underlying object is
 * rediscovered by a provenance-aware scan, the import path inserts a new,
 * fully-attributed row for it; the old ambiguous row is left alone and is
 * only ever removable by the user manually.
 */

const { pool } = require("../db/database");
const { writeAudit } = require("./audit");
const { logger } = require("../utils/logger");
const { claimScanForCleanup } = require("./integrationScans");

const KNOWN_PROVIDERS = [
  "github",
  "gitlab",
  "vault",
  "aws",
  "azure",
  "azure-ad",
  "gcp",
];

/**
 * Validates a cleanup request payload. Returns null when valid, otherwise
 * an error string suitable for a 400 response.
 *
 * Contract: `{ enabled: true, provider, scanId, reason? }`. The scan itself
 * (not this payload) carries the scope/completeness data; this object only
 * says "yes, run cleanup, driven by this scan".
 */
function validateCleanupRequest(cleanup) {
  if (cleanup === undefined || cleanup === null) return null;
  if (typeof cleanup !== "object" || Array.isArray(cleanup)) {
    return "cleanup must be an object";
  }
  if (cleanup.enabled !== true) return null;
  if (!KNOWN_PROVIDERS.includes(cleanup.provider)) {
    return `cleanup.provider must be one of: ${KNOWN_PROVIDERS.join(", ")}`;
  }
  if (typeof cleanup.scanId !== "string" || cleanup.scanId.trim() === "") {
    return "cleanup.scanId is required (cleanup must be driven by a completed backend scan)";
  }
  return null;
}

// A sub-scope's dimension filter narrows which candidate tokens fall inside
// it. Only keys the scan actually recorded are compared; a key absent from
// the sub-scope's dimensions means "not narrowed on this axis" for that
// provider (e.g. an AWS sub-scope with no `region` means "global, every
// region-independent resource"). `pathPrefix` (Vault) is a prefix match
// against the token's own recorded `path` dimension. `categories` (Vault)
// is a membership check against the token's own recorded `category`
// dimension, since a scan can narrow to more than one category at once.
// Everything else is exact-match.
function buildDimensionFilterSql(dimensions, paramOffset) {
  const clauses = [];
  const params = [];
  let p = paramOffset;
  const dims = dimensions && typeof dimensions === "object" ? dimensions : {};
  for (const [key, value] of Object.entries(dims)) {
    if (value === null || value === undefined || value === "") continue;
    if (key === "pathPrefix") {
      clauses.push(`(t.source_dimensions->>'path') LIKE $${p}`);
      params.push(`${String(value)}%`);
      p++;
    } else if (key === "categories") {
      const list = Array.isArray(value) ? value : [value];
      if (list.length === 0) continue;
      clauses.push(`(t.source_dimensions->>'category') = ANY($${p}::text[])`);
      params.push(list.map((v) => String(v)));
      p++;
    } else {
      clauses.push(`(t.source_dimensions->>'${key.replace(/[^a-zA-Z0-9_]/g, "")}') = $${p}`);
      params.push(String(value));
      p++;
    }
  }
  return { sql: clauses.length ? ` AND ${clauses.join(" AND ")}` : "", params };
}

/**
 * Deletes workspace tokens that belong to the scan's provider/instance/
 * owner, fall inside a sub-scope the scan reported complete, and were not
 * rediscovered by that scan -- all inside one transaction with the scan
 * claim, the delete, and the audit write.
 *
 * @returns {Promise<{deleted: Array<{id:number,name:string,location:string}>}>}
 */
async function cleanupObsoleteTokens({
  workspaceId,
  actorUserId,
  cleanup,
  reason = "import_cleanup",
}) {
  const deleted = [];
  if (!cleanup || cleanup.enabled !== true) return { deleted };
  const validationError = validateCleanupRequest(cleanup);
  if (validationError) {
    throw new Error(`Invalid cleanup request: ${validationError}`);
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const scan = await claimScanForCleanup({
      scanId: cleanup.scanId,
      workspaceId,
      provider: cleanup.provider,
      client,
    });
    if (!scan) {
      await client.query("ROLLBACK");
      logger.warn("Cleanup refused: scan not found, incomplete, or already consumed", {
        workspaceId,
        provider: cleanup.provider,
        scanId: cleanup.scanId,
      });
      return { deleted: [] };
    }

    const subScopes = Array.isArray(scan.cleanup_scope?.subScopes)
      ? scan.cleanup_scope.subScopes
      : [];
    const completeSubScopes = subScopes.filter((s) => s && s.complete === true);
    if (completeSubScopes.length === 0) {
      // The scan was claimed (consumed) even though it drove no deletions,
      // by design: a scan that produced nothing usable for cleanup should
      // not be replayable either, since replay-ability is exactly the
      // property claiming exists to remove.
      await client.query("COMMIT");
      logger.info("Cleanup ran but no sub-scope was complete; nothing deleted", {
        workspaceId,
        provider: cleanup.provider,
        scanId: cleanup.scanId,
      });
      return { deleted: [] };
    }

    for (const subScope of completeSubScopes) {
      // Dimension placeholders start after the 7 fixed params below ($1-$7),
      // so the offset here must stay in sync with that fixed param count.
      const { sql: dimensionSql, params: dimensionParams } =
        buildDimensionFilterSql(subScope.dimensions, 8);
      const params = [
        workspaceId,
        cleanup.provider,
        scan.source_instance,
        scan.source_owner_key,
        String(subScope.sourceKind),
        scan.id,
        scan.started_at,
        ...dimensionParams,
      ];
      // Anti-join: candidates are previously-imported tokens in this exact
      // provider/instance/owner/kind scope that have no matching row in
      // integration_scan_items for *this* scan -- i.e. not rediscovered.
      // The observation fence (source_observed_at <= scan.started_at)
      // excludes anything a newer, still-running concurrent scan already
      // touched, even if this (older, slower) scan is the one committing
      // first.
      const res = await client.query(
        `SELECT t.id, t.name, t.location
         FROM tokens t
         WHERE t.workspace_id = $1
           AND t.imported_at IS NOT NULL
           AND t.source_provider = $2
           AND t.source_instance = $3
           AND t.source_owner_key = $4
           AND t.source_kind = $5
           AND (t.source_observed_at IS NULL OR t.source_observed_at <= $7)
           ${dimensionSql}
           AND NOT EXISTS (
             SELECT 1 FROM integration_scan_items si
             WHERE si.scan_id = $6
               AND si.source_kind = t.source_kind
               AND si.source_object_id = t.source_object_id
           )
         FOR UPDATE`,
        params,
      );

      for (const row of res.rows) {
        try {
          await client.query("DELETE FROM alert_queue WHERE token_id = $1", [row.id]);
          await client.query("DELETE FROM domain_monitors WHERE token_id = $1", [row.id]);
          await client.query("DELETE FROM tokens WHERE id = $1", [row.id]);
          deleted.push({ id: row.id, name: row.name, location: row.location });
          await writeAudit({
            client,
            actorUserId: actorUserId || null,
            subjectUserId: actorUserId || null,
            action: "TOKEN_DELETED",
            targetType: "token",
            targetId: row.id,
            channel: null,
            workspaceId,
            metadata: {
              name: row.name,
              location: row.location,
              reason,
              provider: cleanup.provider,
              scanId: scan.id,
              sourceKind: subScope.sourceKind,
            },
          });
        } catch (delErr) {
          // A per-token failure must not silently roll back deletions that
          // already succeeded in this loop, but it also must not be
          // swallowed: surface it so the caller's audit summary reflects a
          // partial cleanup rather than a clean one.
          logger.error("Obsolete token cleanup failed for token; aborting transaction", {
            tokenId: row.id,
            error: delErr.message,
          });
          throw delErr;
        }
      }
    }

    await client.query("COMMIT");
    return { deleted };
  } catch (err) {
    try {
      await client.query("ROLLBACK");
    } catch (_rollbackErr) {
      logger.warn("Cleanup rollback failed", { error: _rollbackErr.message });
    }
    throw err;
  } finally {
    client.release();
  }
}

module.exports = {
  KNOWN_PROVIDERS,
  validateCleanupRequest,
  cleanupObsoleteTokens,
  buildDimensionFilterSql,
};
