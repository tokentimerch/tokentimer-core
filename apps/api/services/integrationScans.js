"use strict";

/**
 * Scan persistence: the backend-authoritative record of what an integration
 * scan actually covered, used as the single source of truth for cleanup
 * scope instead of frontend-reconstructed `scannedSources`/`scannedLocations`.
 *
 * Lifecycle:
 *   1. createScan() at the start of a provider scan -> { id, startedAt }.
 *   2. recordScanItems() as items are discovered (metadata only, never
 *      secret material) -- gives import something to bind client-submitted
 *      items against instead of trusting arbitrary client-supplied
 *      provenance.
 *   3. finalizeScan() once the scan is done, with the authoritative
 *      cleanup_scope (per source-kind/dimension completeness).
 *   4. claimScanForCleanup() at cleanup time: a single-use, transactional
 *      claim so a scan can never drive more than one destructive cleanup.
 */

const { pool } = require("../db/database");

async function createScan({
  workspaceId,
  provider,
  instance,
  ownerKey,
  createdBy = null,
  client = null,
}) {
  const db = client || pool;
  const res = await db.query(
    `INSERT INTO integration_scans (workspace_id, provider, source_instance, source_owner_key, created_by)
     VALUES ($1, $2, $3, $4, $5)
     RETURNING id, started_at`,
    [workspaceId, provider, instance, ownerKey, createdBy],
  );
  return { id: res.rows[0].id, startedAt: res.rows[0].started_at };
}

/**
 * Bulk-persist discovered items (metadata only) so import can later bind
 * client-submitted items to a real row here by (scanId, sourceKind,
 * sourceObjectId), rather than trusting whatever provenance the client
 * claims for an arbitrary item object.
 */
async function recordScanItems(scanId, items, { client = null } = {}) {
  if (!Array.isArray(items) || items.length === 0) return;
  const db = client || pool;
  const CHUNK = 500;
  for (let i = 0; i < items.length; i += CHUNK) {
    const chunk = items.slice(i, i + CHUNK);
    const values = [];
    const params = [];
    let p = 1;
    for (const item of chunk) {
      values.push(`($${p++}, $${p++}, $${p++}, $${p++})`);
      params.push(
        scanId,
        String(item.sourceKind),
        String(item.sourceObjectId),
        item.dimensions || {},
      );
    }
    await db.query(
      `INSERT INTO integration_scan_items (scan_id, source_kind, source_object_id, source_dimensions)
       VALUES ${values.join(", ")}
       ON CONFLICT (scan_id, source_kind, source_object_id) DO NOTHING`,
      params,
    );
  }
}

/**
 * @param {Array<{sourceKind, dimensions, complete, reason}>} subScopes - Per
 *   source-kind/dimension completeness, e.g. one entry per Vault mount, per
 *   AWS region+service, per Azure Key Vault source kind, etc. A subScope
 *   with complete:true and zero discovered items is a legitimate
 *   "obsolete-everything-in-this-scope" result, not a signal to skip it.
 */
async function finalizeScan(scanId, subScopes, { client = null } = {}) {
  const db = client || pool;
  await db.query(
    `UPDATE integration_scans
     SET completed_at = NOW(), cleanup_scope = $2
     WHERE id = $1`,
    [scanId, JSON.stringify({ subScopes: subScopes || [] })],
  );
}

/**
 * Looks up recorded scan items matching the given (sourceKind, objectId)
 * pairs, so import can trust only the dimensions the scan actually
 * observed rather than whatever the client echoes back.
 */
async function lookupScanItems(scanId, pairs, { client = null } = {}) {
  const db = client || pool;
  if (!scanId || !Array.isArray(pairs) || pairs.length === 0) return new Map();
  const kinds = pairs.map((p) => String(p.sourceKind));
  const objectIds = pairs.map((p) => String(p.sourceObjectId));
  const res = await db.query(
    `SELECT source_kind, source_object_id, source_dimensions
     FROM integration_scan_items
     WHERE scan_id = $1
       AND (source_kind, source_object_id) IN (
         SELECT * FROM UNNEST($2::text[], $3::text[])
       )`,
    [scanId, kinds, objectIds],
  );
  const map = new Map();
  for (const row of res.rows) {
    map.set(`${row.source_kind}::${row.source_object_id}`, row.source_dimensions);
  }
  return map;
}

/**
 * Atomically claims a scan for a destructive cleanup run. Returns null if
 * the scan does not exist, does not belong to this workspace/provider
 * scope, or has already been consumed by a previous cleanup -- the single
 * UPDATE ... WHERE cleanup_consumed_at IS NULL RETURNING makes replay of
 * the same scan_id for a second cleanup impossible even under concurrency.
 */
async function claimScanForCleanup({ scanId, workspaceId, provider, client }) {
  const db = client || pool;
  const res = await db.query(
    `UPDATE integration_scans
     SET cleanup_consumed_at = NOW()
     WHERE id = $1
       AND workspace_id = $2
       AND provider = $3
       AND completed_at IS NOT NULL
       AND cleanup_consumed_at IS NULL
     RETURNING id, source_instance, source_owner_key, started_at, cleanup_scope`,
    [scanId, workspaceId, provider],
  );
  return res.rows[0] || null;
}

module.exports = {
  createScan,
  recordScanItems,
  finalizeScan,
  lookupScanItems,
  claimScanForCleanup,
};
