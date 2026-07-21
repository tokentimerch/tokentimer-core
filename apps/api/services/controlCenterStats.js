const { pool } = require("../db/database");
const {
  resolveTimeZone,
  classifyExpiryBucket,
  computeDaysLeft,
} = require("../src/shared/expiryBuckets");
const {
  sqlExpiryBucketCase,
  emptyBuckets,
  formatSourceEntry,
  buildPrivilegeHighlight,
  formatAutoSyncStatusRow,
} = require("../src/shared/controlCenterStatsHelpers");

/**
 * @param {string} workspaceId
 * @returns {Promise<string>}
 */
async function loadWorkspaceTimeZone(workspaceId) {
  const { rows } = await pool.query(
    `SELECT delivery_window_tz
       FROM workspace_settings
      WHERE workspace_id = $1`,
    [workspaceId],
  );
  return resolveTimeZone(rows[0]?.delivery_window_tz);
}

// Default/initial page size shared between the aggregate stats payload and
// the dedicated pagination endpoints, so the first "page" rendered from
// /control-center/stats lines up exactly with what infinite-scroll appends.
const LIST_PAGE_SIZE_DEFAULT = 20;
const LIST_PAGE_SIZE_MAX = 100;
// Scoring/sorting the privileges list happens in JS (see scorePrivileges),
// so pagination over it requires a bounded candidate pool fetched from SQL
// rather than a plain OFFSET/LIMIT. This cap keeps that query cheap while
// comfortably covering realistic workspace sizes.
const PRIVILEGE_CANDIDATE_POOL_CAP = 2000;

function clampLimit(limit) {
  return Math.max(1, Math.min(LIST_PAGE_SIZE_MAX, Number(limit) || LIST_PAGE_SIZE_DEFAULT));
}

function clampOffset(offset) {
  return Math.max(0, Number(offset) || 0);
}

/**
 * Paginated "never expires" (perpetual asset) list, ordered by name.
 *
 * @param {string} workspaceId
 * @param {{ limit?: number, offset?: number }} [options]
 * @returns {Promise<{ items: Array<object>, total: number, hasMore: boolean }>}
 */
async function fetchNeverExpiresPage(workspaceId, options = {}) {
  const limit = clampLimit(options.limit);
  const offset = clampOffset(options.offset);

  const [rowsRes, totalRes] = await Promise.all([
    pool.query(
      `SELECT t.id,
              t.name,
              t.type,
              t.category,
              t.section
         FROM tokens t
        WHERE t.workspace_id = $1
          AND (
            t.expiration >= DATE '9999-01-01'
            OR t.expiration::text LIKE '2099%'
            OR t.expiration::text LIKE '9999%'
          )
        ORDER BY LOWER(t.name) ASC
        LIMIT $2 OFFSET $3`,
      [workspaceId, limit, offset],
    ),
    pool.query(
      `SELECT COUNT(*)::int AS total
         FROM tokens t
        WHERE t.workspace_id = $1
          AND (
            t.expiration >= DATE '9999-01-01'
            OR t.expiration::text LIKE '2099%'
            OR t.expiration::text LIKE '9999%'
          )`,
      [workspaceId],
    ),
  ]);

  const items = rowsRes.rows.map((row) => {
    const { key, name } = formatSourceEntry(row.category);
    const section = Array.isArray(row.section)
      ? row.section.filter(Boolean).join(", ")
      : row.section || null;
    return {
      id: row.id,
      name: row.name,
      type: row.type,
      category: key,
      categoryLabel: name,
      section,
    };
  });

  const total = Number(totalRes.rows[0]?.total) || 0;
  return {
    items,
    total,
    hasMore: offset + items.length < total,
  };
}

/**
 * Paginated scopes/privileges highlight list, ordered by privilege score
 * (highest risk first). Scoring runs in JS over a bounded candidate pool,
 * so `hasMore` also respects that pool cap in addition to the true total.
 *
 * @param {string} workspaceId
 * @param {{ limit?: number, offset?: number }} [options]
 * @returns {Promise<{ items: Array<object>, total: number, hasMore: boolean }>}
 */
async function fetchPrivilegeHighlightsPage(workspaceId, options = {}) {
  const limit = clampLimit(options.limit);
  const offset = clampOffset(options.offset);

  const [candidatesRes, totalRes] = await Promise.all([
    pool.query(
      `SELECT t.id,
              t.name,
              t.type,
              t.category,
              t.privileges
         FROM tokens t
        WHERE t.workspace_id = $1
          AND t.privileges IS NOT NULL
          AND LENGTH(TRIM(t.privileges)) > 0
        ORDER BY LENGTH(t.privileges) DESC, LOWER(t.name) ASC
        LIMIT $2`,
      [workspaceId, PRIVILEGE_CANDIDATE_POOL_CAP],
    ),
    pool.query(
      `SELECT COUNT(*)::int AS total
         FROM tokens t
        WHERE t.workspace_id = $1
          AND t.privileges IS NOT NULL
          AND LENGTH(TRIM(t.privileges)) > 0`,
      [workspaceId],
    ),
  ]);

  const scored = candidatesRes.rows
    .map((row) => buildPrivilegeHighlight(row, row.privileges))
    .filter(Boolean)
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  const items = scored.slice(offset, offset + limit);
  const total = Number(totalRes.rows[0]?.total) || 0;

  return {
    items,
    total,
    hasMore: offset + items.length < scored.length,
  };
}

/**
 * Aggregate Control Center stats for a workspace (server-side SQL only).
 * The `neverExpires` and `privilegeHighlights` arrays only contain the
 * first page (see LIST_PAGE_SIZE_DEFAULT); use fetchNeverExpiresPage /
 * fetchPrivilegeHighlightsPage with an offset to load more.
 *
 * @param {string} workspaceId
 * @returns {Promise<{
 *   totalAssets: number,
 *   buckets: Record<string, number>,
 *   sources: Array<{ key: string, name: string, count: number }>,
 *   needsAttention: Array<object>,
 *   neverExpires: Array<object>,
 *   neverExpiresHasMore: boolean,
 *   privilegeHighlights: Array<object>,
 *   privilegeHighlightsTotal: number,
 *   privilegeHighlightsHasMore: boolean,
 *   autoSync: Array<object>,
 *   generatedAt: string,
 *   isComplete: boolean,
 * }>}
 */
async function fetchControlCenterStats(workspaceId) {
  const timezone = await loadWorkspaceTimeZone(workspaceId);
  const bucketCase = sqlExpiryBucketCase(2);

  const [
    totalRes,
    bucketRes,
    sourcesRes,
    attentionRes,
    neverExpiresPage,
    privilegePage,
    autoSyncRes,
  ] = await Promise.all([
    pool.query(
      `SELECT COUNT(*)::int AS total
         FROM tokens
        WHERE workspace_id = $1`,
      [workspaceId],
    ),
    pool.query(
      `SELECT bucket, COUNT(*)::int AS count
         FROM (
           SELECT ${bucketCase} AS bucket
             FROM tokens t
            WHERE t.workspace_id = $1
         ) grouped
        GROUP BY bucket`,
      [workspaceId, timezone],
    ),
    pool.query(
      `SELECT COALESCE(NULLIF(TRIM(t.category), ''), 'general') AS source_key,
              COUNT(*)::int AS count
         FROM tokens t
        WHERE t.workspace_id = $1
        GROUP BY source_key
        ORDER BY count DESC, source_key ASC`,
      [workspaceId],
    ),
    pool.query(
      `SELECT t.id,
              t.name,
              t.type,
              t.category,
              t.expiration::text AS expiration
         FROM tokens t
        WHERE t.workspace_id = $1
          AND NOT (
            t.expiration >= DATE '9999-01-01'
            OR t.expiration::text LIKE '2099%'
            OR t.expiration::text LIKE '9999%'
          )
          AND (t.expiration - (NOW() AT TIME ZONE $2)::date) <= 30
        ORDER BY (t.expiration - (NOW() AT TIME ZONE $2)::date) ASC,
                 LOWER(t.name) ASC
        LIMIT 10`,
      [workspaceId, timezone],
    ),
    fetchNeverExpiresPage(workspaceId, { limit: LIST_PAGE_SIZE_DEFAULT, offset: 0 }),
    fetchPrivilegeHighlightsPage(workspaceId, { limit: LIST_PAGE_SIZE_DEFAULT, offset: 0 }),
    pool.query(
      `SELECT id,
              provider,
              frequency,
              schedule_time,
              schedule_tz,
              enabled,
              last_sync_at,
              last_sync_status,
              last_sync_error,
              last_sync_items_count,
              next_sync_at
         FROM auto_sync_configs
        WHERE workspace_id = $1
        ORDER BY provider ASC`,
      [workspaceId],
    ),
  ]);

  const buckets = emptyBuckets();
  for (const row of bucketRes.rows) {
    const key = String(row.bucket || "");
    if (Object.prototype.hasOwnProperty.call(buckets, key)) {
      buckets[key] = Number(row.count) || 0;
    }
  }
  buckets.critical = buckets.expired + buckets.expiring7;

  const sources = sourcesRes.rows.map((row) => {
    const { key, name } = formatSourceEntry(row.source_key);
    return {
      key,
      name,
      count: Number(row.count) || 0,
    };
  });

  const needsAttention = attentionRes.rows.map((row) => {
    const expiresAt = row.expiration || null;
    const daysLeft = computeDaysLeft(expiresAt, { timezone });
    return {
      id: row.id,
      name: row.name,
      type: row.type,
      category: row.category,
      expiresAt,
      daysLeft,
      bucket: classifyExpiryBucket(daysLeft),
    };
  });

  const autoSync = autoSyncRes.rows.map(formatAutoSyncStatusRow);

  return {
    totalAssets: Number(totalRes.rows[0]?.total) || 0,
    buckets,
    sources,
    needsAttention,
    neverExpires: neverExpiresPage.items,
    neverExpiresHasMore: neverExpiresPage.hasMore,
    privilegeHighlights: privilegePage.items,
    privilegeHighlightsTotal: privilegePage.total,
    privilegeHighlightsHasMore: privilegePage.hasMore,
    autoSync,
    generatedAt: new Date().toISOString(),
    isComplete: true,
  };
}

module.exports = {
  fetchControlCenterStats,
  fetchNeverExpiresPage,
  fetchPrivilegeHighlightsPage,
  LIST_PAGE_SIZE_DEFAULT,
  LIST_PAGE_SIZE_MAX,
};
