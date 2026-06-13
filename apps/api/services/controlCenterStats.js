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

/**
 * Aggregate Control Center stats for a workspace (server-side SQL only).
 *
 * @param {string} workspaceId
 * @returns {Promise<{
 *   totalAssets: number,
 *   buckets: Record<string, number>,
 *   sources: Array<{ key: string, name: string, count: number }>,
 *   needsAttention: Array<object>,
 *   generatedAt: string,
 *   isComplete: boolean,
 * }>}
 */
async function fetchControlCenterStats(workspaceId) {
  const timezone = await loadWorkspaceTimeZone(workspaceId);
  const bucketCase = sqlExpiryBucketCase(2);

  const [totalRes, bucketRes, sourcesRes, attentionRes] = await Promise.all([
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

  return {
    totalAssets: Number(totalRes.rows[0]?.total) || 0,
    buckets,
    sources,
    needsAttention,
    generatedAt: new Date().toISOString(),
    isComplete: true,
  };
}

module.exports = {
  fetchControlCenterStats,
};
