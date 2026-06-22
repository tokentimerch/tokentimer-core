const CATEGORY_SOURCE_LABELS = {
  cert: "Certificates",
  key_secret: "Keys & secrets",
  license: "Licenses",
  general: "General",
};

const BUCKET_KEYS = [
  "healthy",
  "neverExpires",
  "expiring7",
  "expiring8To30",
  "expired",
];

/**
 * SQL CASE for expiry bucket classification aligned with classifyExpiryBucket.
 *
 * @param {number} tzParamIndex - 1-based $N index for the timezone bind param
 * @returns {string}
 */
function sqlExpiryBucketCase(tzParamIndex) {
  const today = `(NOW() AT TIME ZONE $${tzParamIndex})::date`;
  const daysLeft = `(t.expiration - ${today})`;
  return `
    CASE
      WHEN t.expiration >= DATE '9999-01-01'
        OR t.expiration::text LIKE '2099%'
        OR t.expiration::text LIKE '9999%'
      THEN 'neverExpires'
      WHEN ${daysLeft} < 0 THEN 'expired'
      WHEN ${daysLeft} <= 7 THEN 'expiring7'
      WHEN ${daysLeft} <= 30 THEN 'expiring8To30'
      ELSE 'healthy'
    END
  `;
}

/**
 * @returns {Record<string, number>}
 */
function emptyBuckets() {
  return BUCKET_KEYS.reduce((acc, key) => {
    acc[key] = 0;
    return acc;
  }, /** @type {Record<string, number>} */ ({}));
}

/**
 * @param {string} categoryKey
 * @returns {{ key: string, name: string }}
 */
function formatSourceEntry(categoryKey) {
  const key = String(categoryKey || "general").trim().toLowerCase() || "general";
  return {
    key,
    name: CATEGORY_SOURCE_LABELS[key] || key,
  };
}

const HIGH_PRIVILEGE_PATTERNS = [
  { pattern: /\badmin\b/i, weight: 50 },
  { pattern: /\bowner\b/i, weight: 40 },
  { pattern: /\bdelete\b/i, weight: 25 },
  { pattern: /\bwrite\b/i, weight: 20 },
  { pattern: /\bmanage\b/i, weight: 20 },
  { pattern: /\bfull\b/i, weight: 15 },
  { pattern: /[:*]|(^|\s)all(\s|$)/i, weight: 30 },
];

/**
 * @param {string|null|undefined} text
 * @returns {string[]}
 */
function parsePrivilegeScopes(text) {
  if (!text) return [];
  return String(text)
    .split(/[,;\n|]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/**
 * Score privilege breadth for Control Center ranking (higher = broader access).
 *
 * @param {string|null|undefined} text
 * @returns {{ score: number, scopeCount: number, preview: string }}
 */
function scorePrivileges(text) {
  const scopes = parsePrivilegeScopes(text);
  let score = scopes.length * 2;
  const joined = scopes.join(" ");

  for (const { pattern, weight } of HIGH_PRIVILEGE_PATTERNS) {
    if (pattern.test(joined)) {
      score += weight;
    }
  }

  return {
    score,
    scopeCount: scopes.length,
    preview: scopes.slice(0, 4).join(", "),
  };
}

/**
 * @param {string|null|undefined} privileges
 * @param {{ id: unknown, name: string, type: string|null|undefined, category: string|null|undefined }} token
 * @returns {object|null}
 */
function buildPrivilegeHighlight(token, privileges) {
  const raw = String(privileges || "").trim();
  if (!raw) return null;

  const { score, scopeCount, preview } = scorePrivileges(raw);
  return {
    id: token.id,
    name: token.name,
    type: token.type || null,
    category: token.category || null,
    privileges: raw,
    scopeCount,
    preview: preview || raw.slice(0, 120),
    score,
    level: score >= 40 ? "high" : score >= 15 ? "medium" : "low",
  };
}

/**
 * @param {{
 *   provider: string,
 *   frequency?: string|null,
 *   schedule_time?: string|null,
 *   schedule_tz?: string|null,
 *   enabled?: boolean|null,
 *   last_sync_at?: string|null,
 *   last_sync_status?: string|null,
 *   last_sync_error?: string|null,
 *   last_sync_items_count?: number|null,
 *   next_sync_at?: string|null,
 * }} row
 * @returns {object}
 */
function formatAutoSyncStatusRow(row) {
  const enabled = row.enabled !== false;
  const lastStatus = String(row.last_sync_status || "").toLowerCase();
  const nextSyncAt = row.next_sync_at ? new Date(row.next_sync_at) : null;
  const isOverdue =
    enabled &&
    nextSyncAt &&
    !Number.isNaN(nextSyncAt.getTime()) &&
    nextSyncAt.getTime() < Date.now();

  let health = "scheduled";
  if (!enabled) {
    health = "paused";
  } else if (lastStatus === "failed") {
    health = "failed";
  } else if (lastStatus === "success") {
    health = isOverdue ? "overdue" : "healthy";
  } else if (isOverdue) {
    health = "overdue";
  }

  const frequency = String(row.frequency || "daily");
  const scheduleTime = row.schedule_time ? String(row.schedule_time) : null;
  const scheduleTz = row.schedule_tz ? String(row.schedule_tz) : "UTC";

  return {
    id: row.id,
    provider: row.provider,
    frequency,
    scheduleLabel: scheduleTime
      ? `${frequency} · ${scheduleTime} ${scheduleTz}`
      : frequency,
    enabled,
    health,
    lastSyncAt: row.last_sync_at || null,
    lastSyncStatus: row.last_sync_status || null,
    lastSyncError: row.last_sync_error || null,
    lastSyncItemsCount:
      typeof row.last_sync_items_count === "number"
        ? row.last_sync_items_count
        : null,
    nextSyncAt: row.next_sync_at || null,
  };
}

module.exports = {
  BUCKET_KEYS,
  CATEGORY_SOURCE_LABELS,
  sqlExpiryBucketCase,
  emptyBuckets,
  formatSourceEntry,
  parsePrivilegeScopes,
  scorePrivileges,
  buildPrivilegeHighlight,
  formatAutoSyncStatusRow,
};
