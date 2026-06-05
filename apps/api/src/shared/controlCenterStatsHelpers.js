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

module.exports = {
  BUCKET_KEYS,
  CATEGORY_SOURCE_LABELS,
  sqlExpiryBucketCase,
  emptyBuckets,
  formatSourceEntry,
};
