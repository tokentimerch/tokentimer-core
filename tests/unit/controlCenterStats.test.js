"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const {
  emptyBuckets,
  formatSourceEntry,
  sqlExpiryBucketCase,
  scorePrivileges,
  buildPrivilegeHighlight,
  formatAutoSyncStatusRow,
  SQL_EXCLUDE_RETIRED_CERTS,
  RETIRED_CERT_LIFECYCLE_STATUSES,
} = require(path.resolve(
  __dirname,
  "../../apps/api/src/shared/controlCenterStatsHelpers.js",
));

describe("controlCenterStats helpers", () => {
  it("emptyBuckets includes all expiry bucket keys", () => {
    const buckets = emptyBuckets();
    assert.deepEqual(
      Object.keys(buckets).sort(),
      [
        "expired",
        "expiring7",
        "expiring8To30",
        "healthy",
        "neverExpires",
      ].sort(),
    );
    assert.equal(buckets.healthy, 0);
  });

  it("formatSourceEntry maps known categories to display names", () => {
    assert.deepEqual(formatSourceEntry("cert"), {
      key: "cert",
      name: "Certificates",
    });
    assert.deepEqual(formatSourceEntry("unknown"), {
      key: "unknown",
      name: "unknown",
    });
  });

  it("sqlExpiryBucketCase references timezone bind param", () => {
    const sql = sqlExpiryBucketCase(2);
    assert.match(sql, /AT TIME ZONE \$2/);
    assert.match(sql, /neverExpires/);
    assert.match(sql, /expiring8To30/);
  });

  it("scorePrivileges ranks broader scopes higher", () => {
    const narrow = scorePrivileges("metrics:read");
    const broad = scorePrivileges("admin, repo:write, delete:packages, owner");

    assert.ok(broad.score > narrow.score);
    assert.equal(broad.scopeCount, 4);
  });

  it("scorePrivileges treats underscore-separated scopes as high privilege", () => {
    const fullAccess = buildPrivilegeHighlight(
      { id: 2, name: "Deploy key", type: "api_key", category: "key_secret" },
      "full_access",
    );
    assert.ok(fullAccess);
    assert.equal(fullAccess.level, "high");

    const adminAccess = buildPrivilegeHighlight(
      { id: 3, name: "Admin key", type: "api_key", category: "key_secret" },
      "admin_access",
    );
    assert.ok(adminAccess);
    assert.equal(adminAccess.level, "high");
  });

  it("buildPrivilegeHighlight returns ranked metadata", () => {
    const highlight = buildPrivilegeHighlight(
      {
        id: 1,
        name: "CI deploy key",
        type: "api_key",
        category: "key_secret",
      },
      "admin, repo:write",
    );

    assert.ok(highlight);
    assert.equal(highlight.level, "high");
    assert.match(highlight.preview, /admin/);
  });

  it("formatAutoSyncStatusRow maps sync health states", () => {
    const healthy = formatAutoSyncStatusRow({
      id: "cfg-1",
      provider: "github",
      frequency: "daily",
      schedule_time: "09:00",
      schedule_tz: "UTC",
      enabled: true,
      last_sync_status: "success",
      last_sync_at: new Date().toISOString(),
      next_sync_at: new Date(Date.now() + 3600000).toISOString(),
    });
    assert.equal(healthy.health, "healthy");

    const failed = formatAutoSyncStatusRow({
      id: "cfg-2",
      provider: "gitlab",
      enabled: true,
      last_sync_status: "failed",
      last_sync_error: "Rate limited",
    });
    assert.equal(failed.health, "failed");
  });
});

describe("controlCenterStats retired-certificate exclusion", () => {
  const servicePath = path.resolve(
    __dirname,
    "../../apps/api/services/controlCenterStats.js",
  );
  const source = fs.readFileSync(servicePath, "utf8");

  it("treats revoked and decommissioned as the retired lifecycle set", () => {
    assert.deepEqual([...RETIRED_CERT_LIFECYCLE_STATUSES].sort(), [
      "decommissioned",
      "revoked",
    ]);
  });

  it("keeps NULL lifecycle rows in scope so non-CertOps assets still count", () => {
    assert.match(SQL_EXCLUDE_RETIRED_CERTS, /cert_lifecycle_status IS NULL/);
    assert.match(
      SQL_EXCLUDE_RETIRED_CERTS,
      /NOT IN \('revoked', 'decommissioned'\)/,
    );
    // The fragment is appended to an existing WHERE, so it must start with AND
    // rather than introduce its own clause.
    assert.match(SQL_EXCLUDE_RETIRED_CERTS.trim(), /^AND\b/);
  });

  it("lists the exclusion in the SQL fragment for each lifecycle value", () => {
    for (const status of RETIRED_CERT_LIFECYCLE_STATUSES) {
      assert.ok(
        SQL_EXCLUDE_RETIRED_CERTS.includes(`'${status}'`),
        `expected the exclusion fragment to name ${status}`,
      );
    }
  });

  // A retired certificate must not inflate asset health anywhere. Counting the
  // interpolations is what catches a newly added query that forgets the filter,
  // which is exactly how the original bug shipped.
  it("applies the exclusion to every workspace-scoped token query", () => {
    const interpolations = source.match(/\$\{SQL_EXCLUDE_RETIRED_CERTS\}/g);
    assert.ok(interpolations, "expected the exclusion to be interpolated");
    // total, buckets, sources, needsAttention, neverExpires rows + count,
    // privilege candidates + count.
    assert.equal(interpolations.length, 8);
  });

  it("never counts tokens without applying the filter", () => {
    // Any COUNT/SELECT over `tokens` scoped only by workspace_id is a bug.
    const unfiltered = source.match(
      /FROM tokens[\s\S]{0,200}?WHERE t\.workspace_id = \$1\s*(?:`|ORDER|GROUP|LIMIT)/g,
    );
    assert.equal(
      unfiltered,
      null,
      "found a tokens query scoped only by workspace_id",
    );
  });
});
