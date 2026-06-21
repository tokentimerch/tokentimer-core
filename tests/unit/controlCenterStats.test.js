"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const {
  emptyBuckets,
  formatSourceEntry,
  sqlExpiryBucketCase,
  scorePrivileges,
  buildPrivilegeHighlight,
  formatAutoSyncStatusRow,
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
