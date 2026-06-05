"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const {
  emptyBuckets,
  formatSourceEntry,
  sqlExpiryBucketCase,
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
});
