"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

const {
  NEVER_EXPIRES_DATE,
  isNeverExpires,
  computeDaysLeft,
  classifyExpiryBucket,
} = require(path.resolve(
  __dirname,
  "../../apps/api/src/shared/expiryBuckets.js",
));

describe("expiryBuckets", () => {
  describe("isNeverExpires", () => {
    it("detects sentinel never-expires values", () => {
      assert.equal(isNeverExpires(NEVER_EXPIRES_DATE), true);
      assert.equal(isNeverExpires(`${NEVER_EXPIRES_DATE}T00:00:00Z`), true);
      assert.equal(isNeverExpires("9999-12-31"), true);
      assert.equal(isNeverExpires("2026-06-04"), false);
      assert.equal(isNeverExpires(null), false);
      assert.equal(isNeverExpires(""), false);
    });
  });

  describe("classifyExpiryBucket", () => {
    const BOUNDARY_CASES = [
      [-1, "expired"],
      [0, "expiring7"],
      [7, "expiring7"],
      [8, "expiring8To30"],
      [30, "expiring8To30"],
      [31, "healthy"],
    ];

    for (const [days, expected] of BOUNDARY_CASES) {
      it(`classifies ${days} days as ${expected}`, () => {
        assert.equal(classifyExpiryBucket(days), expected);
      });
    }

    it("classifies null and undefined as neverExpires", () => {
      assert.equal(classifyExpiryBucket(null), "neverExpires");
      assert.equal(classifyExpiryBucket(undefined), "neverExpires");
    });
  });

  describe("computeDaysLeft", () => {
    it("returns null for never-expires and invalid expirations", () => {
      assert.equal(computeDaysLeft(null), null);
      assert.equal(computeDaysLeft(NEVER_EXPIRES_DATE), null);
      assert.equal(
        computeDaysLeft(`${NEVER_EXPIRES_DATE}T00:00:00Z`),
        null,
      );
      assert.equal(computeDaysLeft("9999-12-31"), null);
      assert.equal(computeDaysLeft("not-a-date"), null);
    });

    it("uses UTC calendar dates when timezone is UTC", () => {
      const today = new Date();
      const future = new Date(
        Date.UTC(
          today.getUTCFullYear(),
          today.getUTCMonth(),
          today.getUTCDate() + 10,
        ),
      );
      const iso = future.toISOString().slice(0, 10);
      assert.equal(computeDaysLeft(iso, { timezone: "UTC" }), 10);
    });
  });
});
