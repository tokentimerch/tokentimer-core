"use strict";

const assert = require("node:assert/strict");
const { describe, it } = require("node:test");

const {
  _test: { escapeIlikePattern, normalizeJobSearchQuery },
} = require("../../apps/api/services/certops/jobs");

describe("Jobs free-text search ILIKE escaping", () => {
  it("escapes %, _, and backslash for literal substring matching", () => {
    assert.equal(escapeIlikePattern("%"), "\\%");
    assert.equal(escapeIlikePattern("_"), "\\_");
    assert.equal(escapeIlikePattern("a\\b%c_d"), "a\\\\b\\%c\\_d");
    assert.equal(escapeIlikePattern("token"), "token");
  });

  it("normalizes the query before escaping would be applied", () => {
    assert.deepEqual(normalizeJobSearchQuery("  %  "), {
      q: "%",
      fingerprintNeedle: null,
    });
    assert.equal(normalizeJobSearchQuery(""), null);
    assert.equal(
      escapeIlikePattern(normalizeJobSearchQuery("  100%_off  ").q),
      "100\\%\\_off",
    );
  });

  it("derives a hex fingerprint needle like certificate inventory search", () => {
    const fp = "ab".repeat(32);
    const colon = fp.match(/.{1,2}/g).join(":");
    const q = colon.slice(0, 20);
    const stripped = q.replace(/[^a-fA-F0-9]/g, "").toLowerCase();
    assert.deepEqual(normalizeJobSearchQuery(q), {
      q,
      fingerprintNeedle: stripped.length >= 4 ? stripped : null,
    });
    assert.deepEqual(normalizeJobSearchQuery("abc"), {
      q: "abc",
      fingerprintNeedle: null,
    });
  });
});
