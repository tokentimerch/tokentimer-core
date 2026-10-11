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
    assert.equal(normalizeJobSearchQuery("  %  "), "%");
    assert.equal(normalizeJobSearchQuery(""), null);
    assert.equal(escapeIlikePattern(normalizeJobSearchQuery("  100%_off  ")), "100\\%\\_off");
  });
});
