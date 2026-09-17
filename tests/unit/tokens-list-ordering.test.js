"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const TOKENS_ROUTE = path.join(
  __dirname,
  "../../apps/api/routes/tokens.js",
);

describe("GET /api/tokens list sort", () => {
  const src = fs.readFileSync(TOKENS_ROUTE, "utf8");

  it("ties every list ORDER BY on tokens.id so offset pages stay distinct", () => {
    assert.match(src, /tokens\.expiration ASC NULLS LAST, tokens\.id ASC/);
    assert.match(src, /tokens\.expiration DESC NULLS LAST, tokens\.id DESC/);
    assert.match(src, /LOWER\(tokens\.name\) ASC, tokens\.id ASC/);
    assert.match(src, /tokens\.last_used DESC NULLS LAST, tokens\.id DESC/);
    assert.match(src, /tokens\.last_used ASC NULLS LAST, tokens\.id ASC/);
    assert.match(src, /tokens\.imported_at DESC NULLS LAST, tokens\.id DESC/);
    assert.match(src, /tokens\.imported_at ASC NULLS LAST, tokens\.id ASC/);
    assert.match(src, /tokens\.created_at DESC NULLS LAST, tokens\.id DESC/);
    assert.doesNotMatch(src, /tokens\.created_at DESC NULLS LAST";/);
  });
});
