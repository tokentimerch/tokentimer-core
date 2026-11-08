"use strict";
const { it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const yaml = createRequire(require.resolve("mocha/package.json"))("js-yaml");
const { validateManifest } = require("../../scripts/check-integrations-manifest");
const manifest = yaml.load(fs.readFileSync("integrations.watch.yaml", "utf8"));
it("rejects malformed integration metadata", () => {
  for (const [field, value] of [["api_version", 42], ["api_version", "wrong-version"], ["base_urls", "bad"], ["base_urls", ["http://bad.example"]], ["endpoints", [{ method: "BOGUS", pattern: "/x" }]], ["webhook_formats", { sent: [""] }]]) {
    const copy = structuredClone(manifest);
    copy.integrations.github[field] = value;
    assert.throws(() => validateManifest(copy), /github:/);
  }
});
