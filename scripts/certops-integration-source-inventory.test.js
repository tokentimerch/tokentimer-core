/**
 * Regression coverage: committed certificate sources map to production scanners.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const inventory = require("../docs/certops/integration-source-inventory.json");
const { validateInventory } = require("./certops-integration-source-inventory");
test("committed certificate sources map to production scanners", () => {
  assert.deepEqual(validateInventory(inventory), { sources: 6, liveProvidersQualified: 0 });
});
test("missing and duplicate sources cannot silently narrow the inventory", () => {
  const missing = structuredClone(inventory); missing.sources.pop();
  assert.throws(() => validateInventory(missing), /incomplete/);
  const duplicate = structuredClone(inventory); duplicate.sources[5] = duplicate.sources[0];
  assert.throws(() => validateInventory(duplicate), /duplicated/);
});
test("static metadata cannot claim provider execution or survive scanner drift", () => {
  const claimed = structuredClone(inventory); claimed.sources[0].liveProviderQualified = true;
  assert.throws(() => validateInventory(claimed), /cannot qualify/);
  assert.throws(() => validateInventory(inventory, () => "module.exports = {}"), /mapping drift/);
});
