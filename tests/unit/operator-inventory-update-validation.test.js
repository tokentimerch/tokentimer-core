"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { normalizeUpdate } = require("../../apps/api/services/operator/inventoryUpdateValidation");
const current = { name: "Inventory item", type: "api_key", category: "key_secret", expiresAt: null, location: null, usedBy: null, sections: [], domains: [], description: null };

test("partial changes use inventory validation and do not include unchanged fields", () => {
  assert.deepEqual(normalizeUpdate(current, { usedBy: "  platform  ", sections: ["Production", "Production"] }), { sections: ["Production"], usedBy: "platform" });
  assert.deepEqual(normalizeUpdate(current, { expiresAt: null }), { expiresAt: null });
});

test("update validation refuses invalid dates, credentials and non-metadata fields", () => {
  for (const changes of [{}, { type: "ssl_cert" }, { source_provider: "gitlab" }, { expiresAt: "2026-02-30" }, { description: "Bearer abcdefghijklmnopqrstuvwxyz0123456789" }]) {
    assert.throws(() => normalizeUpdate(current, changes));
  }
});
