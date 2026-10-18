"use strict";
// Environment variants share causal source lists on disk. Readers receive the
// same independent, expanded slots used by report and fingerprint verification.
const assert = require("node:assert/strict");
function expand(input) {
  const { sourceGroups = {}, ...manifest } = structuredClone(input);
  assert.ok(sourceGroups && typeof sourceGroups === "object" && !Array.isArray(sourceGroups));
  assert.ok(Object.keys(sourceGroups).length <= 512);
  for (const [name, sources] of Object.entries(sourceGroups)) {
    assert.match(name, /^[a-z0-9][a-z0-9-]{0,127}$/);
    assert.ok(Array.isArray(sources) && sources.length > 0 && sources.length <= 256);
    assert.ok(sources.every(file => typeof file === "string" && file.length > 0));
    assert.equal(new Set(sources).size, sources.length);
  }
  for (const slot of manifest.slots || []) {
    if (!Object.hasOwn(slot, "requiredSourceGroup")) continue;
    assert.ok(!Object.hasOwn(slot, "requiredSources"), "Conflicting source declarations");
    assert.ok(typeof slot.requiredSourceGroup === "string" && Object.hasOwn(sourceGroups, slot.requiredSourceGroup), "Unknown source group");
    slot.requiredSources = [...sourceGroups[slot.requiredSourceGroup]];
    delete slot.requiredSourceGroup;
  }
  return manifest;
}
module.exports = expand(require("../docs/certops/qualification-suites.json"));
// Non-enumerable so serializing or comparing the materialized contract retains
// its existing schema. Tests also exercise malformed and legacy flat manifests.
Object.defineProperty(module.exports, "expand", { value: expand });
