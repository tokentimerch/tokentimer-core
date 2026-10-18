"use strict";
// Environment variants share causal source lists on disk. Readers receive the
// same independent, expanded slots used by report and fingerprint verification.
const assert = require("node:assert/strict");
function expand(input) {
  const { sourceGroups = {}, environmentGroups = {}, suiteDefinitions, capabilityGroups = {}, testGroups = {}, ...manifest } = structuredClone(input);
  // A suite's OS/language variants share requirements, but remain independent
  // ordered slots at every runtime and report-verification boundary.
  assert.ok(testGroups && typeof testGroups === "object" && !Array.isArray(testGroups));
  assert.ok(Object.keys(testGroups).length <= 512);
  for (const [name, tests] of Object.entries(testGroups)) {
    assert.match(name, /^[a-z0-9][a-z0-9-]{0,127}$/);
    assert.ok(Array.isArray(tests) && tests.length > 0 && tests.length <= 256 && tests.every(id => typeof id === "string" && id.length > 0) && new Set(tests).size === tests.length);
  }
  if (manifest.slots) {
    assert.ok(Array.isArray(manifest.slots) && manifest.slots.length <= 512);
    manifest.slots = manifest.slots.flatMap(slot => {
      if (!Object.hasOwn(slot, "environmentVariants")) return [slot];
      const {environmentVariants, ...common} = slot;
      assert.ok(!Object.hasOwn(slot, "id") && !Object.hasOwn(slot, "environment") && !Object.hasOwn(slot, "environmentGroup"), "Conflicting slot variants");
      assert.ok(environmentVariants && typeof environmentVariants === "object" && !Array.isArray(environmentVariants));
      const entries = Object.entries(environmentVariants);
      assert.ok(entries.length > 0 && entries.length <= 512);
      return entries.map(([id, environmentGroup]) => {
        assert.ok(id.length > 0 && id.length <= 128);
        assert.equal(typeof environmentGroup, "string");
        return {...structuredClone(common), id, environmentGroup};
      });
    });
    assert.ok(manifest.slots.length <= 512);
    const ids = manifest.slots.filter(slot => Object.hasOwn(slot, "id")).map(slot => slot.id);
    assert.equal(new Set(ids).size, ids.length, "Duplicate slot identity");
  }
  assert.ok(capabilityGroups && typeof capabilityGroups === "object" && !Array.isArray(capabilityGroups));
  assert.ok(Object.keys(capabilityGroups).length <= 512);
  for (const [name, values] of Object.entries(capabilityGroups)) {
    assert.match(name, /^[a-z0-9][a-z0-9-]{0,127}$/);
    assert.ok(Array.isArray(values) && values.length > 0 && values.length <= 256 && values.every(value => typeof value === "string" && value.length > 0) && new Set(values).size === values.length);
  }
  if (suiteDefinitions !== undefined) {
    assert.ok(suiteDefinitions && typeof suiteDefinitions === "object" && !Array.isArray(suiteDefinitions));
    assert.ok(Object.keys(suiteDefinitions).length > 0 && Object.keys(suiteDefinitions).length <= 512);
    for (const field of ["suites", "requiredCapabilities", "suiteEvidenceLevels"]) {
      assert.ok(!Object.hasOwn(manifest, field), "Conflicting suite declarations");
      manifest[field] = {};
    }
    manifest.scenarioEvidenceLevels ??= {};
    assert.ok(manifest.scenarioEvidenceLevels && typeof manifest.scenarioEvidenceLevels === "object" && !Array.isArray(manifest.scenarioEvidenceLevels));
    for (const [name, definition] of Object.entries(suiteDefinitions)) {
      assert.match(name, /^[a-z0-9][a-z0-9-]{0,127}$/);
      assert.ok(definition && typeof definition === "object" && !Array.isArray(definition));
      const {scenarios, evidenceLevel, scenarioEvidenceLevel = evidenceLevel, scenarioEvidenceOverrides = {}} = definition;
      let capabilities = definition.capabilities;
      if (Object.hasOwn(definition, "capabilityGroup")) {
        assert.ok(!Object.hasOwn(definition, "capabilities"), "Conflicting capability declarations");
        assert.ok(typeof definition.capabilityGroup === "string" && Object.hasOwn(capabilityGroups, definition.capabilityGroup), "Unknown capability group");
        capabilities = [...capabilityGroups[definition.capabilityGroup]];
      }
      assert.ok(Array.isArray(scenarios) && scenarios.length > 0 && scenarios.every(id => typeof id === "string" && id.length > 0) && new Set(scenarios).size === scenarios.length);
      assert.ok(Array.isArray(capabilities) && capabilities.length > 0 && capabilities.every(id => typeof id === "string" && id.length > 0) && new Set(capabilities).size === capabilities.length);
      assert.ok(["integration", "real-host", "e2e"].includes(evidenceLevel));
      assert.ok(["unit", "integration", "real-host", "e2e"].includes(scenarioEvidenceLevel));
      assert.ok(scenarioEvidenceOverrides && typeof scenarioEvidenceOverrides === "object" && !Array.isArray(scenarioEvidenceOverrides));
      assert.ok(!Object.hasOwn(manifest.scenarioEvidenceLevels, name), "Conflicting scenario classifications");
      for (const [id, level] of Object.entries(scenarioEvidenceOverrides)) {
        assert.ok(scenarios.includes(id) && ["unit", "integration", "real-host", "e2e"].includes(level), "Unknown scenario classification");
      }
      manifest.suites[name] = scenarios;
      manifest.requiredCapabilities[name] = capabilities;
      manifest.suiteEvidenceLevels[name] = evidenceLevel;
      manifest.scenarioEvidenceLevels[name] = Object.fromEntries(scenarios.map(id => [id, scenarioEvidenceOverrides[id] ?? scenarioEvidenceLevel]));
    }
  }
  assert.ok(sourceGroups && typeof sourceGroups === "object" && !Array.isArray(sourceGroups));
  assert.ok(Object.keys(sourceGroups).length <= 512);
  for (const name of Object.keys(sourceGroups)) assert.match(name, /^[a-z0-9][a-z0-9-]{0,127}$/);
  const resolvedSources = new Map();
  function sourcesFor(name, visiting = new Set()) {
    assert.ok(visiting.size < 32, "Source group nesting exceeds bounds");
    assert.ok(Object.hasOwn(sourceGroups, name) && !visiting.has(name), "Unknown or cyclic source group");
    if (!resolvedSources.has(name)) resolvedSources.set(name, expandSources(sourceGroups[name], new Set([...visiting, name])));
    return resolvedSources.get(name);
  }
  function expandSources(sources, visiting = new Set()) {
    assert.ok(Array.isArray(sources) && sources.length > 0 && sources.length <= 256);
    const result = sources.flatMap(source => {
      if (typeof source === "string") { assert.ok(source.length > 0); return [source]; }
      assert.ok(source && typeof source === "object" && !Array.isArray(source));
      assert.deepEqual(Object.keys(source), ["sourceGroup"]);
      assert.equal(typeof source.sourceGroup, "string");
      return sourcesFor(source.sourceGroup, visiting);
    });
    assert.ok(result.length <= 256);
    assert.equal(new Set(result).size, result.length, "Duplicate source obligation");
    return result;
  }
  for (const name of Object.keys(sourceGroups)) sourcesFor(name);
  assert.ok(environmentGroups && typeof environmentGroups === "object" && !Array.isArray(environmentGroups));
  assert.ok(Object.keys(environmentGroups).length <= 512);
  for (const [name, environment] of Object.entries(environmentGroups)) {
    assert.match(name, /^[a-z0-9][a-z0-9-]{0,127}$/);
    assert.ok(environment && typeof environment === "object" && !Array.isArray(environment) && Object.keys(environment).length > 0);
  }
  for (const slot of manifest.slots || []) {
    if (Object.hasOwn(slot, "requiredTestGroup")) {
      assert.ok(!Object.hasOwn(slot, "requiredTests"), "Conflicting test declarations");
      assert.ok(typeof slot.requiredTestGroup === "string" && Object.hasOwn(testGroups, slot.requiredTestGroup), "Unknown test group");
      slot.requiredTests = [...testGroups[slot.requiredTestGroup]];
      delete slot.requiredTestGroup;
    }
    if (Object.hasOwn(slot, "environmentGroup")) {
      assert.ok(!Object.hasOwn(slot, "environment"), "Conflicting environment declarations");
      assert.ok(typeof slot.environmentGroup === "string" && Object.hasOwn(environmentGroups, slot.environmentGroup), "Unknown environment group");
      slot.environment = structuredClone(environmentGroups[slot.environmentGroup]);
      delete slot.environmentGroup;
    }

    if (Object.hasOwn(slot, "requiredSources")) slot.requiredSources = expandSources(slot.requiredSources);
    if (!Object.hasOwn(slot, "requiredSourceGroup")) continue;
    assert.ok(!Object.hasOwn(slot, "requiredSources"), "Conflicting source declarations");
    assert.ok(typeof slot.requiredSourceGroup === "string" && Object.hasOwn(sourceGroups, slot.requiredSourceGroup), "Unknown source group");
    slot.requiredSources = [...sourcesFor(slot.requiredSourceGroup)];
    delete slot.requiredSourceGroup;
  }
  return manifest;
}
module.exports = expand(require("../docs/certops/qualification-suites.json"));
// Non-enumerable so serializing or comparing the materialized contract retains
// its existing schema. Tests also exercise malformed and legacy flat manifests.
Object.defineProperty(module.exports, "expand", { value: expand });
