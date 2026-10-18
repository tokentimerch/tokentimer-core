"use strict";
const test = require("node:test"), assert = require("node:assert/strict");
const manifest = require("./certops-qualification-manifest"), {expand} = manifest;
const compact = () => ({sourceGroups: {shared: ["scripts/fixture.js"]}, slots: [{requiredSourceGroup: "shared"}, {requiredSourceGroup: "shared"}]});
test("shared source groups expand independently without changing flat contracts", () => {
  const input = compact(), result = expand(input);
  assert.deepEqual(result, {slots: [{requiredSources: ["scripts/fixture.js"]}, {requiredSources: ["scripts/fixture.js"]}]});
  result.slots[0].requiredSources.push("another.js");
  assert.equal(result.slots[1].requiredSources.length, 1);
  assert.deepEqual(input, compact());
  const flat = {slots: [{requiredSources: ["a.js"]}]};
  assert.deepEqual(expand(flat), flat);
});
test("ambiguous missing and malformed groups cannot hide source obligations", () => {
  for (const patch of [
    {sourceGroups: null}, {sourceGroups: []},
    {sourceGroups: {shared: []}}, {sourceGroups: {shared: ["a.js", "a.js"]}},
    {sourceGroups: {shared: [false]}}, {sourceGroups: {shared: Array.from({length: 257}, (_, i) => `${i}.js`)}},
    {sourceGroups: {"../shared": ["a.js"]}},
    {slots: [{requiredSourceGroup: "missing"}]},
    {slots: [{requiredSourceGroup: "shared", requiredSources: []}]},
    {slots: [{requiredSourceGroup: ["shared"]}]},
  ]) assert.throws(() => expand({...compact(), ...patch}));
});
test("every expanded committed slot retains a bounded unique source list", () => {
  const raw = require("../docs/certops/qualification-suites.json");
  assert.equal(manifest.slots.length, raw.slots.length);
  assert.deepEqual(manifest.scenarios, raw.scenarios);
  for (const slot of manifest.slots) {
    assert.ok(!Object.hasOwn(slot, "requiredSourceGroup"));
    if (!slot.requiredSources) continue;
    assert.ok(slot.requiredSources.length <= 256);
    assert.equal(new Set(slot.requiredSources).size, slot.requiredSources.length);
  }
});

test("environment references reject ambiguity and expand into independent nested objects", () => {
  const input = {environmentGroups: {ubuntu: {osFamily: "linux", nested: {version: "24.04"}}}, slots: [{environmentGroup: "ubuntu"}, {environmentGroup: "ubuntu"}]};
  const result = expand(input);
  result.slots[0].environment.nested.version = "changed";
  assert.equal(result.slots[1].environment.nested.version, "24.04");
  assert.equal(input.environmentGroups.ubuntu.nested.version, "24.04");
  assert.deepEqual(expand({slots: [{environment: {osFamily: "linux"}}]}), {slots: [{environment: {osFamily: "linux"}}]});
  for (const patch of [
    {environmentGroups: null}, {environmentGroups: []},
    {environmentGroups: {ubuntu: null}}, {environmentGroups: {ubuntu: []}},
    {environmentGroups: {ubuntu: {}}}, {environmentGroups: {"../ubuntu": {osFamily: "linux"}}},
    {slots: [{environmentGroup: "missing"}]},
    {slots: [{environmentGroup: "ubuntu", environment: {}}]},
    {slots: [{environmentGroup: ["ubuntu"]}]},
  ]) assert.throws(() => expand({...input, ...patch}));
});

test("canonical suite declarations preserve ordered cases and mixed evidence levels", () => {
  const definition = {evidenceLevel: "real-host", capabilities: ["windows"], scenarioEvidenceLevel: "real-host", scenarios: ["first", "second"], scenarioEvidenceOverrides: {second: "unit"}};
  const input = {suiteDefinitions: {sample: definition}};
  const result = expand(input);
  assert.deepEqual(result, {suites: {sample: ["first", "second"]}, requiredCapabilities: {sample: ["windows"]}, suiteEvidenceLevels: {sample: "real-host"}, scenarioEvidenceLevels: {sample: {first: "real-host", second: "unit"}}});
  result.suites.sample.push("third");
  assert.deepEqual(definition.scenarios, ["first", "second"]);
  for (const patch of [
    {scenarios: []}, {scenarios: ["first", "first"]}, {scenarios: [false]},
    {capabilities: []}, {capabilities: ["windows", "windows"]},
    {evidenceLevel: "unit"}, {scenarioEvidenceLevel: "invented"},
    {scenarioEvidenceOverrides: {unknown: "unit"}}, {scenarioEvidenceOverrides: {first: "invented"}},
    {scenarioEvidenceOverrides: null},
  ]) assert.throws(() => expand({suiteDefinitions: {sample: {...definition, ...patch}}}));
  for (const patch of [{suites: {}}, {requiredCapabilities: {}}, {suiteEvidenceLevels: {}}, {scenarioEvidenceLevels: {sample: {}}}, {scenarioEvidenceLevels: []}]) assert.throws(() => expand({...input, ...patch}));
  for (const suiteDefinitions of [null, [], {}, {sample: null}]) assert.throws(() => expand({suiteDefinitions}));
});

test("shared source segments preserve order and reject cycles duplicates and excess expansion", () => {
  const input = {sourceGroups: {base: ["a.js", "b.js"], composed: [{sourceGroup: "base"}, "c.js"]}, slots: [{requiredSourceGroup: "composed"}, {requiredSources: [{sourceGroup: "base"}, "d.js"]}]};
  assert.deepEqual(expand(input).slots, [{requiredSources: ["a.js", "b.js", "c.js"]}, {requiredSources: ["a.js", "b.js", "d.js"]}]);
  for (const sourceGroups of [
    {base: [{sourceGroup: "base"}]},
    {base: [{sourceGroup: "other"}], other: [{sourceGroup: "base"}]},
    {base: [{sourceGroup: "missing"}]},
    {base: ["a.js"], composed: [{sourceGroup: "base"}, "a.js"]},
    {base: [{sourceGroup: "other", ignored: true}], other: ["a.js"]},
    {base: Array.from({length: 200}, (_, i) => `${i}.js`), composed: [{sourceGroup: "base"}, ...Array.from({length: 57}, (_, i) => `extra${i}.js`)]},
  ]) assert.throws(() => expand({sourceGroups}));
});

test("shared capability sets remain independent and reject conflicting declarations", () => {
  const suite = {evidenceLevel: "real-host", scenarios: ["case"], capabilityGroup: "windows"};
  const input = {capabilityGroups: {windows: ["windows", "system"]}, suiteDefinitions: {first: suite, second: suite}};
  const result = expand(input);
  assert.deepEqual(result.scenarioEvidenceLevels.first, {case: "real-host"});
  result.requiredCapabilities.first.push("changed");
  assert.deepEqual(result.requiredCapabilities.second, ["windows", "system"]);
  for (const patch of [{capabilityGroups: null}, {capabilityGroups: {windows: []}}, {capabilityGroups: {windows: [false]}}, {capabilityGroups: {windows: ["windows", "windows"]}}, {suiteDefinitions: {first: {...suite, capabilities: ["windows"]}}}, {suiteDefinitions: {first: {...suite, capabilityGroup: "missing"}}}]) assert.throws(() => expand({...input, ...patch}));
});
