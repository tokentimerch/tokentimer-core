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
