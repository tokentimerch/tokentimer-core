"use strict";

// A combined (shard=all) run registers the same shared fixture source from several journeys. The report
// must still hold every source exactly once so the journeys' own one-entry asserts and the release
// verifier accept it, while a different digest for an already registered file stays a hard failure.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { createHostGate } = require("../packages/agent/scripts/host-gate");

const gate = () => createHostGate({ suite: "enterprise-adcs-real", strict: true, candidateSha: "a".repeat(40), reportPath: undefined });

test("fixtureSources is absent until a journey registers its first source", () => {
  assert.equal(Object.keys(gate().report).includes("fixtureSources"), false);
});

test("re-registering an identical source is a no-op and the report keeps one entry", () => {
  const { report } = gate();
  const row = { file: "infra/certops-adcs/owned-ca-checkpoint.ps1", sha256: "b".repeat(64) };
  report.fixtureSources ??= [];
  report.fixtureSources.push({ ...row });
  report.fixtureSources.push({ ...row }, { file: "other.js", sha256: "c".repeat(64) });
  // The strict check several journeys perform on their own sources.
  assert.equal(report.fixtureSources.filter((item) => item.file === row.file).length, 1);
  const serialized = JSON.parse(JSON.stringify(report));
  assert.deepEqual(serialized.fixtureSources.map((item) => item.file), [row.file, "other.js"]);
});

test("a different digest for an already registered source fails closed", () => {
  const { report } = gate();
  report.fixtureSources ??= [];
  report.fixtureSources.push({ file: "a.js", sha256: "b".repeat(64) });
  assert.throws(() => report.fixtureSources.push({ file: "a.js", sha256: "d".repeat(64) }), /Conflicting fixture source digest/);
  assert.equal(report.fixtureSources.length, 1);
});

test("assigning a list with repeated identical sources collapses it", () => {
  const { report } = gate();
  report.fixtureSources = [{ file: "a.js", sha256: "b".repeat(64) }, { file: "a.js", sha256: "b".repeat(64) }];
  assert.equal(report.fixtureSources.length, 1);
  assert.throws(() => { report.fixtureSources = [{ file: "a.js", sha256: "b".repeat(64) }, { file: "a.js", sha256: "e".repeat(64) }]; }, /Conflicting fixture source digest/);
});
