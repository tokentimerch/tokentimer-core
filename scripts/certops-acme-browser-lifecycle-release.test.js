"use strict";
// Offline strict schema/source regression only; no browser or native execution.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fixture = require("./test-support/acme-browser-lifecycle-proof.cjs"),
  helper = require("../tests/e2e/helpers/certops-acme-browser-lifecycle"),
  runner = require("./certops-acme-browser-lifecycle");
const slot = () =>
  require("../docs/certops/release-qualification-matrix.json").slots.find(
    (s) => s.suite === "linux-native-acme-browser-lifecycle",
  );
const errors = (a) =>
  require("./certops-release-qualification").verifyMatrix([a], {
    candidateSha: "a".repeat(40),
    specification: { schemaVersion: 1, slots: [slot()] },
  });
test("native UI issue/renew requires whole proof and every current causal source", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of helper.FLAGS) {
    const a = fixture.artifact();
    delete a.report.nativeAcmeBrowserLifecycle[flag];
    assert.ok(errors(a).length);
  }
  for (const file of runner.REQUIRED_SOURCES) {
    const a = fixture.artifact();
    a.report.fixtureSources.find((r) => r.file === file).sha256 = "e".repeat(
      64,
    );
    assert.ok(errors(a).length);
  }
});
test("native UI lifecycle rejects reused keys, skipped jobs, failed cleanup and wrong platform", () => {
  for (const mutate of [
    (a) => {
      a.report.nativeAcmeBrowserLifecycle.spkiHashes.fill("a".repeat(64));
    },
    (a) => {
      a.report.scenarios[0].status = "skipped";
    },
    (a) => {
      a.report.cleanup.status = "failed";
    },
    (a) => {
      a.report.platform = "win32";
    },
    (a) => {
      a.report.nativeAcmeBrowserLifecycle.rawKey = "secret";
    },
  ]) {
    const a = fixture.artifact();
    mutate(a);
    assert.ok(errors(a).length);
  }
});
