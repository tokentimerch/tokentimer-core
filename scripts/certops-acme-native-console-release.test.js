"use strict";
/** Offline release evidence/source adversaries, never native qualification. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification"),
  fixture = require("./test-support/acme-native-console-proof.cjs");
const errors = (value) =>
  verifyMatrix([value], {
    candidateSha: "a".repeat(40),
    specification: { schemaVersion: 1, slots: [fixture.slot()] },
  });
test("native browser console cell requires every actual observation and causal source", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of require("../tests/e2e/helpers/certops-acme-browser-console")
    .FLAGS) {
    const value = fixture.artifact();
    value.report.nativeAcmeBrowserConsole[flag] = false;
    assert.ok(errors(value).length);
  }
  for (const file of fixture.slot().requiredSources) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === file).sha256 =
      "f".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("console native proof cannot qualify a protocol/container/client/failed-cleanup substitute", () => {
  for (const mutate of [
    (v) => delete v.report.nativeAcmeBrowserConsole,
    (v) => {
      v.report.platform = "win32";
    },
    (v) => {
      v.report.qualificationEnvironment.executionSurface = "container";
    },
    (v) => {
      v.report.nativeAcmeBrowserConsole.client = "acme.sh";
    },
    (v) => {
      v.report.scenarios[0].status = "skipped";
    },
    (v) => {
      v.report.cleanup.status = "failed";
    },
    (v) => {
      v.report.nativeAcmeBrowserConsole.rawLine = "private";
    },
    (v) => {
      v.report.candidateSha = "b".repeat(40);
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});
