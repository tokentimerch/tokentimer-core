"use strict";
// Offline release adversaries only. No DNS server/provider process is started.
const test = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification"),
  fixture = require("./test-support/dns-resolver-views-artifact.cjs"),
  helper = require("./certops-dns-resolver-views");
const errors = (value) =>
  verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [fixture.slot()] },
  });
test("native resolver slot binds all observations and every actual source", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of helper.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeResolverViews[flag];
    assert.ok(errors(value).length);
  }
  for (const file of helper.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === file).sha256 =
      "e".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("native views cannot relabel reachability, environment, cleanup or public recursion scope", () => {
  for (const mutate of [
    (v) => delete v.report.nativeResolverViews,
    (v) => {
      v.report.nativeResolverViews.allForwarded = [2, 0];
    },
    (v) => {
      v.report.nativeResolverViews.scope = "public-recursive-cache";
    },
    (v) => {
      v.report.nativeResolverViews.privatePackets = "secret";
    },
    (v) => {
      v.report.platform = "win32";
    },
    (v) => {
      v.report.cleanup.status = "failed";
    },
    (v) => {
      v.report.scenarios.find((s) => s.id === helper.SCENARIO).status =
        "skipped";
    },
    (v) => {
      v.report.qualificationEnvironment.executionSurface = "container";
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});
