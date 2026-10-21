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

test("interrupted real hook proof, scenario, sources and limited claims are mandatory", () => {
  const interruption = require("./certops-dns-hook-interruption");
  for (const key of Object.keys(fixture.artifact().report.nativeDnsHookInterruption)) {
    for (const wrong of [undefined, typeof fixture.artifact().report.nativeDnsHookInterruption[key] === "boolean" ? 1 : true, null]) {
      const value = fixture.artifact();
      value.report.nativeDnsHookInterruption[key] = wrong;
      assert.ok(errors(value).length, key);
    }
  }
  for (const key of ["liveProviderQualified", "acmeCancellationQualified", "sameNameSiblingQualified", "fullPropagationQualified"]) {
    const value = fixture.artifact(); value.report.nativeDnsHookInterruption[key] = true;
    assert.ok(errors(value).length);
  }
  for (const file of interruption.REQUIRED_SOURCES) {
    const value = fixture.artifact(); value.report.fixtureSources.find(row => row.file === file).sha256 = "e".repeat(64);
    assert.ok(errors(value).length);
  }
  for (const mutate of [v => delete v.report.nativeDnsHookInterruption, v => v.report.nativeDnsHookInterruption.rawPackets = "secret", v => v.report.scenarios.find(row => row.id === interruption.SCENARIO).status = "skipped"]) {
    const value = fixture.artifact(); mutate(value); assert.ok(errors(value).length);
  }
});
