"use strict";
/** Offline release and source adversaries; no native trust refresh runs. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const fixture = require("./test-support/linux-trust-independent-artifact.cjs");
const h = require("./certops-linux-trust-independent-roots");
const errors = (artifact, version = "24.04") =>
  verifyMatrix([artifact], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [fixture.slot(version)] },
  });
test("three native trust slots require genuine selective root preservation proof and exact sources", () => {
  for (const version of ["22.04", "24.04", "9.6"])
    assert.deepEqual(errors(fixture.artifact(version), version), []);
  for (const flag of h.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeIndependentTrustRoots[flag];
    assert.ok(errors(value).length);
  }
  for (const file of h.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === file).sha256 =
      "e".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("trust release rejects wrong native family, unclosed proof, skipped cases and failed cleanup", () => {
  for (const mutate of [
    (v) => delete v.report.nativeIndependentTrustRoots,
    (v) => {
      v.report.nativeIndependentTrustRoots.family = "rhel";
    },
    (v) => {
      v.report.platform = "win32";
    },
    (v) => {
      v.report.nativeIndependentTrustRoots.rawKey = "secret";
    },
    (v) => {
      v.report.scenarios[0].status = "skipped";
    },
    (v) => {
      v.report.cleanup.status = "failed";
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});
