"use strict";
/** Offline release/source adversaries only; no consuming daemon is run. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const fixture = require("./test-support/daemon-coordinator-artifact.cjs"),
  helper = require("./certops-daemon-coordinator-rollback");
const errors = (value, service = "nginx", version = "24.04") =>
  verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: {
      schemaVersion: 1,
      slots: [fixture.slot(service, version)],
    },
  });
test("all six consuming-service slots require native rollback proof and exact critical sources", () => {
  for (const service of ["nginx", "apache", "haproxy"])
    for (const version of ["22.04", "24.04"])
      assert.deepEqual(
        errors(fixture.artifact(service, version), service, version),
        [],
      );
  for (const flag of helper.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeDaemonCoordinatorRollback[flag];
    assert.ok(errors(value).length);
  }
  for (const file of helper.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === file).sha256 =
      "e".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("daemon native release refuses service relabeling, signed-API promotion and missing cleanup", () => {
  for (const change of [
    { service: "apache" },
    { evidenceTransport: "signed-api" },
    { rawKey: "secret" },
  ]) {
    const value = fixture.artifact();
    Object.assign(value.report.nativeDaemonCoordinatorRollback, change);
    assert.ok(errors(value).length);
  }
  for (const mutate of [
    (v) => delete v.report.nativeDaemonCoordinatorRollback,
    (v) => {
      v.report.platform = "win32";
    },
    (v) => {
      v.report.cleanup.status = "failed";
    },
    (v) => {
      v.report.scenarios[0].status = "skipped";
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});
