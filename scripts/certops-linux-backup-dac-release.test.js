"use strict";
/** Offline schema/source adversaries only. No Linux process, certificate or service executes. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const fixture = require("./test-support/linux-backup-dac-artifact.cjs");
const helper = require("./certops-linux-filesystem-permission");
function errors(value) {
  return verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [fixture.slot()] },
  });
}
test("Linux DAC release requires closed real-host scope and every measured refusal/recovery flag", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of helper.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeLinuxBackupDac[flag];
    assert.ok(errors(value).length);
    const wrong = fixture.artifact();
    wrong.report.nativeLinuxBackupDac[flag] = false;
    assert.ok(errors(wrong).length);
  }
  for (const changed of [
    { uid: 0 },
    { gid: true },
    { scope: "signed-service-deployment" },
    { rawPrivateKey: "withheld" },
  ]) {
    const value = fixture.artifact();
    Object.assign(value.report.nativeLinuxBackupDac, changed);
    assert.ok(errors(value).length);
  }
});
test("Linux DAC release cannot accept Windows, containers, skipped cases or stale critical sources", () => {
  const mutations = [
    (value) => delete value.report.nativeLinuxBackupDac,
    (value) => {
      value.report.platform = "win32";
    },
    (value) => {
      value.report.architecture = "arm64";
    },
    (value) => {
      value.report.qualificationEnvironment = {
        ...value.report.qualificationEnvironment,
        executionSurface: "container",
      };
    },
    (value) => {
      value.report.scenarios[0].status = "skipped";
    },
    (value) => {
      value.report.cleanup.status = "failed";
    },
  ];
  for (const mutate of mutations) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
  for (const file of helper.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === file).sha256 =
      "b".repeat(64);
    assert.ok(errors(value).length);
  }
});
