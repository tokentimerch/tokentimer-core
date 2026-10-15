"use strict";
// Offline report/source regressions, never installed-service execution proof.
const test = require("node:test"),
  assert = require("node:assert/strict");
const fixture = require("./test-support/linux-installed-discovery-proof.cjs"),
  helper = require("../tests/e2e/helpers/certops-linux-installed-discovery");
const slot = (version) =>
  require("../docs/certops/release-qualification-matrix.json").slots.find(
    (row) => row.id === `linux-installed-file-discovery-${version}`,
  );
const errors = (artifact, version = "24.04") =>
  require("./certops-release-qualification").verifyMatrix([artifact], {
    candidateSha: "a".repeat(40),
    specification: { schemaVersion: 1, slots: [slot(version)] },
  });
test("both current-source native Ubuntu installed discovery reports satisfy only their declared cells", () => {
  for (const version of ["22.04", "24.04"]) {
    assert.deepEqual(errors(fixture.artifact(version), version), []);
    assert.ok(
      errors(fixture.artifact(version), version === "22.04" ? "24.04" : "22.04")
        .length,
    );
  }
  for (const source of helper.REQUIRED_SOURCES) {
    const value = fixture.artifact();
    value.report.fixtureSources.find((row) => row.file === source).sha256 =
      "f".repeat(64);
    assert.ok(errors(value).length);
  }
});
test("every actual discovery/native-restoration fact and strict cleanup is mandatory", () => {
  for (const flag of helper.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeInstalledFileDiscovery[flag];
    assert.ok(errors(value).length);
  }
  for (const mutate of [
    (value) => {
      delete value.report.nativeInstalledFileDiscovery;
    },
    (value) => {
      value.report.nativeInstalledFileDiscovery.uid = 0;
    },
    (value) => {
      value.report.nativeInstalledFileDiscovery.gid = true;
    },
    (value) => {
      value.report.nativeInstalledFileDiscovery.positiveScanCount = 1;
    },
    (value) => {
      value.report.nativeInstalledFileDiscovery.privateConfig =
        "must-not-survive";
    },
    (value) => {
      value.report.cleanup.status = "failed";
    },
    (value) => {
      value.report.scenarios[0].status = "skipped";
    },
    (value) => {
      value.report.platform = "win32";
    },
    (value) => {
      value.report.qualificationEnvironment.executionSurface = "container";
    },
  ]) {
    const value = fixture.artifact();
    mutate(value);
    assert.ok(errors(value).length);
  }
});
