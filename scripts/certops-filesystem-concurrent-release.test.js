"use strict";
/** Offline schema/source adversaries only. No native process, certificate or service executes. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const fixture = require("./test-support/filesystem-concurrent-artifact.cjs");
const helper = require("./certops-filesystem-concurrent");
function errors(value) {
  return verifyMatrix([value], {
    candidateSha: fixture.CANDIDATE,
    specification: { schemaVersion: 1, slots: [fixture.slot()] },
  });
}
test("Filesystem concurrency release requires closed real-host scope and every measured refusal/recovery flag", () => {
  assert.deepEqual(errors(fixture.artifact()), []);
  for (const flag of helper.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeFilesystemConcurrency[flag];
    assert.ok(errors(value).length);
    const wrong = fixture.artifact();
    wrong.report.nativeFilesystemConcurrency[flag] = false;
    assert.ok(errors(wrong).length);
  }
  for (const changed of [
    { contenderCount: 0 },
    { completedMutations: true },
    { scope: "signed-service-deployment" },
    { rawPrivateKey: "withheld" },
  ]) {
    const value = fixture.artifact();
    Object.assign(value.report.nativeFilesystemConcurrency, changed);
    assert.ok(errors(value).length);
  }
});
test("Filesystem concurrency release cannot accept mislabeled platforms, containers, skipped cases or stale critical sources", () => {
  const mutations = [
    (value) => delete value.report.nativeFilesystemConcurrency,
    (value) => {
      value.report.platform = "win32";
      value.report.nativeFilesystemBackupAlias.aliasKind = "junction";
      value.report.nativeFilesystemBackupAlias.aliasKind = "junction";
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

test("paired concurrency is required in all four existing native filesystem slots", () => {
  const slots =
    require("./certops-qualification-manifest").slots.filter(
      (row) => row.suite === fixture.SUITE,
    );
  assert.equal(slots.length, 4);
  for (const slot of slots) {
    const value = fixture.artifact();
    Object.assign(value.report.qualificationEnvironment, slot.environment);
    if (slot.environment.osFamily === "windows") {
      Object.assign(value.report.qualificationEnvironment, { productType: 3 });
      value.report.platform = "win32";
      value.report.nativeFilesystemBackupAlias.aliasKind = "junction";
      delete value.report.qualificationEnvironment.distributionId;
      delete value.report.qualificationEnvironment.distributionVersion;
      delete value.report.qualificationEnvironment.executionSurface;
    }
    value.environment = value.report.qualificationEnvironment;
    assert.deepEqual(
      verifyMatrix([value], {
        candidateSha: fixture.CANDIDATE,
        specification: { schemaVersion: 1, slots: [slot] },
      }),
      [],
    );
  }
});

test("native backup alias scope refuses missing observations and wrong platform or recovery", () => {
  const h = require("./certops-filesystem-backup-alias");
  for (const flag of h.FLAGS) {
    const value = fixture.artifact();
    delete value.report.nativeFilesystemBackupAlias[flag];
    assert.ok(errors(value).length);
  }
  for (const change of [
    { aliasKind: "junction" },
    { refusalStage: "backup-key" },
    { rawKey: "secret" },
  ]) {
    const value = fixture.artifact();
    Object.assign(value.report.nativeFilesystemBackupAlias, change);
    assert.ok(errors(value).length);
  }
  const value = fixture.artifact();
  delete value.report.nativeFilesystemBackupAlias;
  assert.ok(errors(value).length);
});

test("native retention count cannot omit scoped pruning or sibling/private preservation", () => {
  const h = require("./certops-filesystem-backup-retention");
  for (const flag of h.FLAGS) {
    const v = fixture.artifact();
    delete v.report.nativeFilesystemBackupRetention[flag];
    assert.ok(errors(v).length);
  }
  for (const p of [
    { retentionCount: 2 },
    { targetCount: 1 },
    { rawKey: "secret" },
  ]) {
    const v = fixture.artifact();
    Object.assign(v.report.nativeFilesystemBackupRetention, p);
    assert.ok(errors(v).length);
  }
});

test("every filesystem release slot requires actual paired rollback evidence and causal source identity", () => {
  const h = require("./certops-filesystem-host");
  const slots = require("./certops-qualification-manifest").slots.filter(row => row.suite === fixture.SUITE);
  for (const slot of slots) assert.deepEqual(slot.requiredSources, h.ROLLBACK_SOURCES);
  assert.ok(fixture.IDS.includes(h.ROLLBACK_SCENARIO));
  for (const flag of h.ROLLBACK_FLAGS) {
    const value = fixture.artifact(); delete value.report.nativeFilesystemPairedRollback[flag];
    assert.ok(errors(value).length);
    for (const wrong of [false, 1, "true", null]) {
      const changed = fixture.artifact(); changed.report.nativeFilesystemPairedRollback[flag] = wrong;
      assert.ok(errors(changed).length);
    }
  }
  for (const mutate of [value => delete value.report.nativeFilesystemPairedRollback, value => { value.report.nativeFilesystemPairedRollback.fingerprints.fill("a".repeat(64)); }, value => { value.report.scenarios.find(row => row.id === h.ROLLBACK_SCENARIO).status = "skipped"; }, value => { value.report.nativeFilesystemPairedRollback.privateKey = "withheld"; }]) {
    const value = fixture.artifact(); mutate(value); assert.ok(errors(value).length);
  }
  for (const source of h.ROLLBACK_SOURCES) {
    const value = fixture.artifact(); value.report.fixtureSources.find(row => row.file === source).sha256 = "b".repeat(64);
    assert.ok(errors(value).length);
  }
});
