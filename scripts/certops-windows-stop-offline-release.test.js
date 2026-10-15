"use strict";
/** Current-source synthetic reports only; never a native execution verdict. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  {
    artifact,
    candidateSha,
  } = require("./test-support/windows-stop-offline.cjs"),
  { verifyMatrix } = require("./certops-release-qualification");
const slots =
  require("../docs/certops/release-qualification-matrix.json").slots.filter(
    (x) => x.suite === "windows-installed-stop-offline-renewal",
  );
function errors(value, slot) {
  return verifyMatrix([value], {
    candidateSha,
    specification: { schemaVersion: 1, slots: [slot] },
  });
}
test("both separate stopped/offline Server slots require actual closed facts and current causal sources", () => {
  assert.equal(slots.length, 2);
  for (const slot of slots) {
    const make = () => artifact(slot.environment.osVersion);
    assert.deepEqual(errors(make(), slot), []);
    for (const key of Object.keys(make().report.nativeWindowsStoppedOffline)) {
      const missing = make();
      delete missing.report.nativeWindowsStoppedOffline[key];
      assert.ok(errors(missing, slot).length, key);
    }
    for (const change of [
      (r) => (r.cleanup.status = "failed"),
      (r) => (r.architecture = "arm64"),
      (r) => (r.qualificationEnvironment.identity = "Administrator"),
      (r) =>
        (r.nativeWindowsStoppedOffline.atomicTreeContainmentQualified = true),
      (r) => (r.nativeWindowsStoppedOffline.waitedMonotonicMs = 1),
      (r) => (r.scenarios = []),
    ]) {
      const value = make();
      change(value.report);
      assert.ok(errors(value, slot).length);
    }
    for (const file of slot.requiredSources) {
      const stale = make();
      stale.report.fixtureSources.find((x) => x.file === file).sha256 =
        "f".repeat(64);
      assert.ok(errors(stale, slot).length, file);
    }
  }
});
