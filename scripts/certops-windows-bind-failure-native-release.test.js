"use strict";
// Synthetic report adversaries only; native runtime remains unexecuted here.
const test = require("node:test"), assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const { artifact } = require("./fixtures/certops-windows-installed-bind-failure-native.cjs");
const slots = require("./certops-qualification-manifest").slots.filter(slot => slot.suite === "windows-installed-bind-failure-rollback");
test("native bind collector accepts only its exact current Server cells and native proof", () => {
  assert.equal(slots.length, 2);
  for (const slot of slots) {
    const input = artifact(slot.environment.osVersion), options = { candidateSha: input.report.candidateSha, specification: { schemaVersion: 1, slots: [slot] } };
    assert.deepEqual(verifyMatrix([input], options), []);
    for (const patch of [{ failureCode: "VERIFY_FAILED" }, { serviceEnvironmentRestored: false }, { nativeInterposer: null }, { nativeInterposer: { ...input.report.nativeInstalledBindFailure.nativeInterposer, captureOverflow: true } }, { scope: "installed-public-bind-failure-injection-and-rollback", nativeExecutionQualified: false }]) {
      const bad = structuredClone(input); Object.assign(bad.report.nativeInstalledBindFailure, patch); assert.ok(verifyMatrix([bad], options).length);
    }
    for (const patch of [{ identity: "Administrator" }, { measurement: "simulated" }, { productType: 1 }, { architecture: "arm64" }]) {
      const bad = structuredClone(input); Object.assign(bad.report.qualificationEnvironment, patch); assert.ok(verifyMatrix([bad], options).length);
    }
  }
});
