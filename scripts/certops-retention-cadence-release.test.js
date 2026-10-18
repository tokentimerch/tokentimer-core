"use strict";
/** Supporting strict release controls only; offline receipts are not native runs. */
const test = require("node:test"),
  assert = require("node:assert/strict");
const { verifyMatrix } = require("./certops-release-qualification");
const { fixture } = require("./test-support/retention-cadence-artifact.cjs");
const matrix = require("../docs/certops/qualification-suites.json");
const slot = matrix.slots.find(
  (x) => x.suite === "windows-domain-installed-retention-default-timer",
);
function verify(report) {
  return verifyMatrix(
    [
      {
        kind: "host",
        suite: slot.suite,
        environment: slot.environment,
        report,
      },
    ],
    {
      candidateSha: report.candidateSha,
      specification: { schemaVersion: 1, slots: [slot] },
    },
  );
}
test("actual factory requires the installed timer scope, native facts and all current sources", () => {
  const { report } = fixture();
  assert.deepEqual(verify(report), []);
  for (const field of Object.keys(report.nativeRetentionCadence)) {
    const changed = structuredClone(report);
    delete changed.nativeRetentionCadence[field];
    assert.ok(verify(changed).length, field);
  }
  for (const change of [
    (r) => {
      r.nativeRetentionCadence.full168HourRetentionQualified = true;
    },
    (r) => {
      r.nativeRetentionCadence.actualMonotonicIntervalMs = 1;
    },
    (r) => {
      r.nativeRetentionCadence.agentPid = 4294967296;
    },
    (r) => {
      r.nativeRetentionCadence.foreign = true;
    },
    (r) => {
      r.platform = "linux";
    },
    (r) => {
      r.cleanup.status = "failed";
    },
    (r) => {
      r.fixtureSources.pop();
    },
    (r) => {
      r.fixtureSources[0].sha256 = "0".repeat(64);
    },
    (r) => {
      r.scenarios.pop();
    },
    (r) => {
      r.capabilities.api.available = false;
    },
  ]) {
    const changed = structuredClone(report);
    change(changed);
    assert.ok(verify(changed).length);
  }
});
