"use strict";
/** Offline measured-fact contract fixtures; no clock, service or CA executes. */
const test = require("node:test"),
  assert = require("node:assert/strict");
const h = require("../tests/e2e/helpers/certops-windows-stop-offline-proof");
const { fixture } = require("./test-support/windows-stop-offline.cjs");

test("stopped offline proof binds actual production15minlease10minoffline1hgrace without claiming alivegrace or workerloop", () => {
  h.verifyProof(fixture());
  h.verifyProof({ ...fixture(), stopOutcome: "graceful-stop-observed" });
  for (const key of Object.keys(fixture())) {
    const bad = fixture();
    delete bad[key];
    assert.throws(() => h.verifyProof(bad));
  }
});
test("accelerated timing, premature reaping, replay and graceful relabeling cannot qualify", () => {
  for (const patch of [
    { defaultLeaseMs: 60000 },
    { defaultOfflineMs: 1 },
    { defaultHardGraceMs: 60000 },
    { defaultAliveGraceElapsedQualified: true },
    { deployedWorkerLoopQualified: true },
    { atomicTreeContainmentQualified: true },
    { originalOperationAutomaticallyRecovered: true },
    { waitedMonotonicMs: 100 },
    { reapedObservedAt: "2026-10-15T10:14:59.000Z" },
    { originalAttemptCount: 2 },
    { originalTerminalStatus: "failed" },
    { stopOutcome: "graceful" },
    { privateKey: "secret" },
  ])
    assert.throws(() => h.verifyProof({ ...fixture(), ...patch }));
});
