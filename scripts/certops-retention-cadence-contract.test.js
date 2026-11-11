"use strict";
// Supporting protocol checks only: no elapsed/native qualification occurs here.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const c = require("./certops-retention-cadence-contract");
function fixture() {
  const owner = {
    candidateSha: "a".repeat(40),
    runId: "123",
    runAttempt: "1",
    nonce: "b".repeat(64),
    vmResourceId:
      "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/tt-certops-123-1/providers/Microsoft.Compute/virtualMachines/windows-agent",
    vmId: "12345678-1234-1234-1234-123456789abc",
    taskName: `TokenTimer-RetentionCadence-${"b".repeat(64)}`,
    nodeSha256: "c".repeat(64),
    observerSha256: "d".repeat(64),
  };
  const lease = c.createLease(owner, "2026-10-15T00:00:00.000Z");
  const observed = {
    ...owner,
    ...Object.fromEntries(c.FLAGS.map((key) => [key, true])),
    principalSid: "S-1-5-18",
    taskState: "Running",
    processId: 10,
    processCreatedAt: "2026-10-15T00:01:00.0000000Z",
    bootTime: "2026-10-14T23:00:00.000Z",
    serviceHostPid: 11,
    serviceHostCreatedAt: "2026-10-15T00:01:01.0000000Z",
    agentPid: 12,
    agentCreatedAt: "2026-10-15T00:01:02.0000000Z",
    configSha256: "e".repeat(64),
    observerConfigSha256: "1".repeat(64),
    immutableLedgerSha256: "f".repeat(64),
    pendingLedgerFileId: "1:2",
    immediateLedgerFileId: "1:3",
    immediateObservedAt: "2026-10-15T00:02:00.000Z",
    immediateMonotonicMs: 60000,
    oldNotAfter: "2026-10-17T00:00:00.000Z",
    verifiedAt: "2026-10-15T00:03:00.000Z",
  };
  return { lease, observed };
}
test("original authenticated four-hour lease fixes the sixteen-hour ceiling", () => {
  const { lease, observed } = fixture();
  const extended = c.attestHandoff(lease, observed);
  assert.equal(c.verifyOriginalLease(extended, lease), extended);
  assert.equal(
    Date.parse(extended.expiresAt) - Date.parse(lease.createdAt),
    16 * c.HOUR,
  );
  for (const key of ["createdAt", "hardExpiresAt", "observerSha256", "nonce"]) {
    const modified = {
      ...extended,
      [key]: key.endsWith("At") ? "2026-10-16T00:00:00.000Z" : "0".repeat(64),
    };
    assert.throws(() => c.verifyOriginalLease(modified, lease));
  }
  assert.throws(() => c.verifyLease({ ...lease, unexpected: true }));
});
test("every observed native prerequisite is mandatory and file replacement is independent", () => {
  const { lease, observed } = fixture();
  assert.equal(c.verifyObservation(observed, lease), observed);
  for (const flag of c.FLAGS) {
    assert.throws(() =>
      c.verifyObservation({ ...observed, [flag]: false }, lease),
    );
    const missing = { ...observed };
    delete missing[flag];
    assert.throws(() => c.verifyObservation(missing, lease));
  }
  assert.throws(() =>
    c.verifyObservation(
      { ...observed, immediateLedgerFileId: observed.pendingLedgerFileId },
      lease,
    ),
  );
  assert.throws(() =>
    c.verifyObservation(
      { ...observed, oldNotAfter: lease.hardExpiresAt },
      lease,
    ),
  );
  assert.throws(() =>
    c.verifyObservation({ ...observed, taskState: "Ready" }, lease),
  );
});
test("actual monotonic timer rewrite must fit default jitter plus explicit observation margin", () => {
  const t = 60000;
  assert.equal(
    c.verifyTimerWindow(t, t + c.MIN_INTERVAL, t + c.MIN_INTERVAL + 1),
    true,
  );
  assert.equal(
    c.verifyTimerWindow(
      t,
      t + c.MAX_INTERVAL + c.OBSERVATION_MARGIN,
      t + c.MAX_INTERVAL + c.OBSERVATION_MARGIN,
    ),
    true,
  );
  assert.throws(() =>
    c.verifyTimerWindow(
      t,
      t + c.MIN_INTERVAL - c.OBSERVATION_MARGIN - 1,
      t + c.MIN_INTERVAL,
    ),
  );
  assert.throws(() =>
    c.verifyTimerWindow(
      t,
      t + c.MAX_INTERVAL + c.OBSERVATION_MARGIN + 1,
      t + c.MAX_INTERVAL + c.OBSERVATION_MARGIN + 1,
    ),
  );
  assert.throws(() =>
    c.verifyTimerWindow(
      t,
      t + c.MIN_INTERVAL,
      t + c.MIN_INTERVAL + c.OBSERVATION_MARGIN + 1,
    ),
  );
});
