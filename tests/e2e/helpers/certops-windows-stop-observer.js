"use strict";
/** Closed public protocol for the read-only retained-handle observer.
 * A completed receipt proves only the identified handles exited. It cannot
 * establish atomic ownership of descendants that were never observed. */
const assert = require("node:assert/strict");
const READY_FIELDS = Object.freeze([
  "schemaVersion",
  "token",
  "observerPid",
  "capturedProcessCount",
  "retainedReadOnlyHandles",
]);
const RESULT_FIELDS = Object.freeze([
  "schemaVersion",
  "token",
  "capturedProcessCount",
  "rootExitCode",
  "nodeExitCode",
  "allCapturedHandlesExited",
  "capturedLineageAbsent",
  "fixtureCommandPathsAbsent",
  "readOnlyObservation",
  "atomicTreeContainmentQualified",
  "nativeHandlesClosed",
]);
function closed(value, fields, token) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort());
  assert.equal(value.schemaVersion, 1);
  assert.match(token, /^[a-f0-9]{64}$/);
  assert.equal(value.token, token);
  assert.ok(Number.isSafeInteger(value.capturedProcessCount));
  assert.ok(
    value.capturedProcessCount >= 2 && value.capturedProcessCount <= 128,
  );
}
function verifyReady(value, { token, observerPid }) {
  closed(value, READY_FIELDS, token);
  assert.ok(
    Number.isSafeInteger(observerPid) &&
      observerPid > 0 &&
      observerPid <= 0xffffffff,
  );
  assert.equal(value.observerPid, observerPid);
  assert.equal(value.retainedReadOnlyHandles, true);
  return true;
}
function verifyResult(value, { token, ready, observerPid, observerClosed }) {
  verifyReady(ready, { token, observerPid });
  closed(value, RESULT_FIELDS, token);
  assert.equal(
    observerClosed,
    true,
    "Retained observer must close before accepting native receipt",
  );
  assert.equal(value.capturedProcessCount, ready.capturedProcessCount);
  for (const field of ["rootExitCode", "nodeExitCode"])
    assert.ok(
      Number.isSafeInteger(value[field]) &&
        value[field] >= 0 &&
        value[field] <= 0xffffffff,
    );
  for (const name of [
    "allCapturedHandlesExited",
    "capturedLineageAbsent",
    "fixtureCommandPathsAbsent",
    "readOnlyObservation",
    "nativeHandlesClosed",
  ])
    assert.equal(value[name], true, name);
  assert.equal(value.atomicTreeContainmentQualified, false);
  return true;
}
function classifyObservedStop(log, { nodePid, rootExitCode, nodeExitCode }) {
  assert.ok(typeof log === "string" && Buffer.byteLength(log) <= 1024 * 1024);
  assert.ok(
    Number.isSafeInteger(nodePid) && nodePid > 0 && nodePid <= 0xffffffff,
  );
  assert.equal(
    rootExitCode,
    0,
    "Installed service host must complete its requested stop",
  );
  const prefix = `child pid=${nodePid} `;
  const hostPrefix =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z tokentimer-agent-host: /;
  const hostLines = log.split(/\r?\n/).filter((line) => hostPrefix.test(line));
  const lines = hostLines.filter((line) => line.includes(prefix));
  const graceful = lines.filter((line) =>
    line.endsWith(prefix + "exited gracefully: <nil>"),
  );
  const fallback = lines.filter((line) =>
    line.endsWith(
      prefix +
        "did not exit within 20s of the stop signal; forcing termination",
    ),
  );
  const deliveryFailed = hostLines.some((line) =>
    line.includes(
      `could not deliver a graceful stop signal to pid=${nodePid}:`,
    ),
  );
  assert.equal(
    deliveryFailed,
    false,
    "Signal delivery failure is not this stop boundary",
  );
  assert.equal(
    graceful.length + fallback.length,
    1,
    "Exactly one observed host stop outcome required",
  );
  if (graceful.length === 1) {
    assert.equal(
      nodeExitCode,
      0,
      "Graceful host log must match retained Node exit",
    );
    return "graceful-stop-observed";
  }
  assert.ok(
    Number.isSafeInteger(nodeExitCode) &&
      nodeExitCode > 0 &&
      nodeExitCode <= 0xffffffff,
    "Timeout fallback must match actual retained nonzero Node exit",
  );
  return "host-timeout-fallback-observed";
}
module.exports = {
  READY_FIELDS,
  RESULT_FIELDS,
  verifyReady,
  verifyResult,
  classifyObservedStop,
};
