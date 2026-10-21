"use strict";
/** Pure receipt checks only: no Windows processes or native APIs are invoked. */
const test = require("node:test");
const assert = require("node:assert/strict");
const observer = require("../tests/e2e/helpers/certops-windows-stop-observer");
function fixture() {
  const token = "a".repeat(64),
    observerPid = 123;
  const ready = {
    schemaVersion: 1,
    token,
    observerPid,
    capturedProcessCount: 3,
    retainedReadOnlyHandles: true,
  };
  const result = {
    schemaVersion: 1,
    token,
    capturedProcessCount: 3,
    rootExitCode: 0,
    nodeExitCode: 0,
    allCapturedHandlesExited: true,
    capturedLineageAbsent: true,
    fixtureCommandPathsAbsent: true,
    readOnlyObservation: true,
    atomicTreeContainmentQualified: false,
    nativeHandlesClosed: true,
  };
  return {
    ready,
    result,
    context: { token, ready, observerPid, observerClosed: true },
  };
}
test("read-only stop receipt requires observer close and exact captured-handle facts", () => {
  const f = fixture();
  assert.equal(observer.verifyResult(f.result, f.context), true);
  for (const key of [
    "allCapturedHandlesExited",
    "capturedLineageAbsent",
    "fixtureCommandPathsAbsent",
    "readOnlyObservation",
    "nativeHandlesClosed",
  ])
    assert.throws(() =>
      observer.verifyResult({ ...f.result, [key]: false }, f.context),
    );
  assert.throws(() =>
    observer.verifyResult(f.result, { ...f.context, observerClosed: false }),
  );
  assert.throws(() =>
    observer.verifyResult(
      { ...f.result, atomicTreeContainmentQualified: true },
      f.context,
    ),
  );
});
test("observer receipts reject mismatched identity, private fields and unbounded native values", () => {
  const f = fixture();
  for (const patch of [
    { token: "b".repeat(64) },
    { capturedProcessCount: 4 },
    { rootExitCode: -1 },
    { rootExitCode: 0x100000000 },
    { rootExitCode: "0" },
    { nodeExitCode: -1 },
    { nodeExitCode: 0x100000000 },
    { privateCommandLine: "private" },
  ])
    assert.throws(() =>
      observer.verifyResult({ ...f.result, ...patch }, f.context),
    );
  for (const patch of [
    { observerPid: 0 },
    { capturedProcessCount: 129 },
    { retainedReadOnlyHandles: false },
  ])
    assert.throws(() =>
      observer.verifyReady({ ...f.ready, ...patch }, f.context),
    );
});
test("stop classification binds exact host log outcome to retained native exit facts", () => {
  const prefix = "2026-10-15T00:00:00Z tokentimer-agent-host: child pid=123 ";
  const graceful = prefix + "exited gracefully: <nil>";
  const fallback =
    prefix + "did not exit within 20s of the stop signal; forcing termination";
  assert.equal(
    observer.classifyObservedStop(graceful, {
      nodePid: 123,
      rootExitCode: 0,
      nodeExitCode: 0,
    }),
    "graceful-stop-observed",
  );
  assert.equal(
    observer.classifyObservedStop(fallback, {
      nodePid: 123,
      rootExitCode: 0,
      nodeExitCode: 1,
    }),
    "host-timeout-fallback-observed",
  );
  for (const [log, exits] of [
    ["", [0, 0]],
    [graceful, [0, 1]],
    [fallback, [0, 0]],
    [graceful, [1, 0]],
    [graceful + "\n" + fallback, [0, 1]],
    [graceful.replace("123", "124"), [0, 0]],
  ])
    assert.throws(() =>
      observer.classifyObservedStop(log, {
        nodePid: 123,
        rootExitCode: exits[0],
        nodeExitCode: exits[1],
      }),
    );
});
