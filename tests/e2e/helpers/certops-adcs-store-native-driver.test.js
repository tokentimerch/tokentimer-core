"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { startNativeStoreObserver, verifyNativeFault } = require("./certops-adcs-store-native-observer");
const { qualifyNativeStoreRecovery, validateNativeCounts, validateInitialNativeCounts } = require("./certops-adcs-store-native-driver");

test("native observer starts only the scoped lab script and refuses unproven drainage", async () => {
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => {};
  const observer = startNativeStoreObserver({ workDir: "owned", configDir: "config", root: "root", nodeExecutable: "node.exe",
    spawnImpl(program, args, options) {
      assert.equal(program, "powershell.exe");
      assert.match(args[3], /store-accept-phase-fault\.ps1$/);
      assert.equal(args[args.indexOf("-OwnedDirectory") + 1], "owned");
      assert.equal(options.windowsHide, true);
      return child;
    } });
  child.stdout.write("CERTOPS_STORE_ACCEPT_READY\n"); await observer.ready;
  child.emit("close", 1);
  await assert.rejects(observer.result, /not proven/);
  await observer.stopAndDrain();
  assert.equal(observer.hasLiveChild(), true);
});

test("native proof fails before journal inspection when key possession or drainage is missing", () => {
  assert.throws(() => verifyNativeFault({ nativeIdentity: "LocalSystem", observedPostAccept: true,
    nativeProcessDrained: false, keyPossessionVerified: true }, { configDir: "unused" }));
  assert.throws(() => verifyNativeFault({ nativeIdentity: "LocalSystem", observedPostAccept: true,
    nativeProcessDrained: true, keyPossessionVerified: false }, { configDir: "unused" }));
});

test("native driver refuses to run without an independent operation counter", async () => {
  if (process.platform !== "win32") return;
  const previous = process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
  try {
    process.env.CERTOPS_ADCS_DISPOSABLE_LAB = "1";
    await assert.rejects(qualifyNativeStoreRecovery({ serviceOwned: true, ps() {}, until() {}, jobFinished() {} }), /native operation counter/);
  } finally {
    if (previous === undefined) delete process.env.CERTOPS_ADCS_DISPOSABLE_LAB;
    else process.env.CERTOPS_ADCS_DISPOSABLE_LAB = previous;
  }
});

test("native operation counts require continuous complete capture", () => {
  const before = { captureId: "a".repeat(32), coverageComplete: true, submissions: 1, keygens: 1, accepts: 1 };
  assert.equal(validateNativeCounts({ ...before }, before).captureId, before.captureId);
  for (const change of [{ coverageComplete: false }, { captureId: "b".repeat(32) }, { keygens: 0 }, { accepts: null }]) {
    assert.throws(() => validateNativeCounts({ ...before, ...change }, before));
  }
});

test("native capture must count the one initial key, request and acceptance", () => {
  const counts = { captureId: "a".repeat(32), coverageComplete: true, submissions: 1, keygens: 1, accepts: 1 };
  assert.equal(validateInitialNativeCounts(counts, counts.captureId), counts);
  for (const changed of [{ keygens: 2 }, { accepts: 2 }, { submissions: 2 }, { captureId: "b".repeat(32) }]) {
    assert.throws(() => validateInitialNativeCounts({ ...counts, ...changed }, counts.captureId));
  }
});
