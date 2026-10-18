"use strict";
// Pure evidence and source-admission regressions. No native certificate/process
// mutation, fake clock advancement or 24-hour execution is performed here.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-retention24h-interrupted");
const { DAY } = require("./certops-retention24h-contract");
const deadline = "2026-10-15T12:00:00.000Z";
function proof() {
  return {
    scope: helper.SCOPE,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
    monotonicElapsedBeforeCrashMs: DAY + 100,
    interruptedAt: "2026-10-15T12:01:00.000Z",
    resumedAt: "2026-10-15T12:01:10.000Z",
    cleanupDeadline: deadline,
    productionSixHourCadenceQualified: false,
    full168HourRetentionQualified: false,
  };
}
test("real-day interruption proof requires every native stage and refuses broader timing claims", () => {
  assert.equal(helper.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const missing = proof();
    delete missing[key];
    assert.throws(() => helper.verifyProof(missing), key);
  }
  for (const key of helper.FLAGS)
    for (const value of [false, 1, "true", null])
      assert.throws(
        () => helper.verifyProof({ ...proof(), [key]: value }),
        key,
      );
  for (const patch of [
    { monotonicElapsedBeforeCrashMs: DAY - 1 },
    { monotonicElapsedBeforeCrashMs: DAY + 0.5 },
    { interruptedAt: deadline },
    { resumedAt: deadline },
    { productionSixHourCadenceQualified: true },
    { full168HourRetentionQualified: true },
    { rawNativeKey: "private" },
  ])
    assert.throws(() => helper.verifyProof({ ...proof(), ...patch }));
});
test("native deletion receipt binds the exact owned child certificate key and postdeadline event", () => {
  const expected = {
    thumbprint: "A".repeat(40),
    containerName: "tokentimer-enr-11111111-1111-1111-1111-111111111111",
    childPid: 123,
    cleanupDeadline: deadline,
  };
  const receipt = {
    fault: "process-exit-after-native-delstore-before-delkey",
    thumbprint: expected.thumbprint,
    containerName: expected.containerName,
    nativeCommandSucceeded: true,
    pid: 123,
    observedAt: "2026-10-15T12:01:00.000Z",
  };
  assert.equal(helper.verifyReceipt(receipt, expected), true);
  for (const change of [
    { fault: "before-delete" },
    { thumbprint: "B".repeat(40) },
    { containerName: "foreign" },
    { pid: 999 },
    { nativeCommandSucceeded: false },
    { observedAt: deadline },
    { rawCommand: "private" },
  ])
    assert.throws(() =>
      helper.verifyReceipt({ ...receipt, ...change }, expected),
    );
});
test("same resident day precedes the native fault and ordinary production resume without clock injection", () => {
  const keeper = fs.readFileSync(
    path.resolve(
      __dirname,
      "../tests/e2e/helpers/certops-retention24h-keeper.js",
    ),
    "utf8",
  );
  assert.ok(
    keeper.indexOf("await beforeDueSweep(") >
      keeper.indexOf("await waitUntilMonotonic(startMonoMs + DAY"),
  );
  assert.ok(
    keeper.indexOf('await sweep("removed-after-real-day")') >
      keeper.indexOf("await beforeDueSweep("),
  );
  const child = fs.readFileSync(
    path.resolve(
      __dirname,
      "../packages/agent/scripts/host/retention-interrupted-child.js",
    ),
    "utf8",
  );
  assert.match(child, /process\.exit\(86\)/);
  assert.match(child, /args\[0\] === "-delstore"/);
  assert.match(
    child,
    /Date\.now\(\)\s*>\s*Date\.parse\(config\.cleanupDeadline\)/,
  );
  assert.doesNotMatch(
    child,
    /writeLedgerRow|writeFileSync\([^\n]*windows-retention/,
  );
  const source = fs.readFileSync(
    require.resolve("../tests/e2e/helpers/certops-retention24h-interrupted"),
    "utf8",
  );
  assert.match(source, /startContainedNativeProcess/);
  assert.match(source, /onCreated/);
  assert.match(source, /rootExitCode,\s*86/);
  assert.doesNotMatch(source, /taskkill|Stop-Process/);
});
