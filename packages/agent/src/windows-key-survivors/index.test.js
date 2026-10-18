"use strict";
/** Pure adapter boundary tests: callback execution is simulated, no store/key access. */
const { test } = require("node:test"),
  assert = require("node:assert/strict");
const { inspectMachineKeySurvivors, validateResult } = require("./index");
const valid = {
  complete: true,
  shared: false,
  storesScanned: 2,
  certificatesScanned: 3,
  matches: 0,
};
const args = {
  containerName: "tokentimer-old-job-abcd1234",
  store: "My",
  thumbprint: "AA".repeat(20),
  helperPath: __filename,
};
test("survivor probe invokes shipped helper metadata-only argv and propagates cancellation", async () => {
  const controller = new AbortController();
  const result = await inspectMachineKeySurvivors({
    ...args,
    signal: controller.signal,
    execFileImpl(file, argv, options, callback) {
      assert.equal(file, __filename);
      assert.deepEqual(argv, [
        "--key-survivors",
        "--container",
        args.containerName,
        "--exclude-store",
        "My",
        "--exclude-thumbprint",
        args.thumbprint,
      ]);
      assert.equal(options.signal, controller.signal);
      assert.equal(options.maxBuffer, 4096);
      callback(null, JSON.stringify({ ...valid, shared: true, matches: 1 }));
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.shared, true);
});
test("pre-abort launches zero native commands and all execution failures remain unsafe", async () => {
  const c = new AbortController();
  c.abort();
  assert.equal(
    (
      await inspectMachineKeySurvivors({
        ...args,
        signal: c.signal,
        execFileImpl() {
          throw Error("must not execute");
        },
      })
    ).reason,
    "aborted",
  );
  for (const execFileImpl of [
    (f, a, o, cb) => cb(Error("private diagnostic must not escape")),
    (f, a, o, cb) => cb(null, "not JSON"),
    () => {
      throw Error("spawn");
    },
  ]) {
    const r = await inspectMachineKeySurvivors({ ...args, execFileImpl });
    assert.equal(r.ok, false);
    assert.equal(r.shared, true);
    assert.ok(!JSON.stringify(r).includes("private"));
  }
});
test("malformed/incomplete/contradictory or unbounded native proof cannot authorize deletion", () => {
  assert.deepEqual(validateResult(valid), valid);
  for (const change of [
    { complete: false },
    { reason: "failure" },
    { shared: true },
    { matches: 4 },
    { storesScanned: 0 },
    { storesScanned: 513 },
    { certificatesScanned: 100001 },
    { matches: Infinity },
    { privateKey: "unexpected" },
  ])
    assert.throws(() => validateResult({ ...valid, ...change }));
});

test("key-only global mode counts all references and refuses every partial exclusion before execution", async () => {
  const global = { containerName: args.containerName, helperPath: __filename };
  const result = await inspectMachineKeySurvivors({
    ...global,
    execFileImpl(file, argv, options, callback) {
      assert.deepEqual(argv, [
        "--key-survivors",
        "--container",
        args.containerName,
      ]);
      callback(null, JSON.stringify({ ...valid, shared: true, matches: 2 }));
    },
  });
  assert.equal(result.ok, true);
  assert.equal(result.matches, 2);
  assert.equal(result.shared, true);
  for (const fields of [
    { store: "My" },
    { thumbprint: args.thumbprint },
    { store: null, thumbprint: null },
    { store: "", thumbprint: "" },
  ])
    await assert.rejects(
      inspectMachineKeySurvivors({
        ...global,
        ...fields,
        execFileImpl() {
          throw Error("must not execute");
        },
      }),
      TypeError,
    );
});
