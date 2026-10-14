"use strict";
/** Offline state-copy/proof checks; never starts SCM or touches native keys. */
const { test } = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const helper = require("../tests/e2e/helpers/certops-windows-installed-handoff");
test("SCM handoff proof requires explicit operator scope and every custody/cleanup fact", () => {
  const proof = {
    scope: helper.SCOPE,
    ...Object.fromEntries(helper.FLAGS.map((flag) => [flag, true])),
  };
  assert.equal(helper.verifyProof(proof), true);
  for (const flag of helper.FLAGS) {
    for (const invalid of [false, 1, null, "true"])
      assert.throws(() => helper.verifyProof({ ...proof, [flag]: invalid }));
    const missing = { ...proof };
    delete missing[flag];
    assert.throws(() => helper.verifyProof(missing));
  }
  for (const change of [
    { scope: "automatic-in-place-reregistration" },
    { oldAdcsJobsTransferred: true },
    { rawCredential: "private" },
  ])
    assert.throws(() => helper.verifyProof({ ...proof, ...change }));
});
test("custody copy allowlist preserves source and excludes identity credentials and queues", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-handoff-unit-")),
    source = path.join(root, "source"),
    target = path.join(root, "target");
  try {
    fs.mkdirSync(source);
    for (const name of [
      "credential",
      "bootstrap.env",
      "registration.pending.json",
      "registration-id.json",
      "sequence-state.json",
      "config.json",
    ])
      fs.writeFileSync(path.join(source, name), "private-identity-sentinel");
    fs.mkdirSync(path.join(source, "outbox"));
    fs.writeFileSync(
      path.join(source, "outbox", "old-result.json"),
      "old-message",
    );
    for (const name of ["keys", "job-journal", "windows-cert-store"]) {
      fs.mkdirSync(path.join(source, name));
      fs.writeFileSync(
        path.join(source, name, "owned.json"),
        "local-custody-fixture",
      );
    }
    fs.writeFileSync(path.join(source, "signing-key-pin.json"), "public-pin");
    const before = helper.stateFiles(source),
      protectedEntries = [];
    const platform = {
      applyRestrictivePermissions(file, options) {
        protectedEntries.push([file, options.kind]);
      },
      assertRestrictivePermissions() {},
    };
    const copied = helper.copyCustody(source, target, platform);
    assert.ok(copied.some((row) => row.file === "job-journal/owned.json"));
    assert.ok(copied.some((row) => row.file === "signing-key-pin.json"));
    assert.equal(fs.existsSync(path.join(target, "credential")), false);
    assert.equal(fs.existsSync(path.join(target, "outbox")), false);
    assert.equal(
      fs.existsSync(path.join(target, "registration.pending.json")),
      false,
    );
    assert.deepEqual(helper.stateFiles(source), before);
    assert.equal(
      fs.readFileSync(path.join(target, "keys/owned.json"), "utf8"),
      "local-custody-fixture",
    );
    assert.ok(
      protectedEntries.some(
        ([file, kind]) => file === target && kind === "directory",
      ),
    );
    assert.throws(() => helper.copyCustody(source, target, platform));
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    assert.match(path.basename(root), /^certops-handoff-unit-/);
    fs.rmSync(root, { recursive: true, force: true });
  }
});
test("state enumeration refuses a reparse entry before reading its bytes", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "certops-handoff-unit-"));
  try {
    fs.writeFileSync(path.join(root, "owned"), "public");
    const native = fs.lstatSync;
    t.mock.method(fs, "lstatSync", (file) =>
      path.basename(file) === "owned"
        ? { isSymbolicLink: () => true }
        : native(file),
    );
    assert.throws(() => helper.stateFiles(root), /reparse/);
    t.mock.restoreAll();
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("failed service restoration retains ownership and protected receipt until a successful retry", async () => {
  const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "certops-handoff-unit-"),
    ),
    receipt = path.join(directory, "ownership.json");
  let live = true,
    allowRestore = false;
  try {
    fs.writeFileSync(receipt, "owned receipt");
    const resource = helper.createOwnedHandoffResource({
      receipt,
      hasLiveChild: () => live,
      drain: () => {
        live = false;
        return Promise.resolve();
      },
      restore: () =>
        allowRestore
          ? Promise.resolve()
          : Promise.reject(new Error("foreign SCM registry replacement")),
    });
    await assert.rejects(resource.close(), /foreign SCM/);
    assert.equal(resource.hasLiveChild(), false);
    assert.equal(resource.hasOwnershipReceipt(), true);
    assert.equal(fs.existsSync(receipt), true);
    allowRestore = true;
    await resource.close();
    assert.equal(resource.hasOwnershipReceipt(), false);
    assert.equal(fs.existsSync(receipt), false);
    allowRestore = false;
    await resource.close();
  } finally {
    assert.equal(
      path.dirname(path.resolve(directory)),
      path.resolve(os.tmpdir()),
    );
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("native process-job receipt requires actual descendant drainage and exact wrapper ownership", () => {
  const expected = { token: "a".repeat(32), wrapperPid: 18, ownerPid: 17 },
    valid = {
      ...expected,
      nativeRootPid: 19,
      rootExitCode: 1,
      activeNativeProcesses: 0,
      retainedJobDrained: true,
    };
  assert.equal(helper.verifyDrainReceipt(valid, expected), true);
  for (const change of [
    { token: "b".repeat(32) },
    { wrapperPid: 19 },
    { ownerPid: 16 },
    { nativeRootPid: 0 },
    { activeNativeProcesses: 1 },
    { activeNativeProcesses: false },
    { retainedJobDrained: false },
    { rootExitCode: -1 },
    { rawCommand: "private" },
  ])
    assert.throws(() =>
      helper.verifyDrainReceipt({ ...valid, ...change }, expected),
    );
});
