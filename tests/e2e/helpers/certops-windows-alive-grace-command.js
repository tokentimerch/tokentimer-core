"use strict";
/** Qualification-only pre-delegation gate. It never fabricates a certificate,
 * result or command output. The real installed executor owns command lifetime. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawn } = require("node:child_process"),
  { setTimeout: delay } = require("node:timers/promises");
const { readOwned } = require("./certops-windows-installed-verify-rollback");
const id = (s) => `${s.dev}:${s.ino}`;
function publish(file, value) {
  const temporary = file + ".pending-" + crypto.randomBytes(8).toString("hex");
  const bytes = Buffer.from(JSON.stringify(value));
  const fd = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.linkSync(temporary, file);
  fs.unlinkSync(temporary);
  return bytes;
}
const active = new Set();
const rootKey = (root) => path.resolve(root).toLowerCase();
function assertCleanupSafe(root) {
  assert.ok(
    !active.has(rootKey(root)) &&
      !fs.existsSync(path.join(root, "alive-grace-command")),
    "Preserve unresolved owned command gate",
  );
}
function createCommandBarrier({ root, program, args, ownedResources }) {
  assert.equal(
    fs.realpathSync.native(root).toLowerCase(),
    path.resolve(root).toLowerCase(),
  );
  assert.equal(typeof program, "string");
  assert.ok(Array.isArray(args) && args.every((a) => typeof a === "string"));
  assert.ok(Array.isArray(ownedResources));
  assertCleanupSafe(root);
  const rootIdentity = fs.lstatSync(root, { bigint: true });
  assert.ok(
    rootIdentity.isDirectory() &&
      !rootIdentity.isSymbolicLink() &&
      rootIdentity.dev > 0n &&
      rootIdentity.ino > 0n,
  );
  const directory = path.join(root, "alive-grace-command"),
    receipt = { root, cleanupCompleted: false };
  ownedResources.push(receipt);
  active.add(rootKey(root));
  fs.mkdirSync(directory);
  const original = fs.lstatSync(directory, { bigint: true });
  const files = new Map();
  let token = null,
    released = false,
    finished = false;
  const check = () => {
    const currentRoot = fs.lstatSync(root, { bigint: true });
    assert.ok(
      currentRoot.isDirectory() &&
        !currentRoot.isSymbolicLink() &&
        id(currentRoot) === id(rootIdentity),
      "Original command gate root required",
    );
    const s = fs.lstatSync(directory, { bigint: true });
    assert.ok(
      s.isDirectory() && !s.isSymbolicLink() && id(s) === id(original),
      "Original owned command gate required",
    );
  };
  check();
  require("../../../packages/agent/src/platform").applyRestrictivePermissions(
    directory,
    { kind: "directory" },
  );
  check();
  const file = (name) => path.join(directory, name);
  const record = (name) => {
    check();
    const r = readOwned(file(name), 8192);
    if (files.has(name)) {
      const before = files.get(name);
      assert.ok(
        id(r.stat) === id(before.stat) && r.bytes.equals(before.bytes),
        "Original command receipt changed",
      );
    } else files.set(name, r);
    return r;
  };
  const write = (name, value) => {
    check();
    const bytes = publish(file(name), value);
    const r = record(name);
    assert.ok(r.bytes.equals(bytes));
    return r;
  };
  return {
    argv: [process.execPath, __filename, directory, program, ...args],
    arm() {
      assert.equal(token, null);
      check();
      assert.deepEqual(fs.readdirSync(directory), []);
      token = crypto.randomBytes(32).toString("hex");
      write("arm.json", { schemaVersion: 1, token });
    },
    observe() {
      assert.ok(token);
      check();
      if (
        !fs.existsSync(file("ready.json")) ||
        fs
          .readdirSync(directory)
          .some((name) => name.startsWith("ready.json.pending-"))
      )
        return null;
      const r = JSON.parse(record("ready.json").bytes);
      assert.deepEqual(
        Object.keys(r).sort(),
        ["schemaVersion", "token", "pid", "parentPid", "armId"].sort(),
      );
      assert.equal(r.schemaVersion, 1);
      assert.equal(r.token, token);
      assert.equal(r.armId, id(files.get("arm.json").stat));
      for (const k of ["pid", "parentPid"])
        assert.ok(Number.isSafeInteger(r[k]) && r[k] > 0 && r[k] <= 0xffffffff);
      return r;
    },
    release() {
      assert.ok(token && !released);
      assert.ok(this.observe());
      record("arm.json");
      write("go.json", { schemaVersion: 1, token });
      released = true;
    },
    finish() {
      assert.ok(!finished);
      if (token === null) {
        check();
        assert.deepEqual(fs.readdirSync(directory), []);
        fs.rmdirSync(directory);
        finished = true;
        receipt.cleanupCompleted = true;
        active.delete(rootKey(root));
        return;
      }
      assert.ok(released);
      const ready = this.observe(),
        closed = JSON.parse(record("closed.json").bytes);
      assert.deepEqual(
        Object.keys(closed).sort(),
        [
          "schemaVersion",
          "token",
          "pid",
          "parentPid",
          "exitCode",
          "signal",
        ].sort(),
      );
      assert.equal(closed.schemaVersion, 1);
      assert.equal(closed.token, token);
      assert.equal(closed.pid, ready.pid);
      assert.equal(closed.parentPid, ready.parentPid);
      assert.equal(closed.exitCode, 0);
      assert.equal(closed.signal, null);
      assert.deepEqual(fs.readdirSync(directory).sort(), [
        "arm.json",
        "closed.json",
        "go.json",
        "ready.json",
      ]);
      for (const name of files.keys()) record(name);
      for (const [name, r] of files) {
        check();
        const now = record(name);
        assert.ok(id(now.stat) === id(r.stat));
        fs.unlinkSync(file(name));
      }
      check();
      fs.rmdirSync(directory);
      finished = true;
      receipt.cleanupCompleted = true;
      active.delete(rootKey(root));
    },
    hasArmed: () => token !== null,
    hasOwnershipReceipt: () => !finished,
    hasLiveResource: () => !finished,
  };
}
async function main(argv = process.argv.slice(2)) {
  assert.equal(process.platform, "win32");
  const [directory, program, ...args] = argv;
  assert.ok(directory && program);
  const arm = path.join(directory, "arm.json");
  let control = null;
  if (fs.existsSync(arm)) {
    const r = readOwned(arm, 8192);
    control = JSON.parse(r.bytes);
    assert.deepEqual(Object.keys(control).sort(), ["schemaVersion", "token"]);
    assert.equal(control.schemaVersion, 1);
    assert.match(control.token, /^[a-f0-9]{64}$/);
    const ready = {
      schemaVersion: 1,
      token: control.token,
      pid: process.pid,
      parentPid: process.ppid,
      armId: id(r.stat),
    };
    publish(path.join(directory, "ready.json"), ready);
    const began = performance.now();
    while (
      !fs.existsSync(path.join(directory, "go.json")) ||
      fs
        .readdirSync(directory)
        .some((name) => name.startsWith("go.json.pending-"))
    ) {
      assert.ok(
        performance.now() - began < 120000,
        "Owned pre-delegation gate exceeded2min",
      );
      await delay(50);
    }
    const now = readOwned(arm, 8192);
    assert.ok(
      id(now.stat) === id(r.stat) && now.bytes.equals(r.bytes),
      "Original command gate changed",
    );
    assert.deepEqual(
      JSON.parse(readOwned(path.join(directory, "go.json"), 8192).bytes),
      control,
    );
  }
  const child = spawn(program, args, {
    env: process.env,
    stdio: "inherit",
    windowsHide: true,
  });
  const result = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (exitCode, signal) => resolve({ exitCode, signal }));
  });
  if (control)
    publish(path.join(directory, "closed.json"), {
      schemaVersion: 1,
      token: control.token,
      pid: process.pid,
      parentPid: process.ppid,
      ...result,
    });
  process.exitCode = Number.isInteger(result.exitCode) ? result.exitCode : 1;
}
if (require.main === module)
  main().catch(() => {
    process.stderr.write("Owned alive-grace command gate failed\n");
    process.exitCode = 1;
  });
module.exports = { createCommandBarrier, assertCleanupSafe, publish, main };
