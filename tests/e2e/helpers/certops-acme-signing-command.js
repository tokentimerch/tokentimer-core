"use strict";
/** Qualification-only transparent ACME command gate. Production launches this
 * exact command profile and owns its detached process group. The immutable arm
 * remains for the retained pidfd observer; only a separate exact go token lets
 * the real client execute. No signing payload, CA output or clock is changed. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
function readOwnedBytes(file, maximum, original) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() &&
        before.nlink === 1n &&
        before.dev === original.dev &&
        before.ino === original.ino &&
        before.size > 0n &&
        before.size <= BigInt(maximum),
    );
    const bytes = Buffer.alloc(maximum + 1);
    const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    const after = fs.fstatSync(fd, { bigint: true }),
      current = fs.lstatSync(file, { bigint: true });
    assert.ok(
      length === Number(before.size) &&
        ["dev", "ino", "size", "mtimeNs", "ctimeNs"].every(
          (key) => before[key] === after[key],
        ) &&
        current.isFile() &&
        !current.isSymbolicLink() &&
        current.dev === before.dev &&
        current.ino === before.ino,
    );
    return bytes.subarray(0, length);
  } finally {
    fs.closeSync(fd);
  }
}
const [directory, binary, ...args] = process.argv.slice(2);
assert.equal(process.platform, "linux");
assert.ok(path.isAbsolute(directory) && binary);
const originalRoot = fs.lstatSync(directory, { bigint: true });
assert.ok(originalRoot.isDirectory() && !originalRoot.isSymbolicLink());
assert.equal(fs.realpathSync(directory), directory);
const arm = path.join(directory, "armed.json");
function execute() {
  const child = spawn(binary, args, { stdio: "inherit", env: process.env });
  child.once("error", () => {
    process.exitCode = 1;
  });
  child.once("close", (code, signal) => {
    process.exitCode = signal ? 1 : code;
  });
}
if (!fs.existsSync(arm)) execute();
else {
  const armIdentity = fs.lstatSync(arm, { bigint: true });
  const armBytes = readOwnedBytes(arm, 1024, armIdentity);
  const value = JSON.parse(armBytes);
  assert.deepEqual(Object.keys(value), ["token"]);
  assert.match(value.token, /^[a-f0-9-]{36}$/);
  const raw = fs.readFileSync("/proc/self/stat", "utf8");
  const native = raw.slice(raw.lastIndexOf(") ") + 2).split(/\s+/);
  fs.writeFileSync(
    path.join(directory, "process.json"),
    JSON.stringify({
      token: value.token,
      pid: process.pid,
      parentPid: process.ppid,
      binary,
      processGroup: Number(native[2]),
      startTicks: native[19],
    }),
    { flag: "wx", mode: 0o600 },
  );
  const deadline = setTimeout(() => {
    throw Error("Owned signing command gate exceeded deadline");
  }, 90000);
  const timer = setInterval(() => {
    const current = fs.lstatSync(directory, { bigint: true });
    assert.ok(
      current.dev === originalRoot.dev &&
        current.ino === originalRoot.ino &&
        !current.isSymbolicLink(),
    );
    assert.ok(readOwnedBytes(arm, 1024, armIdentity).equals(armBytes));
    const go = path.join(directory, "go");
    if (!fs.existsSync(go)) return;
    const identity = fs.lstatSync(go, { bigint: true });
    assert.equal(readOwnedBytes(go, 36, identity).toString(), value.token);
    clearInterval(timer);
    clearTimeout(deadline);
    execute();
  }, 25);
}
