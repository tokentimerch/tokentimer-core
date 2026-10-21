/**
 * Qualification: retained ACME lease-loss command
 *
 * Attach to the actual production-launched command blocked before ACME exec, then retire
 * its agent through the public API. Production lease abort must terminate without
 * releasing the arm while certificate/key/TLS/DNS remain unchanged. Pin the root with a
 * Linux pidfd and independently verify birth, parent, group, Node executable, exact
 * wrapper argv and original arm/receipt identities; initial group contains only that
 * root. Never replace production launch or signal a numeric PID/PGID. Natural-success
 * drainage needs readable descriptor, empty group, unchanged public ownership files and
 * controller close with code 0. Emergency signaling is separately recorded and cannot
 * qualify genuine lease cancellation. Unknown descendants, lost receipts,
 * attachment/closure failures preserve durable AND in-memory cleanup authority. Parent
 * must observe its original agent ChildProcess close before DB/private cleanup. Benign
 * capability-free UID/GID 65534 Node 22 controls verify adapter drainage and lost
 * receipt refusal only: no native Node 24 certificate, agent, CA, service or network
 * execution is implied, nor atomic process-tree containment.
 */
// Shared execution, evidence and cleanup policy: docs/certops/e2e-qualification.md.
"use strict";

/** External observer for an actual production-launched, still-armed command.
 * A retained Linux pidfd is the only emergency signal target. This is not a
 * launcher, reaper, process-group signal API, or native qualification claim. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const active = new Set();

function validateRecord(value, expected, kind) {
  const keys =
    kind === "lease-pidfd-attached"
      ? [
          "kind",
          "token",
          "pid",
          "startTicks",
          "pidfdPinned",
          "initialGroupRootOnly",
        ]
      : [
          "kind",
          "token",
          "pid",
          "startTicks",
          "rootExited",
          "groupEmpty",
          "pidfdClosed",
          "pidfdSignalUsed",
        ];
  assert.deepEqual(
    Object.keys(value).sort(),
    keys.sort(),
    "Closed lease process receipt required",
  );
  assert.equal(value.kind, kind);
  assert.equal(value.token, expected.token);
  assert.equal(value.pid, expected.pid);
  assert.equal(value.startTicks, expected.startTicks);
  for (const key of keys.filter(
    (key) =>
      !["kind", "token", "pid", "startTicks", "pidfdSignalUsed"].includes(key),
  ))
    assert.equal(
      value[key],
      true,
      "Positive native ownership observation required",
    );
  if (kind === "lease-pidfd-closed")
    assert.equal(typeof value.pidfdSignalUsed, "boolean");
  return value;
}

function ownedFile(file) {
  const resolved = path.resolve(file);
  assert.equal(
    fs.realpathSync(resolved),
    resolved,
    "Canonical owned barrier path required",
  );
  const fd = fs.openSync(
    resolved,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    assert.ok(
      before.isFile() &&
        before.nlink === 1n &&
        before.ino > 0n &&
        before.size <= 8192n &&
        (before.mode & 0o777n) === 0o600n &&
        before.uid === BigInt(process.getuid()),
    );
    const bytes = Buffer.alloc(Number(before.size) + 1);
    const length = fs.readSync(fd, bytes, 0, bytes.length, 0);
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(resolved, { bigint: true });
    assert.equal(length, Number(before.size));
    for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"])
      assert.equal(
        after[key],
        before[key],
        "Owned barrier changed during read",
      );
    assert.ok(current.isFile() && !current.isSymbolicLink());
    assert.equal(current.dev, before.dev);
    assert.equal(current.ino, before.ino);
    return {
      path: resolved,
      dev: String(before.dev),
      ino: String(before.ino),
      sha256: crypto
        .createHash("sha256")
        .update(bytes.subarray(0, length))
        .digest("hex"),
    };
  } finally {
    fs.closeSync(fd);
  }
}

function assertCleanupSafe(root) {
  assert.equal(
    active.has(path.resolve(root)),
    false,
    "Preserve unresolved lease command ownership",
  );
}

function attach({
  proof,
  token,
  agent,
  barrierDirectory,
  ownedResources,
  waitUntil,
  commandWrapper = path.join(__dirname, "certops-acme-command-barrier.js"),
}) {
  assert.equal(process.platform, "linux");
  assert.equal(proof.token, token);
  assert.equal(proof.parentPid, agent.pid);
  assert.ok(Number.isSafeInteger(proof.pid) && proof.pid > 1);
  assert.equal(proof.processGroup, proof.pid);
  assert.match(proof.startTicks, /^[1-9][0-9]*$/);
  const root = path.resolve(barrierDirectory);
  assert.equal(fs.realpathSync(root), root);
  const rootIdentity = fs.lstatSync(root, { bigint: true });
  assert.ok(
    rootIdentity.isDirectory() &&
      !rootIdentity.isSymbolicLink() &&
      rootIdentity.ino > 0n,
  );
  assert.equal(active.has(root), false);
  active.add(root);
  let child = null,
    manifest = null,
    failure,
    attached,
    closedReceipt,
    closed = false,
    released = false,
    buffer = "";
  const expected = { ...proof, token };
  function fail() {
    failure = new Error(
      "Owned lease process observer failed; preserve fixture",
    );
  }
  async function awaitClosed(timeout) {
    await waitUntil(() => {
      if (failure) throw failure;
      return closed;
    }, timeout);
    assert.equal(child.exitCode, 0, "Actual lease observer close0 required");
    assert.equal(child.signalCode, null);
    assert.ok(
      attached && closedReceipt,
      "Both retained native receipts required",
    );
  }
  const resource = {
    hasOwnershipReceipt: () => !released,
    hasLiveResource: () => !!child && !closed,
    async waitForNativeExit() {
      await awaitClosed(90000);
      assert.equal(
        closedReceipt.pidfdSignalUsed,
        false,
        "Fixture emergency signal cannot qualify production lease cancellation",
      );
    },
    async stopAndDrain() {
      if (!child)
        throw new Error(
          "Unconfirmed lease process attachment; preserve fixture",
        );
      if (!closed && !closedReceipt && !child.stdin.destroyed)
        child.stdin.write(`stop:${token}\n`);
      await awaitClosed(10000);
    },
    release() {
      assert.ok(!failure && closed && attached && closedReceipt);
      assert.equal(child.exitCode, 0);
      assert.equal(child.signalCode, null);
      released = true;
      active.delete(root);
    },
    removeOwnedBarriersAndRelease() {
      assert.ok(!failure && closed && attached && closedReceipt);
      const currentRoot = fs.lstatSync(root, { bigint: true });
      assert.ok(currentRoot.isDirectory() && !currentRoot.isSymbolicLink());
      assert.equal(currentRoot.dev, rootIdentity.dev);
      assert.equal(currentRoot.ino, rootIdentity.ino);
      for (const original of [manifest.arm, manifest.receipt]) {
        const current = ownedFile(original.path);
        assert.ok(
          current.dev === original.dev &&
            current.ino === original.ino &&
            current.sha256 === original.sha256,
          "Preserve changed barrier ownership",
        );
        fs.unlinkSync(original.path);
      }
      resource.release();
    },
  };
  // Register before any observer launch or pipe operation. A throwing launch
  // cannot hide unresolved authority, even when the marker later disappears.
  ownedResources.push(resource);
  manifest = {
    token,
    pid: proof.pid,
    parentPid: proof.parentPid,
    processGroup: proof.processGroup,
    startTicks: proof.startTicks,
    executable: fs.realpathSync(process.execPath),
    argvHex: fs.readFileSync(`/proc/${proof.pid}/cmdline`).toString("hex"),
    arm: ownedFile(path.join(root, "armed.json")),
    receipt: ownedFile(path.join(root, "process.json")),
  };
  const argv = Buffer.from(manifest.argvHex, "hex")
    .toString("utf8")
    .split("\0");
  assert.ok(
    ["certops-acme-command-barrier.js", "certops-acme-signing-command.js"].some(
      (name) => commandWrapper === path.join(__dirname, name),
    ),
    "Fixed owned qualification command wrapper required",
  );
  assert.equal(argv[1], commandWrapper);
  assert.equal(argv[2], root);
  assert.equal(agent.exitCode, null);
  assert.equal(agent.signalCode, null);
  assert.ok(Buffer.byteLength(JSON.stringify(manifest)) <= 16383);
  child = spawn(
    "python3",
    [path.join(__dirname, "certops-acme-lease-pidfd.py")],
    {
      stdio: ["pipe", "pipe", "ignore"],
      env: { PATH: process.env.PATH, LANG: "C.UTF-8" },
    },
  );
  child.on("error", fail);
  child.stdin.on("error", fail);
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    try {
      buffer += chunk;
      assert.ok(Buffer.byteLength(buffer) <= 8192);
      while (buffer.includes("\n")) {
        const end = buffer.indexOf("\n");
        const value = JSON.parse(buffer.slice(0, end));
        buffer = buffer.slice(end + 1);
        if (!attached)
          attached = validateRecord(value, expected, "lease-pidfd-attached");
        else {
          assert.equal(closedReceipt, undefined);
          closedReceipt = validateRecord(value, expected, "lease-pidfd-closed");
        }
      }
    } catch {
      fail();
    }
  });
  child.on("close", () => {
    closed = true;
    if (buffer) fail();
  });
  child.stdin.write(`${JSON.stringify(manifest)}\n`);
  resource.ready = waitUntil(() => {
    if (failure || closed)
      throw failure || new Error("Lease observer closed before attachment");
    return !!attached;
  }, 10000);
  return resource;
}

module.exports = { attach, validateRecord, assertCleanupSafe };
