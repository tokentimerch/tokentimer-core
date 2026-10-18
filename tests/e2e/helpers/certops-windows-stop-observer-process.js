"use strict";
/** Starts the read-only stop observer with a private original-identity context.
 * There is deliberately no kill fallback: an uncertain observer preserves the
 * installed fixture. This module does not request an SCM operation itself. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { setTimeout: delay } = require("node:timers/promises");
const protocol = require("./certops-windows-stop-observer");
const active = new Set();
const PREFIX = ".retained-stop-observer-";
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function sameFile(file, original, bytes) {
  const now = fs.lstatSync(file, { bigint: true });
  assert.ok(
    now.isFile() &&
      !now.isSymbolicLink() &&
      now.dev === original.dev &&
      now.ino === original.ino &&
      now.size === BigInt(bytes.length),
    "Preserve changed stop observer file",
  );
  assert.ok(
    fs.readFileSync(file).equals(bytes),
    "Preserve changed stop observer bytes",
  );
}
function assertCleanupSafe(root) {
  const absolute = path.resolve(root);
  assert.ok(
    ![...active].some((entry) => entry.root === absolute),
    "Preserve unresolved retained stop observation",
  );
  assert.ok(
    !fs.readdirSync(absolute).some((entry) => entry.startsWith(PREFIX)),
    "Preserve durable retained stop observation",
  );
}
function identity(value) {
  assert.ok(value && typeof value === "object");
  assert.deepEqual(
    Object.keys(value).sort(),
    ["pid", "parentPid", "createdAt", "executable", "commandSha256"].sort(),
  );
  for (const name of ["pid", "parentPid"])
    assert.ok(
      Number.isSafeInteger(value[name]) &&
        value[name] > 0 &&
        value[name] <= 0xffffffff,
    );
  assert.match(
    value.createdAt,
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{7}Z$/,
  );
  assert.ok(
    path.win32.isAbsolute(value.executable) &&
      !/[\x00-\x1f\x7f]/.test(value.executable),
  );
  assert.match(value.commandSha256, /^[a-f0-9]{64}$/);
}
async function startStopObservation({
  workDir,
  powershell,
  ownerIdentity,
  hostIdentity,
  nodeIdentity,
  commandRoots,
  onCreated,
}) {
  assert.equal(process.platform, "win32");
  identity(ownerIdentity);
  identity(hostIdentity);
  identity(nodeIdentity);
  assert.equal(nodeIdentity.parentPid, hostIdentity.pid);
  assert.equal(ownerIdentity.pid, process.pid);
  assert.ok(path.win32.isAbsolute(powershell));
  assert.ok(
    Array.isArray(commandRoots) &&
      commandRoots.length >= 1 &&
      commandRoots.length <= 8,
  );
  for (const value of commandRoots)
    assert.ok(
      typeof value === "string" &&
        path.win32.isAbsolute(value) &&
        value.length <= 4096 &&
        !/[\x00-\x1f\x7f]/.test(value),
    );
  const root = path.resolve(workDir),
    rootStat = fs.lstatSync(root, { bigint: true });
  assert.equal(fs.realpathSync.native(root), root);
  assert.ok(
    rootStat.isDirectory() && !rootStat.isSymbolicLink() && rootStat.ino > 0n,
  );
  const token = crypto.randomBytes(32).toString("hex");
  const directory = path.join(root, PREFIX + token);
  fs.mkdirSync(directory, { mode: 0o700 });
  const directoryStat = fs.lstatSync(directory, { bigint: true });
  const registration = { root, directory };
  active.add(registration);
  require("../../../packages/agent/src/platform").applyRestrictivePermissions(
    directory,
    { kind: "directory" },
  );
  const contextFile = path.join(directory, "context.json"),
    readyFile = path.join(directory, "ready.json");
  const bytes = Buffer.from(
    JSON.stringify({
      schemaVersion: 1,
      token,
      ownerExecutable: ownerIdentity.executable,
      ownerCreatedAt: ownerIdentity.createdAt,
      identity: hostIdentity,
      nodeIdentity,
      commandRoots,
      maxWaitMs: 120000,
    }),
  );
  fs.writeFileSync(contextFile, bytes, { flag: "wx", mode: 0o600 });
  require("../../../packages/agent/src/platform").applyRestrictivePermissions(
    contextFile,
    { kind: "file" },
  );
  const contextStat = fs.lstatSync(contextFile, { bigint: true });
  let closed = false,
    code,
    output = Buffer.alloc(0),
    outputInvalid = false,
    ready,
    readyBytes,
    readyStat;
  const nativeEnv = { ...process.env };
  for (const key of Object.keys(nativeEnv))
    if (key.toLowerCase() === "psmodulepath") delete nativeEnv[key];
  const child = spawn(
    powershell,
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      path.join(__dirname, "certops-windows-stop-observer.ps1"),
      "-ContextFile",
      contextFile,
      "-ContextSha256",
      sha(bytes),
      "-OwnerProcessId",
      String(process.pid),
      "-ReadyFile",
      readyFile,
    ],
    { windowsHide: true, env: nativeEnv, stdio: ["ignore", "pipe", "pipe"] },
  );
  child.stdout.on("data", (chunk) => {
    if (output.length + chunk.length > 16384) outputInvalid = true;
    else output = Buffer.concat([output, chunk]);
  });
  let stderrBytes = 0;
  child.stderr.on("data", (chunk) => {
    stderrBytes += chunk.length;
    if (stderrBytes > 65536) outputInvalid = true;
  });
  child.on("error", () => {
    outputInvalid = true;
  });
  child.once("close", (exitCode) => {
    code = exitCode;
    closed = true;
  });
  const originalDirectory = () => {
    const currentRoot = fs.lstatSync(root, { bigint: true }),
      current = fs.lstatSync(directory, { bigint: true });
    assert.ok(
      currentRoot.dev === rootStat.dev &&
        currentRoot.ino === rootStat.ino &&
        !currentRoot.isSymbolicLink(),
    );
    assert.ok(
      current.isDirectory() &&
        !current.isSymbolicLink() &&
        current.dev === directoryStat.dev &&
        current.ino === directoryStat.ino,
    );
    sameFile(contextFile, contextStat, bytes);
  };
  const resource = {
    hasLiveChild: () => !closed,
    hasOwnershipReceipt: () => active.has(registration),
    async waitForClose() {
      const deadline = performance.now() + 130000;
      while (!closed && performance.now() < deadline) await delay(50);
      assert.equal(closed, true, "Preserve live read-only stop observer");
    },
    async waitForCompletion() {
      await resource.waitForClose();
      assert.equal(code, 0, "Read-only stop observer did not complete");
      assert.equal(
        outputInvalid,
        false,
        "Bounded stop observer output required",
      );
      const result = JSON.parse(output.toString("utf8"));
      protocol.verifyResult(result, {
        token,
        ready,
        observerPid: child.pid,
        observerClosed: closed,
      });
      originalDirectory();
      sameFile(readyFile, readyStat, readyBytes);
      fs.unlinkSync(readyFile);
      fs.unlinkSync(contextFile);
      fs.rmdirSync(directory);
      active.delete(registration);
      return result;
    },
  };
  // Caller records this exact retained ChildProcess resource before any
  // asynchronous startup gate can throw. Waiting for close never clears an
  // unsuccessful observation's ownership guard.
  if (onCreated) onCreated(resource);
  // Registration survives every thrown startup error, including a disappeared
  // pathname. Cleanup authorization never depends on pathname absence alone.
  const deadline = performance.now() + 30000;
  while (performance.now() < deadline) {
    originalDirectory();
    if (fs.existsSync(readyFile)) {
      const stat = fs.lstatSync(readyFile, { bigint: true });
      assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 4096n);
      if (stat.size === 0n) {
        await delay(25);
        continue;
      }
      const current = fs.readFileSync(readyFile);
      // The native writer flushes and closes its exclusive create. A partial
      // read may precede close, so only parse incompleteness is retried.
      let parsed;
      try {
        parsed = JSON.parse(current.toString("utf8"));
      } catch {
        await delay(25);
        continue;
      }
      protocol.verifyReady(parsed, { token, observerPid: child.pid });
      ready = parsed;
      readyBytes = current;
      readyStat = stat;
      return resource;
    }
    assert.equal(
      closed,
      false,
      "Observer closed before retaining native handles",
    );
    await delay(25);
  }
  throw new Error(
    "Stop observer readiness timeout; preserve installed fixture",
  );
}
module.exports = { startStopObservation, assertCleanupSafe };
