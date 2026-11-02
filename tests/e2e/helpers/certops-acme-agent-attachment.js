"use strict";
/** Narrow exact-idle-agent restart ownership; not an atomic tree launcher. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { readOwnedBytes } = require("./certops-acme-native-adoption");
const active = new Set();
function assertCleanupSafe(root) {
  assert.equal(
    active.has(path.resolve(root)),
    false,
    "Preserve unresolved original agent ownership",
  );
}
function validateOriginalBirth(actual, expected) {
  assert.match(actual, /^[1-9][0-9]*$/);
  if (expected !== undefined) {
    assert.match(expected, /^[1-9][0-9]*$/);
    assert.equal(actual, expected, "Original native process birth changed");
  }
  return actual;
}
function validateReceipt(value, expected, closed) {
  const flags = closed
    ? ["rootExited", "noChildAfterStop", "pidfdClosed", "explicitRestartStop"]
    : ["pidfdPinned", "noChildBeforeStop"];
  assert.deepEqual(
    Object.keys(value).sort(),
    ["kind", "token", "pid", "startTicks", ...flags].sort(),
  );
  assert.equal(
    value.kind,
    closed ? "agent-pidfd-closed" : "agent-pidfd-attached",
  );
  for (const key of ["token", "pid", "startTicks"])
    assert.equal(value[key], expected[key]);
  for (const flag of flags) assert.equal(value[flag], true);
  return value;
}
async function attachIdleAgent({
  agent,
  entry,
  workDir,
  resources,
  waitUntil,
  isAgentClosed,
  expectedStartTicks,
}) {
  assert.equal(process.platform, "linux");
  assert.ok(agent && agent.exitCode === null && agent.signalCode === null);
  const pid = agent.pid;
  assert.ok(Number.isSafeInteger(pid) && pid > 1 && Array.isArray(resources));
  const root = fs.realpathSync(workDir),
    token = crypto.randomBytes(16).toString("hex");
  assert.equal(root, path.resolve(workDir));
  const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8"),
    fields = raw
      .slice(raw.lastIndexOf(") ") + 2)
      .trim()
      .split(/\s+/);
  assert.equal(Number(fields[1]), process.pid);
  validateOriginalBirth(fields[19], expectedStartTicks);
  const executable = fs.realpathSync(process.execPath),
    argv = fs.readFileSync(`/proc/${pid}/cmdline`);
  assert.equal(fs.readlinkSync(`/proc/${pid}/exe`), executable);
  assert.ok(
    argv.equals(Buffer.from([process.execPath, entry, ""].join("\0"))),
    "Exact original native agent argv required",
  );
  const expected = {
    pid,
    parentPid: process.pid,
    startTicks: fields[19],
    executable,
    argvHex: argv.toString("hex"),
    token,
  };
  assertCleanupSafe(root);
  active.add(root);
  const marker = path.join(root, ".native-certificate-result-restart.guard"),
    markerBytes = Buffer.from(token);
  let child = null,
    markerIdentity = null,
    failure,
    attached,
    receipt,
    closed = false,
    released = false,
    stopping = false,
    buffer = "";
  const resource = {
    hasOwnershipReceipt: () => !released || fs.existsSync(marker),
    hasLiveResource: () => !!child && !closed,
    async stopAndDrain() {
      assert.ok(child, "Original agent attachment unknown");
      if (!closed && !stopping && !child.stdin.destroyed) {
        stopping = true;
        child.stdin.write(`stop:${token}\n`);
      }
      await waitUntil(() => {
        if (failure) throw failure;
        return closed;
      }, 40000);
      assert.equal(child.exitCode, 0);
      assert.equal(child.signalCode, null);
      await waitUntil(() => isAgentClosed(), 5000);
      assert.ok(
        attached && receipt && isAgentClosed(),
        "Both retained receipts and actual agent close required",
      );
    },
    release() {
      assert.ok(!failure && attached && receipt && closed && isAgentClosed());
      const current = readOwnedBytes(marker, 64, markerIdentity);
      assert.ok(current.equals(markerBytes));
      fs.unlinkSync(marker);
      released = true;
      active.delete(root);
    },
  };
  resources.push(resource);
  fs.writeFileSync(marker, markerBytes, { flag: "wx", mode: 0o600 });
  markerIdentity = fs.lstatSync(marker, { bigint: true });
  const fail = () => {
    failure = new Error(
      "Owned agent pidfd observation failed; preserve fixture",
    );
  };
  child = spawn(
    "python3",
    [path.join(__dirname, "certops-acme-agent-pidfd.py")],
    {
      stdio: ["pipe", "pipe", "ignore"],
      env: { PATH: process.env.PATH, PYTHONUTF8: "1" },
    },
  );
  child.once("error", fail);
  child.once("close", () => {
    closed = true;
  });
  child.stdin.on("error", fail);
  child.stdout.on("data", (bytes) => {
    buffer += bytes.toString("utf8");
    if (buffer.length > 8192) {
      fail();
      return;
    }
    let index;
    while ((index = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, index);
      buffer = buffer.slice(index + 1);
      try {
        const value = JSON.parse(line);
        if (!attached) attached = validateReceipt(value, expected, false);
        else {
          assert.equal(receipt, undefined);
          receipt = validateReceipt(value, expected, true);
        }
      } catch {
        fail();
      }
    }
  });
  child.stdin.write(JSON.stringify(expected) + "\n");
  await waitUntil(() => {
    if (failure) throw failure;
    assert.equal(closed, false);
    return attached;
  }, 10000);
  return resource;
}
module.exports = {
  attachIdleAgent,
  assertCleanupSafe,
  validateReceipt,
  validateOriginalBirth,
};
