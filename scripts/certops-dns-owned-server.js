"use strict";
/** Own the disposable Go DNS fixture from birth through a retained Linux pidfd.
 * Only fixed public fixture arguments enter the controller. No numeric signaling
 * or existing-listener adoption is permitted. Imports perform no native work. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
function nativeEnvironment() {
  return {
    PATH: process.env.PATH,
    ...(process.env.HOME ? { HOME: process.env.HOME } : {}),
    PYTHONUTF8: "1",
  };
}
function probePidfd() {
  if (process.platform !== "linux") return false;
  const result = spawnSync(
    "python3",
    [
      "-c",
      "import os,signal; h=os.pidfd_open(os.getpid(),0); signal.pidfd_send_signal(h,0); os.close(h)",
    ],
    { stdio: "ignore", timeout: 5000, env: nativeEnvironment() },
  );
  return !result.error && result.signal === null && result.status === 0;
}
const ARGS = Object.freeze([
  "-dns01",
  "127.0.0.1:18054",
  "-management",
  "127.0.0.1:18055",
  "-http01",
  "",
  "-https01",
  "",
  "-tlsalpn01",
  "",
  "-doh",
  "",
]);
function processIdentity(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8"),
    fields = raw
      .slice(raw.lastIndexOf(") ") + 2)
      .trim()
      .split(/\s+/);
  return {
    birth: fields[19],
    parentPid: Number(fields[1]),
    groupId: Number(fields[2]),
    sessionId: Number(fields[3]),
  };
}
function verifyReady(value, nonce, wrapperPid) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "kind",
      "nonce",
      "wrapperPid",
      "workerPid",
      "parentPid",
      "birth",
      "groupId",
      "sessionId",
      "pidfdPinnedBeforeExec",
    ].sort(),
  );
  assert.equal(value.kind, "certops-dns-server-pidfd-ready");
  assert.equal(value.nonce, nonce);
  assert.equal(value.wrapperPid, wrapperPid);
  assert.equal(value.parentPid, wrapperPid);
  assert.equal(value.pidfdPinnedBeforeExec, true);
  assert.match(value.birth, /^[0-9]+$/);
  for (const key of ["workerPid", "groupId", "sessionId"])
    assert.ok(Number.isSafeInteger(value[key]) && value[key] > 0);
  return true;
}
function verifyClosed(value, ready) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "kind",
      "nonce",
      "wrapperPid",
      "workerPid",
      "rootExitCode",
      "pidfdSignalUsed",
      "pidfdClosed",
      "workerWaited",
    ].sort(),
  );
  assert.equal(value.kind, "certops-dns-server-pidfd-closed");
  for (const key of ["nonce", "wrapperPid", "workerPid"])
    assert.equal(value[key], ready[key]);
  assert.equal(value.pidfdClosed, true);
  assert.equal(value.workerWaited, true);
  assert.equal(typeof value.pidfdSignalUsed, "boolean");
  assert.ok(Number.isSafeInteger(value.rootExitCode));
  return true;
}
async function until(read, label) {
  const started = performance.now();
  do {
    if (await read()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  } while (performance.now() - started < 10000);
  throw new Error(`Owned DNS server ${label} unproven`);
}
async function startOwnedDnsServer(register) {
  assert.equal(process.platform, "linux");
  assert.equal(typeof register, "function");
  const executable = (process.env.PATH || "")
    .split(path.delimiter)
    .map((dir) => path.join(dir, "pebble-challtestsrv"))
    .find((file) => {
      try {
        return fs.statSync(file).isFile();
      } catch {
        return false;
      }
    });
  assert.ok(executable, "Pinned native DNS fixture executable required");
  const actual = fs.realpathSync(executable),
    nonce = crypto.randomBytes(16).toString("hex");
  let child,
    ready,
    closed,
    wrapperClosed = false,
    failed = false,
    bytes = 0,
    buffer = "";
  const resource = {
    assertLive() {
      assert.ok(
        child && ready && !closed && !wrapperClosed && !failed,
        "Owned DNS process must remain live",
      );
      const identity = processIdentity(ready.workerPid);
      assert.equal(identity.birth, ready.birth);
      assert.equal(identity.parentPid, child.pid);
      assert.equal(fs.realpathSync(`/proc/${ready.workerPid}/exe`), actual);
      assert.deepEqual(
        fs
          .readFileSync(`/proc/${ready.workerPid}/cmdline`)
          .toString()
          .split("\0")
          .filter((_, index, array) => index < array.length - 1),
        [actual, ...ARGS],
      );
    },
    async stop() {
      if (child && !wrapperClosed) child.stdin.end(`stop:${nonce}\n`);
      await until(() => wrapperClosed, "controller close");
      assert.ok(
        !failed && ready && closed,
        "Owned DNS pidfd drainage receipt required",
      );
      verifyClosed(closed, ready);
      try {
        assert.notEqual(
          processIdentity(ready.workerPid).birth,
          ready.birth,
          "Original DNS process remains live",
        );
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
      }
    },
    assertCleanupSafe() {
      assert.ok(
        wrapperClosed && ready && closed && !failed,
        "Preserve unknown native DNS owner",
      );
      verifyClosed(closed, ready);
    },
  };
  register(resource);
  child = spawn(
    "python3",
    [
      path.join(__dirname, "certops-dns-owned-server.py"),
      actual,
      JSON.stringify(ARGS),
      nonce,
    ],
    { stdio: ["pipe", "pipe", "pipe"], env: nativeEnvironment() },
  );
  child.stdin.on("error", () => {
    failed = true;
  });
  child.once("error", () => {
    failed = true;
  });
  child.once("close", () => {
    wrapperClosed = true;
  });
  child.stderr.on("data", (chunk) => {
    bytes += chunk.length;
    if (bytes > 65536) failed = true;
  });
  child.stdout.on("data", (chunk) => {
    bytes += chunk.length;
    if (bytes > 65536) {
      failed = true;
      return;
    }
    buffer += chunk.toString("utf8");
    try {
      while (buffer.includes("\n")) {
        const at = buffer.indexOf("\n"),
          line = buffer.slice(0, at);
        buffer = buffer.slice(at + 1);
        const value = JSON.parse(line);
        if (value.kind === "certops-dns-server-pidfd-ready") {
          assert.ok(!ready);
          verifyReady(value, nonce, child.pid);
          assert.equal(processIdentity(value.workerPid).birth, value.birth);
          ready = value;
        } else {
          assert.ok(ready && !closed);
          verifyClosed(value, ready);
          closed = value;
        }
      }
    } catch {
      failed = true;
    }
  });
  try {
    await until(() => {
      assert.ok(!failed && !wrapperClosed);
      return !!ready;
    }, "pidfd before exec");
    child.stdin.write(`start:${nonce}\n`);
    await until(() => {
      try {
        resource.assertLive();
        return true;
      } catch {
        return false;
      }
    }, "exact native exec");
    return resource;
  } catch {
    throw new Error(
      "Owned DNS server launch incomplete; preserve registered owner",
    );
  }
}
module.exports = {
  probePidfd,
  ARGS,
  processIdentity,
  verifyReady,
  verifyClosed,
  startOwnedDnsServer,
};
