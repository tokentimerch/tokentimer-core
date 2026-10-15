"use strict";
/** Real Linux runner ownership for the ACME journey. The unmodified production
 * CLI uses its default minute cron; this observer never invokes a scheduler.
 * A forked child is pinned by pidfd before exec; only that retained handle
 * receives SIGTERM. The original wrapper owns its private process group.
 * Unknown descendants, birth changes, missing close or failed drainage preserve
 * the ownership marker and block the parent's database/private-file cleanup. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { performance } = require("node:perf_hooks");
const PREFIX = ".preserve-acme-background-worker-";
const active = new Set();
function environment(input, nonce) {
  assert.match(nonce, /^[a-f0-9]{32}$/);
  const result = {};
  for (const key of [
    "PATH",
    "HOME",
    "TMPDIR",
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "DB_SSL",
    "PGSSLROOTCERT",
    "NODE_EXTRA_CA_CERTS",
    "CERTOPS_SIGNING_ENCRYPTION_KEY",
    "CERTOPS_REGISTRATION_ENCRYPTION_KEY",
  ])
    if (input[key] !== undefined) result[key] = input[key];
  for (const key of ["DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD"])
    assert.ok(typeof result[key] === "string" && result[key]);
  for (const key of [
    "CERTOPS_SIGNING_ENCRYPTION_KEY",
    "CERTOPS_REGISTRATION_ENCRYPTION_KEY",
  ])
    assert.match(result[key], /^[a-f0-9]{64}$/i);
  Object.assign(result, {
    NODE_ENV: "production",
    CERTOPS_ENABLED: "true",
    WORKER_EXIT_ON_ERROR: "true",
    PGAPPNAME: `certops-acme-worker-${nonce}`,
  });
  // No WORKER_* schedule/run-on-start override or unrelated secret is inherited.
  return result;
}
function observeRecord(state, value, elapsedMs) {
  assert.ok(value && typeof value === "object");
  if (value.level === "error") state.failed = true;
  if (value.message === "worker-runner-worker-started") {
    assert.equal(value.worker, "certops");
    assert.equal(value.scheduleMode, "cron");
    assert.equal(value.cronExpression, "*/1 * * * *");
    assert.equal(value.runOnStart, false);
    state.starts++;
  }
  if (
    ["worker-runner-job-start", "worker-runner-job-finish"].includes(
      value.message,
    )
  ) {
    assert.equal(value.worker, "certops");
    assert.equal(value.trigger, "cron");
    if (value.message.endsWith("-start"))
      state.tickElapsedMs.push(Math.round(elapsedMs));
    else state.finishes++;
  }
  if (value.message === "CertOps maintenance worker finished") {
    assert.ok(
      value.renewalScheduler &&
        Array.isArray(value.renewalScheduler.errors) &&
        !value.renewalScheduler.errors.length,
    );
    assert.ok(
      Number.isSafeInteger(value.renewalScheduler.created) &&
        value.renewalScheduler.created >= 0 &&
        value.renewalScheduler.created <= 1,
    );
    state.created += value.renewalScheduler.created;
    state.summaries++;
  }
  if (value.message === "worker-runner-stopping") {
    assert.equal(value.signal, "SIGTERM");
    state.stops++;
  }
}
function validateLifecycle(value) {
  assert.deepEqual(
    Object.keys(value).sort(),
    [
      "failed",
      "starts",
      "tickElapsedMs",
      "finishes",
      "summaries",
      "created",
      "stops",
      "exitCode",
      "groupDrained",
      "closed",
      "pidfdPinnedBeforeExec",
      "pidfdSignalUsed",
      "pidfdClosed",
      "workerWaited",
    ].sort(),
  );
  assert.equal(value.failed, false);
  assert.equal(value.starts, 1);
  assert.equal(value.created, 2);
  assert.equal(value.stops, 1);
  assert.equal(value.exitCode, 0);
  assert.equal(value.groupDrained, true);
  assert.equal(value.closed, true);
  for (const field of [
    "pidfdPinnedBeforeExec",
    "pidfdSignalUsed",
    "pidfdClosed",
    "workerWaited",
  ])
    assert.equal(value[field], true);
  assert.ok(
    Array.isArray(value.tickElapsedMs) &&
      value.tickElapsedMs.length >= 2 &&
      value.tickElapsedMs.length <= 8,
  );
  assert.ok(
    value.tickElapsedMs.every(
      (x) => Number.isSafeInteger(x) && x >= 0 && x <= 480000,
    ),
  );
  for (let i = 1; i < value.tickElapsedMs.length; i++)
    assert.ok(
      value.tickElapsedMs[i] - value.tickElapsedMs[i - 1] >= 59000,
      "Actual default cron ticks cannot be compressed",
    );
  assert.ok(value.tickElapsedMs[0] <= 120000);
  assert.equal(value.finishes, value.tickElapsedMs.length);
  assert.equal(value.summaries, value.finishes);
  return true;
}
function identity(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0);
  const raw = fs.readFileSync(`/proc/${pid}/stat`, "utf8"),
    rest = raw
      .slice(raw.lastIndexOf(") ") + 2)
      .trim()
      .split(/\s+/);
  assert.equal(Number(raw.slice(0, raw.indexOf(" "))), pid);
  return {
    pid,
    parent: Number(rest[1]),
    group: Number(rest[2]),
    session: Number(rest[3]),
    birth: rest[19],
    executable: fs.realpathSync(`/proc/${pid}/exe`),
  };
}
function groupMembers(group) {
  const members = [];
  for (const name of fs.readdirSync("/proc"))
    if (/^[1-9][0-9]*$/.test(name)) {
      let raw;
      try {
        raw = fs.readFileSync(`/proc/${name}/stat`, "utf8");
      } catch (error) {
        if (["ENOENT", "ESRCH"].includes(error.code)) continue;
        throw error;
      }
      const parts = raw
        .slice(raw.lastIndexOf(") ") + 2)
        .trim()
        .split(/\s+/);
      if (Number(parts[2]) === group) members.push(Number(name));
    }
  return members.sort((a, b) => a - b);
}
function markerIdentity(file) {
  const st = fs.lstatSync(file, { bigint: true });
  assert.ok(st.isFile() && !st.isSymbolicLink());
  return `${st.dev}:${st.ino}`;
}
function assertCleanupSafe(root) {
  assert.ok(
    ![...active].some((item) => item.root === root),
    "Preserve live or unresolved background worker",
  );
  assert.ok(
    !fs.readdirSync(root).some((name) => name.startsWith(PREFIX)),
    "Preserve background worker ownership receipt",
  );
}
async function startOwnedRunner({
  root,
  repoRoot,
  until,
  input = process.env,
  onCreated,
}) {
  assert.equal(process.platform, "linux");
  assert.equal(fs.realpathSync(root), root);
  assert.equal(
    fs.existsSync(path.join(repoRoot, ".env")),
    false,
    "Default worker qualification requires an env-file-free disposable checkout",
  );
  const nonce = crypto.randomBytes(16).toString("hex"),
    marker = path.join(root, PREFIX + nonce + ".json"),
    bytes = JSON.stringify({ schemaVersion: 1, nonce });
  fs.writeFileSync(marker, bytes, { flag: "wx", mode: 0o600 });
  const markerId = markerIdentity(marker);
  const rootStat = fs.statSync(root, { bigint: true }),
    rootId = `${rootStat.dev}:${rootStat.ino}`;
  const state = {
    failed: false,
    starts: 0,
    tickElapsedMs: [],
    finishes: 0,
    summaries: 0,
    created: 0,
    stops: 0,
    exitCode: null,
    groupDrained: false,
    closed: false,
    pidfdPinnedBeforeExec: false,
    pidfdSignalUsed: false,
    pidfdClosed: false,
    workerWaited: false,
  };
  const entry = { root };
  active.add(entry);
  let child,
    original,
    workerIdentity,
    readyReceipt,
    closedReceipt,
    released = false,
    total = 0;
  const buffers = { stdout: "", stderr: "" },
    start = performance.now();
  const owned = () => {
    const st = fs.lstatSync(root, { bigint: true });
    assert.ok(
      st.isDirectory() &&
        !st.isSymbolicLink() &&
        `${st.dev}:${st.ino}` === rootId,
    );
    assert.equal(markerIdentity(marker), markerId);
    assert.ok(fs.readFileSync(marker, "utf8") === bytes);
  };
  const check = () => {
    owned();
    assert.equal(
      state.failed,
      false,
      "Actual background worker observer failed",
    );
    assert.equal(state.closed, false, "Actual background worker exited early");
    assert.deepEqual(identity(child.pid), original);
    assert.deepEqual(identity(workerIdentity.pid), workerIdentity);
  };
  const stopAndDrain = async () => {
    if (released) return { ...state, tickElapsedMs: [...state.tickElapsedMs] };
    owned();
    if (child && !state.closed) {
      assert.deepEqual(identity(child.pid), original);
      assert.deepEqual(
        groupMembers(child.pid),
        [child.pid, workerIdentity.pid].sort((a, b) => a - b),
        "Unexpected descendants preserve owned worker group",
      );
      assert.deepEqual(identity(workerIdentity.pid), workerIdentity);
      child.stdin.write(`stop:${nonce}\n`);
    }
    if (child) {
      await until(() => state.closed, 40000);
      assert.deepEqual(groupMembers(child.pid), []);
    }
    if (child) {
      assert.ok(closedReceipt);
      assert.equal(closedReceipt.pidfdClosed, true);
      assert.equal(closedReceipt.workerWaited, true);
    }
    state.groupDrained = true;
    owned();
    fs.unlinkSync(marker);
    active.delete(entry);
    released = true;
    return { ...state, tickElapsedMs: [...state.tickElapsedMs] };
  };
  const resource = {
    check,
    stopAndDrain,
    hasOwnershipReceipt: () => !released,
    getState: () => ({ ...state, tickElapsedMs: [...state.tickElapsedMs] }),
  };
  if (onCreated) onCreated(resource);
  try {
    child = spawn(
      "python3",
      [
        path.join(__dirname, "certops-acme-background-pidfd.py"),
        process.execPath,
        path.join(repoRoot, "apps/worker/src/runner.js"),
        nonce,
      ],
      {
        cwd: repoRoot,
        env: environment(input, nonce),
        detached: true,
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    child.once("error", () => {
      state.failed = true;
    });
    child.stdin.on("error", () => {
      state.failed = true;
    });
    for (const name of ["stdout", "stderr"])
      child[name].on("data", (chunk) => {
        try {
          total += chunk.length;
          assert.ok(total <= 4 * 1024 * 1024);
          buffers[name] += chunk.toString("utf8");
          assert.ok(buffers[name].length <= 131072);
          let index;
          while ((index = buffers[name].indexOf("\n")) >= 0) {
            const line = buffers[name].slice(0, index).trim();
            buffers[name] = buffers[name].slice(index + 1);
            assert.ok(index <= 65536);
            if (
              !line ||
              line ===
                "[env] no .env found; using local development defaults (see .env.example)"
            )
              continue;
            const value = JSON.parse(line);
            if (value.kind === "certops-acme-worker-pidfd-ready") {
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
              assert.equal(value.nonce, nonce);
              assert.equal(value.wrapperPid, child.pid);
              assert.equal(value.parentPid, child.pid);
              assert.equal(value.groupId, child.pid);
              assert.equal(value.sessionId, child.pid);
              assert.equal(value.pidfdPinnedBeforeExec, true);
              assert.equal(readyReceipt, undefined);
              readyReceipt = value;
              state.pidfdPinnedBeforeExec = value.pidfdPinnedBeforeExec;
            } else if (value.kind === "certops-acme-worker-pidfd-closed") {
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
              assert.equal(value.nonce, nonce);
              assert.equal(value.wrapperPid, child.pid);
              assert.equal(value.workerPid, readyReceipt.workerPid);
              assert.equal(value.pidfdClosed, true);
              assert.equal(value.workerWaited, true);
              closedReceipt = value;
              for (const key of [
                "pidfdSignalUsed",
                "pidfdClosed",
                "workerWaited",
              ])
                state[key] = value[key];
            } else observeRecord(state, value, performance.now() - start);
          }
        } catch {
          state.failed = true;
        }
      });
    child.once("close", (code) => {
      if (Object.values(buffers).some((value) => value.trim()))
        state.failed = true;
      if (
        !closedReceipt ||
        code !== 0 ||
        closedReceipt.rootExitCode !== 0 ||
        closedReceipt.pidfdSignalUsed !== true
      )
        state.failed = true;
      state.exitCode = code;
      state.closed = true;
    });
    assert.ok(child.pid);
    original = identity(child.pid);
    assert.equal(original.parent, process.pid);
    assert.equal(original.group, child.pid);
    assert.equal(original.session, child.pid);
    await until(() => {
      assert.equal(state.failed, false);
      return readyReceipt;
    }, 30000);
    workerIdentity = identity(readyReceipt.workerPid);
    assert.equal(workerIdentity.parent, child.pid);
    assert.equal(workerIdentity.group, child.pid);
    assert.equal(workerIdentity.session, child.pid);
    assert.equal(workerIdentity.birth, readyReceipt.birth);
    child.stdin.write(`start:${nonce}\n`);
    await until(() => {
      assert.equal(state.failed, false);
      return state.starts === 1;
    }, 30000);
    workerIdentity = identity(readyReceipt.workerPid);
    assert.equal(workerIdentity.birth, readyReceipt.birth);
    assert.equal(workerIdentity.executable, fs.realpathSync(process.execPath));
    check();
    return resource;
  } catch (error) {
    try {
      await stopAndDrain();
    } catch {
      /* Sticky ownership blocks parent cleanup. */
    }
    throw error;
  }
}
module.exports = {
  environment,
  observeRecord,
  validateLifecycle,
  assertCleanupSafe,
  startOwnedRunner,
};
