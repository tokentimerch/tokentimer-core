"use strict";
/** Owned real runner child and bounded public lifecycle observations. Native
 * process checks execute only from the explicit domain qualifier. No PID-only
 * kill is attempted: failed graceful/native drainage preserves the fixture. */
const assert = require("node:assert/strict"),
  fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto"),
  { spawn } = require("node:child_process"),
  { pathToFileURL } = require("node:url");
const platform = require("../../../packages/agent/src/platform");
const digest = (file) =>
  crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
function runnerEnvironment(input, nonce) {
  assert.match(nonce, /^[a-f0-9]{32}$/);
  const env = {};
  for (const key of [
    "PATH",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "DB_HOST",
    "DB_PORT",
    "DB_USER",
    "DB_PASSWORD",
    "DB_NAME",
    "CERTOPS_SIGNING_ENCRYPTION_KEY",
    "CERTOPS_REGISTRATION_ENCRYPTION_KEY",
    "NODE_EXTRA_CA_CERTS",
  ])
    if (input[key] !== undefined) env[key] = input[key];
  for (const key of ["DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME"])
    assert.ok(typeof env[key] === "string" && env[key].length);
  assert.match(env.CERTOPS_SIGNING_ENCRYPTION_KEY, /^[a-f0-9]{64}$/i);
  assert.match(env.CERTOPS_REGISTRATION_ENCRYPTION_KEY, /^[a-f0-9]{64}$/i);
  Object.assign(env, {
    NODE_ENV: "production",
    CERTOPS_ENABLED: "true",
    WORKER_CERTOPS_CRON: "interval",
    WORKER_EXIT_ON_ERROR: "true",
    CERTOPS_WORKER_OWNERSHIP_NONCE: nonce,
    PGAPPNAME: `certops-background-${nonce}`,
  });
  return env;
}
function observeRecord(state, value, elapsedMs) {
  if (!value || typeof value !== "object") return;
  if (value.level === "error") {
    state.failed = true;
    return;
  }
  if (value.message === "worker-runner-worker-started") {
    assert.equal(value.worker, "certops");
    assert.equal(value.scheduleMode, "interval");
    assert.equal(value.intervalMs, 60000);
    assert.equal(value.runOnStart, false);
    state.starts++;
  }
  if (value.message === "worker-runner-job-start") {
    assert.equal(value.worker, "certops");
    assert.equal(value.trigger, "interval");
    state.ticks++;
    state.firstTickElapsedMs ??= Math.floor(elapsedMs);
  }
  if (value.message === "worker-runner-job-finish") {
    assert.equal(value.worker, "certops");
    assert.equal(value.trigger, "interval");
    state.finishes++;
  }
  if (value.message === "CertOps maintenance worker finished") {
    const summary = value.renewalScheduler;
    assert.ok(summary && typeof summary === "object");
    assert.ok(
      Number.isSafeInteger(summary.created) &&
        summary.created >= 0 &&
        summary.created <= 2,
    );
    assert.ok(Array.isArray(summary.errors) && summary.errors.length === 0);
    state.created += summary.created;
    state.summaries++;
  }
  if (value.message === "worker-runner-stopping") {
    assert.equal(value.signal, "SIGTERM");
    state.stops++;
  }
}
function validateLifecycle(state) {
  assert.ok(state && typeof state === "object" && !Array.isArray(state));
  const fields = [
    "failed",
    "starts",
    "ticks",
    "finishes",
    "summaries",
    "created",
    "stops",
    "forwarded",
    "firstTickElapsedMs",
    "exitCode",
    "nativeDrained",
    "bridgeReady",
  ];
  assert.equal(Object.keys(state).length, fields.length);
  assert.ok(Object.keys(state).every((key) => fields.includes(key)));
  for (const key of [
    "starts",
    "ticks",
    "finishes",
    "summaries",
    "created",
    "stops",
    "firstTickElapsedMs",
    "exitCode",
  ])
    assert.ok(Number.isSafeInteger(state[key]));
  assert.equal(state.bridgeReady, true);
  assert.equal(state.failed, false);
  assert.equal(state.starts, 1);
  assert.ok(state.ticks >= 2 && state.ticks <= 20);
  assert.ok(state.finishes >= 2 && state.finishes <= state.ticks);
  assert.equal(state.summaries, state.finishes);
  assert.equal(state.created, 2);
  assert.equal(state.stops, 1);
  assert.equal(state.forwarded, true);
  assert.ok(
    state.firstTickElapsedMs >= 60000 && state.firstTickElapsedMs <= 180000,
  );
  assert.equal(state.exitCode, 0);
  assert.equal(state.nativeDrained, true);
  return true;
}
function createOwnedRunner({
  workDir,
  ps,
  until,
  ownedPhaseObservers,
  env = process.env,
}) {
  assert.equal(process.platform, "win32");
  assert.ok(Array.isArray(ownedPhaseObservers));
  assert.equal(typeof until, "function");
  const root = path.resolve(__dirname, "../../.."),
    nonce = crypto.randomBytes(16).toString("hex"),
    directory = fs.mkdtempSync(path.join(workDir, "background-worker-"));
  platform.applyRestrictivePermissions(directory, { kind: "directory" });
  const directoryId = fs.statSync(directory, { bigint: true }).ino,
    bridge = path.join(directory, "stop-bridge.mjs"),
    bridgeSource = path.join(__dirname, "certops-adcs-worker-stop-bridge.mjs"),
    controller = path.join(__dirname, "certops-adcs-worker-controller.cjs"),
    wrapper = path.join(__dirname, "certops-adcs-worker-job.ps1");
  fs.copyFileSync(bridgeSource, bridge, fs.constants.COPYFILE_EXCL);
  platform.applyRestrictivePermissions(bridge, { kind: "file" });
  const bridgeId = fs.statSync(bridge, { bigint: true }).ino,
    bridgeHash = digest(bridge),
    receipt = path.join(directory, "ownership.json"),
    receiptBytes = JSON.stringify({
      nonce,
      directoryId: String(directoryId),
      bridgeSha256: bridgeHash,
      controllerSha256: digest(controller),
    });
  fs.writeFileSync(receipt, receiptBytes, { flag: "wx", mode: 0o600 });
  platform.applyRestrictivePermissions(receipt, { kind: "file" });
  const receiptId = fs.statSync(receipt, { bigint: true }).ino;
  let child,
    closed,
    observed,
    wrapperIdentity,
    released = false,
    emergencyDrain = false;
  const state = {};
  const ownedFiles = () => {
    for (const [file, id] of [
      [directory, directoryId],
      [bridge, bridgeId],
      [receipt, receiptId],
    ]) {
      assert.equal(fs.lstatSync(file).isSymbolicLink(), false);
      assert.equal(fs.statSync(file, { bigint: true }).ino, id);
      assert.equal(
        fs.realpathSync(file).toLowerCase(),
        path.resolve(file).toLowerCase(),
      );
    }
    assert.equal(digest(bridge), bridgeHash);
    assert.equal(
      fs.readFileSync(receipt, "utf8") === receiptBytes,
      true,
      "Owned runner receipt changed",
    );
  };
  const read = (name) => {
    ownedFiles();
    const file = path.join(directory, name);
    if (!fs.existsSync(file)) return null;
    const stat = fs.lstatSync(file);
    assert.equal(stat.isSymbolicLink(), false);
    assert.ok(stat.size <= 16384);
    return JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""));
  };
  const write = (name) => {
    ownedFiles();
    const file = path.join(directory, name);
    if (fs.existsSync(file)) {
      assert.equal(fs.lstatSync(file).isSymbolicLink(), false);
      assert.equal(fs.readFileSync(file, "utf8"), nonce);
    } else fs.writeFileSync(file, nonce, { flag: "wx", mode: 0o600 });
  };
  const inventory = () =>
    JSON.parse(
      ps(
        "@{processes=@(Get-CimInstance Win32_Process|ForEach-Object {@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;created=$_.CreationDate.ToUniversalTime().ToString('o');exe=$_.ExecutablePath;command=$_.CommandLine}})}|ConvertTo-Json -Depth 4 -Compress",
      ),
    ).processes;
  const update = () => {
    const value = read("observed.json");
    if (!value) return null;
    assert.equal(value.nonce, nonce);
    assert.ok(Number.isInteger(value.controllerPid) && value.controllerPid > 0);
    assert.ok(Number.isInteger(value.workerPid) && value.workerPid > 0);
    observed = value;
    const alreadyFailed = state.failed === true;
    Object.assign(state, value.state);
    state.failed = alreadyFailed || emergencyDrain || state.failed === true;
    return value;
  };
  const resource = {
    hasLiveChild: () => !released,
    async stopAndDrain() {
      if (released) return;
      ownedFiles();
      if (child) {
        write("graceful-stop");
        let receipt;
        try {
          receipt = await until(() => read("closed.json"), 45000);
        } catch {
          emergencyDrain = true;
          state.failed = true;
          write("stop");
          receipt = await until(() => read("closed.json"), 45000);
        }
        assert.equal(receipt.token, nonce);
        assert.equal(receipt.wrapperPid, child.pid);
        assert.equal(receipt.ownerPid, process.pid);
        assert.equal(receipt.activeNativeProcesses, 0);
        assert.equal(receipt.retainedJobDrained, true);
        if (observed)
          assert.equal(receipt.nativeRootPid, observed.controllerPid);
        await Promise.race([
          closed,
          new Promise((_, reject) => {
            const timer = setTimeout(
              () => reject(Error("Owned retained-job wrapper did not close")),
              10000,
            );
            timer.unref();
          }),
        ]);
        const all = inventory();
        if (wrapperIdentity)
          assert.ok(
            !all.some(
              (row) =>
                row.pid === wrapperIdentity.pid &&
                row.created === wrapperIdentity.created,
            ),
            "Exact owned wrapper remains alive",
          );
        assert.ok(
          !all.some((row) =>
            (row.command || "").includes(pathToFileURL(bridge).href),
          ),
          "Owned runner remains alive",
        );
        update();
        state.nativeDrained = true;
        if (receipt.rootExitCode !== 0) state.failed = true;
      } else state.nativeDrained = true;
      ownedFiles();
      fs.rmSync(directory, { recursive: true });
      assert.equal(fs.existsSync(directory), false);
      released = true;
    },
  };
  ownedPhaseObservers.push(resource); // Retained owner is registered before launch or jobs.
  return {
    state,
    resource,
    applicationName: `certops-background-${nonce}`,
    async start() {
      assert.equal(child, undefined);
      ownedFiles();
      assert.equal(
        fs.existsSync(path.join(root, ".env")),
        false,
        "Candidate worker must not read an unowned root environment file",
      );
      const childEnv = {
        ...runnerEnvironment(env, nonce),
        CERTOPS_WORKER_PROTOCOL_DIRECTORY: directory,
      };
      child = spawn(
        path.join(
          env.SystemRoot || env.SYSTEMROOT,
          "System32/WindowsPowerShell/v1.0/powershell.exe",
        ),
        [
          "-NoProfile",
          "-NonInteractive",
          "-File",
          wrapper,
          "-NodePath",
          process.execPath,
          "-Entry",
          controller,
          "-ProtocolDirectory",
          directory,
          "-Token",
          nonce,
          "-OwnerProcessId",
          String(process.pid),
        ],
        { cwd: root, env: childEnv, windowsHide: true, stdio: "ignore" },
      );
      closed = new Promise((resolve) => {
        child.once("close", resolve);
        child.once("error", () => {
          state.failed = true;
        });
      });
      const ready = await until(() => read("ready.json"), 45000);
      assert.equal(ready.token, nonce);
      assert.equal(ready.wrapperPid, child.pid);
      assert.equal(ready.ownerPid, process.pid);
      const rows = inventory().filter((row) => row.pid === child.pid);
      assert.equal(rows.length, 1);
      wrapperIdentity = rows[0];
      assert.equal(wrapperIdentity.parent, process.pid);
      assert.equal(wrapperIdentity.created, ready.creationTime);
      assert.ok(
        wrapperIdentity.command.includes(wrapper),
        "Owned wrapper command mismatch",
      );
      write("run");
      await until(() => {
        const value = update();
        return value?.state.bridgeReady && value.state.starts === 1;
      }, 45000);
      const all = inventory(),
        controllerRow = all.find((row) => row.pid === observed.controllerPid),
        workerRow = all.find((row) => row.pid === observed.workerPid);
      assert.ok(controllerRow && workerRow);
      assert.equal(controllerRow.parent, child.pid);
      assert.equal(workerRow.parent, controllerRow.pid);
      assert.equal(
        controllerRow.exe.toLowerCase(),
        process.execPath.toLowerCase(),
      );
      assert.equal(workerRow.exe.toLowerCase(), process.execPath.toLowerCase());
      assert.ok(
        controllerRow.command.includes(controller) &&
          workerRow.command.includes(pathToFileURL(bridge).href),
        "Retained worker exact tree identity mismatch",
      );
    },
    check() {
      update();
      assert.equal(
        state.failed,
        false,
        "Actual worker lifecycle or maintenance failed",
      );
      assert.ok(
        child && child.exitCode === null && child.signalCode === null,
        "Owned worker job exited before requested stop",
      );
    },
    async stop() {
      await resource.stopAndDrain();
      validateLifecycle(state);
    },
  };
}
module.exports = {
  runnerEnvironment,
  observeRecord,
  validateLifecycle,
  createOwnedRunner,
};
