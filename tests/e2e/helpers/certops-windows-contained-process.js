"use strict";
/** Test-only native child custody. The paired PowerShell driver creates a root
 * suspended, assigns its retained kill-on-close Job Object, and resumes only
 * after independent parent readback. Environment values are inherited privately.
 * No numeric-PID termination or uncontained fallback exists. Never upload the
 * private protocol directory; public qualification projects bounded facts only. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn, spawnSync } = require("node:child_process");
const { isDeepStrictEqual } = require("node:util");
const registry = new Map();
const REQUIRED_SOURCES = Object.freeze([
  "tests/e2e/helpers/certops-windows-contained-process.js",
  "tests/e2e/helpers/certops-windows-contained-process.ps1",
]);
const NAMES = Object.freeze([
  "owner.json",
  "ready.json",
  "launch.json",
  "run",
  "started.json",
  "resume",
  "running.json",
  "stop",
  "closed.json",
]);
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
function publishGate(directory, name, token) {
  assert.ok(["run", "resume", "stop"].includes(name));
  assert.match(token, /^[a-f0-9]{32}$/);
  const temporary = path.join(directory, `.gate-${crypto.randomBytes(16).toString("hex")}.tmp`);
  const destination = path.join(directory, name);
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, token);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  const original = identity(temporary);
  // link publishes an already closed inode and refuses an existing target.
  // An unsupported filesystem fails closed; rename must not overwrite custody.
  fs.linkSync(temporary, destination);
  assert.equal(identity(destination), original);
  assert.equal(identity(temporary), original);
  assert.equal(fs.readFileSync(destination, "utf8"), token);
  fs.unlinkSync(temporary);
}
function verifyFailure(p) {
  exact(p, ["schemaVersion","token","wrapperPid","ownerPid","stage","exceptionType","hresult","nativeErrorCode"]);
  assert.equal(p.schemaVersion, 1);
  assert.match(p.token, /^[a-f0-9]{32}$/);
  for (const key of ["wrapperPid","ownerPid"]) assert.ok(Number.isSafeInteger(p[key]) && p[key] > 4 && p[key] <= 0xffffffff);
  assert.ok(["wait-run","launch-manifest","executable-lock","command-render","launch-ancestry","native-create","suspended-identity","publish-started","wait-resume","native-resume","native-drain"].includes(p.stage));
  assert.match(p.exceptionType, /^(?:System\.)[A-Za-z0-9_.]{1,160}$/);
  assert.ok(Number.isInteger(p.hresult) && p.hresult >= -2147483648 && p.hresult <= 2147483647);
  assert.ok(p.nativeErrorCode === null || (Number.isInteger(p.nativeErrorCode) && p.nativeErrorCode >= 0 && p.nativeErrorCode <= 2147483647));
  return true;
}
function exact(value, fields) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...fields].sort());
}
function pid(value) {
  assert.ok(Number.isInteger(value) && value > 0 && value <= 0xffffffff);
}
function quoteArgument(value) {
  assert.ok(
    typeof value === "string" &&
      value.length <= 32768 &&
      !/[\x00-\x1f]/.test(value),
  );
  return (
    '"' + value.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1") + '"'
  );
}
function commandLine(executable, args) {
  assert.ok(Array.isArray(args) && args.length <= 64);
  const value = [executable, ...args].map(quoteArgument).join(" ");
  assert.ok(value.length <= 32767);
  return value;
}
function identity(file) {
  const s = fs.lstatSync(file, { bigint: true });
  assert.ok(
    !s.isSymbolicLink() && (s.isDirectory() || s.isFile()) && s.ino > 0n,
  );
  assert.equal(
    path.resolve(fs.realpathSync(file)).toLowerCase(),
    path.resolve(file).toLowerCase(),
  );
  return `${s.dev}:${s.ino}`;
}
function nativeEnvironment(environment = process.env) {
  const values = { ...environment };
  for (const key of Object.keys(values)) {
    if (key.toLowerCase() === "psmodulepath") delete values[key];
  }
  return values;
}
function childEnvironment(provided, inherited = process.env) {
  return nativeEnvironment(provided === undefined ? inherited : provided);
}
function nativeObservation(processId) {
  pid(processId);
  const script = `$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$p=Get-CimInstance Win32_Process -Filter 'ProcessId=${processId}';if(!$p-or!$p.ExecutablePath-or!$p.CommandLine){throw 'Complete native identity unavailable'};$o=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid;if($o.ReturnValue-ne 0){throw 'Native owner unavailable'};[pscustomobject]@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;creationTime=$p.CreationDate.ToUniversalTime().ToString('o');executablePath=[string]$p.ExecutablePath;commandLine=[string]$p.CommandLine;sid=[string]$o.Sid}|ConvertTo-Json -Compress`;
  const result = spawnSync(
    path.join(
      process.env.SystemRoot,
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    ),
    [
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(script, "utf16le").toString("base64"),
    ],
    {
      encoding: "utf8",
      timeout: 10000,
      windowsHide: true,
      env: nativeEnvironment(),
    },
  );
  assert.ifError(result.error);
  assert.equal(
    result.status,
    0,
    "Native contained-process identity read failed",
  );
  return JSON.parse(result.stdout);
}
function nativeSuspendedObservation(processId) {
  pid(processId);
  const result = spawnSync(
    path.join(
      process.env.SystemRoot,
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    ),
    [
      "-NoProfile",
      "-NonInteractive",
      "-File",
      path.join(__dirname, "certops-windows-contained-process.ps1"),
      "-ObserveProcessId",
      String(processId),
    ],
    {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
      env: nativeEnvironment(),
    },
  );
  assert.ifError(result.error);
  assert.equal(
    result.status,
    0,
    "Independent suspended native observation failed",
  );
  const value = JSON.parse(result.stdout);
  exact(value, ["pid", "creationTime", "executablePath", "sid"]);
  return value;
}
function verifyStarted(value, expected) {
  exact(value, [
    "token",
    "wrapperPid",
    "ownerPid",
    "pid",
    "parentPid",
    "creationTime",
    "executablePath",
    "commandLine",
    "commandLineOrigin",
    "sid",
    "nativeSuspended",
    "jobAssignedBeforeResume",
  ]);
  for (const field of ["token", "wrapperPid", "ownerPid"])
    assert.ok(
      value[field] === expected[field],
      "Contained launch owner differs",
    );
  pid(value.pid);
  assert.equal(value.parentPid, expected.wrapperPid);
  assert.equal(value.sid, expected.sid);
  assert.ok(
    typeof value.creationTime === "string" &&
      /^\d{4}-\d\d-\d\dT.*Z$/.test(value.creationTime),
  );
  assert.ok(
    value.executablePath.toLowerCase() === expected.executable.toLowerCase(),
    "Contained native image differs",
  );
  assert.ok(
    value.commandLine === expected.commandLine,
    "Contained root arguments differ",
  );
  assert.equal(value.commandLineOrigin, "sealed-createprocess-input");
  assert.equal(value.nativeSuspended, true);
  assert.equal(value.jobAssignedBeforeResume, true);
  return true;
}
function verifyClosed(value, expected) {
  exact(value, [
    "token",
    "wrapperPid",
    "ownerPid",
    "nativeRootPid",
    "rootExitCode",
    "launchOccurred",
    "activeNativeProcesses",
    "retainedJobDrained",
    "nativeRootExited",
    "nativeHandlesClosed",
  ]);
  for (const field of ["token", "wrapperPid", "ownerPid"])
    assert.ok(
      value[field] === expected[field],
      "Contained drain owner differs",
    );
  assert.equal(typeof value.launchOccurred, "boolean");
  if (value.launchOccurred) {
    pid(value.nativeRootPid);
    assert.ok(
      Number.isInteger(value.rootExitCode) &&
        value.rootExitCode >= 0 &&
        value.rootExitCode <= 0xffffffff,
    );
    assert.equal(value.nativeRootPid, expected.rootPid);
  } else {
    assert.equal(value.nativeRootPid, null);
    assert.equal(value.rootExitCode, null);
    assert.equal(expected.rootPid, null);
  }
  assert.equal(value.activeNativeProcesses, 0);
  for (const field of [
    "retainedJobDrained",
    "nativeRootExited",
    "nativeHandlesClosed",
  ])
    assert.equal(value[field], true);
  return true;
}
function assertCleanupSafe(workDir) {
  const root = path.resolve(workDir);
  assert.ok(
    !registry.get(root)?.size,
    "Unresolved contained native process preserves fixture state",
  );
  assert.ok(
    !fs
      .readdirSync(root)
      .some((name) => name.startsWith(".contained-process-")),
    "Unresolved contained native ownership receipt preserves fixture state",
  );
  return true;
}
async function startContainedNativeProcess({
  executable,
  args,
  argsForWrapper,
  environment,
  workDir,
  maxLifetimeMs = 300000,
  expectedSid,
  onCreated,
}) {
  assert.equal(process.platform, "win32");
  assert.ok(path.isAbsolute(executable) && path.isAbsolute(workDir));
  assert.equal(fs.lstatSync(executable).isFile(), true);
  identity(executable);
  assert.ok(
    Number.isInteger(maxLifetimeMs) &&
      maxLifetimeMs >= 5000 &&
      maxLifetimeMs <= 3600000,
  );
  assert.ok(
    (Array.isArray(args) && argsForWrapper === undefined) ||
      (args === undefined && typeof argsForWrapper === "function"),
  );
  const owner = nativeObservation(process.pid);
  if (expectedSid !== undefined) assert.equal(owner.sid, expectedSid);
  const sid = owner.sid;
  const root = path.resolve(workDir),
    rootId = identity(root),
    directory = fs.mkdtempSync(path.join(root, ".contained-process-")),
    directoryId = identity(directory),
    token = crypto.randomBytes(16).toString("hex"),
    driver = path.join(__dirname, "certops-windows-contained-process.ps1"),
    powershell = path.join(
      process.env.SystemRoot,
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    );
  const files = new Map();
  let closed = false,
    started,
    ready,
    released = false,
    closePromise,
    closeResult,
    runIssued = false;
  const entries = registry.get(root) || new Set();
  registry.set(root, entries);
  const check = () => {
    assert.equal(identity(root), rootId);
    assert.equal(identity(directory), directoryId);
    for (const [name, prior] of files) {
      const file = path.join(directory, name);
      assert.equal(identity(file), prior.id);
      assert.equal(
        hash(fs.readFileSync(file)),
        prior.sha256,
        "Contained protocol replacement preserves state",
      );
    }
  };
  const remember = (name) => {
    const file = path.join(directory, name);
    const stat = fs.lstatSync(file);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 65536);
    const bytes = fs.readFileSync(file);
    const item = { id: identity(file), sha256: hash(bytes) };
    if (files.has(name))
      assert.ok(
        isDeepStrictEqual(files.get(name), item),
        "Contained receipt changed",
      );
    else files.set(name, item);
    return bytes;
  };
  const read = (name) => {
    check();
    return JSON.parse(remember(name).toString("utf8"));
  };
  const write = (name, bytes) => {
    check();
    fs.writeFileSync(path.join(directory, name), bytes, { flag: "wx" });
    remember(name);
  };
  const signal = (name) => {
    if (fs.existsSync(path.join(directory, name))) {
      assert.equal(remember(name).toString("utf8"), token);
      return;
    }
    check();
    publishGate(directory, name, token);
    remember(name);
  };
  const wait = async (predicate, limit = 30000) => {
    const deadline = performance.now() + limit;
    while (performance.now() < deadline) {
      check();
      const value = predicate();
      if (value) return value;
      if (closed && fs.existsSync(path.join(directory, "failed.json"))) {
        const failure = read("failed.json");
        verifyFailure(failure);
        assert.equal(failure.token, token);
        assert.equal(failure.wrapperPid, ready.wrapperPid);
        assert.equal(failure.ownerPid, process.pid);
        throw new Error(`Contained native failure at ${failure.stage}: ${failure.exceptionType} (${failure.hresult}, native ${failure.nativeErrorCode})`);
      }
      if (closed)
        throw new Error(
          "Contained wrapper closed before required native phase",
        );
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error("Contained native phase exceeded bounded deadline");
  };
  let exitResolve;
  const exited = new Promise((resolve) => {
    exitResolve = resolve;
  });
  const resource = {
    wrapper: null,
    rootIdentity: null,
    ready: null,
    hasLiveChild: () => Boolean(child && !closed),
    hasOwnershipReceipt: () => !released,
    async stopAndDrain() {
      if (released) return closeResult;
      if (closePromise) return closePromise;
      closePromise = (async () => {
        check();
        if (!closed) signal("stop");
        let timer;
        try {
          await Promise.race([
            exited,
            new Promise((_, reject) => {
              timer = setTimeout(
                () =>
                  reject(
                    new Error(
                      "Contained wrapper did not close after native drain request",
                    ),
                  ),
                45000,
              );
            }),
          ]);
        } finally {
          clearTimeout(timer);
        }
        const result = read("closed.json");
        verifyClosed(result, {
          token,
          wrapperPid: child.pid,
          ownerPid: process.pid,
          rootPid: started?.pid ?? null,
        });
        assert.equal(closed, true);
        check();
        // Every artifact is private, bounded, non-linked and written once. A
        // foreign/unknown file prevents deleting this ownership directory.
        for (const name of fs.readdirSync(directory)) {
          assert.ok(
            NAMES.includes(name),
            "Unexpected contained process artifact preserves state",
          );
          remember(name);
        }
        check();
        for (const name of files.keys())
          fs.unlinkSync(path.join(directory, name));
        fs.rmdirSync(directory);
        released = true;
        entries.delete(resource);
        if (entries.size === 0) registry.delete(root);
        closeResult = result;
        return result;
      })();
      try {
        return await closePromise;
      } finally {
        if (!released) closePromise = null;
      }
    },
  };
  entries.add(resource);
  const manifest = {
    schemaVersion: 1,
    kind: "certops-contained-native-test-process",
    token,
    ownerPid: process.pid,
    executable,
    executableSha256: hash(fs.readFileSync(executable)),
    driverSha256: hash(fs.readFileSync(driver)),
    maxLifetimeMs,
    cwd: root,
  };
  write("owner.json", JSON.stringify(manifest));
  const nativeEnv = childEnvironment(environment);
  const child = spawn(
    powershell,
    [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      driver,
      "-ProtocolDirectory",
      directory,
      "-Token",
      token,
      "-OwnerProcessId",
      String(process.pid),
      "-OwnerSha256",
      files.get("owner.json").sha256,
    ],
    { env: nativeEnv, stdio: "ignore", windowsHide: true },
  );
  resource.wrapper = child;
  child.once("error", () => {});
  child.once("close", () => {
    closed = true;
    exitResolve();
  });
  const startup = async () => {
    if (onCreated) onCreated(resource);
    ready = await wait(
      () =>
        fs.existsSync(path.join(directory, "ready.json")) && read("ready.json"),
    );
    exact(ready, [
      "token",
      "wrapperPid",
      "ownerPid",
      "creationTime",
      "ownerCreationTime",
      "sid",
    ]);
    assert.equal(ready.token, token);
    assert.equal(ready.wrapperPid, child.pid);
    assert.equal(ready.ownerPid, process.pid);
    assert.equal(ready.sid, sid);
    assert.equal(ready.ownerCreationTime, owner.creationTime);
    const observed = nativeObservation(child.pid);
    assert.equal(observed.parentPid, process.pid);
    assert.equal(observed.creationTime, ready.creationTime);
    assert.equal(observed.sid, sid);
    assert.ok(
      observed.executablePath.toLowerCase() === powershell.toLowerCase(),
    );
    assert.ok(
      observed.commandLine.includes(driver) &&
        observed.commandLine.includes(directory) &&
        observed.commandLine.includes(token),
      "Actual wrapper command custody required",
    );
    const actualArgs = argsForWrapper ? argsForWrapper(child.pid) : args,
      cmd = commandLine(executable, actualArgs);
    write(
      "launch.json",
      JSON.stringify({
        token,
        executable,
        args: actualArgs,
        commandLine: cmd,
        cwd: root,
      }),
    );
    signal("run");
    runIssued = true;
    started = await wait(
      () =>
        fs.existsSync(path.join(directory, "started.json")) &&
        read("started.json"),
    );
    verifyStarted(started, {
      token,
      wrapperPid: child.pid,
      ownerPid: process.pid,
      sid,
      executable,
      commandLine: cmd,
    });
    const native = nativeSuspendedObservation(started.pid);
    for (const field of ["pid", "creationTime", "executablePath", "sid"])
      assert.ok(
        native[field] === started[field],
        "Independent suspended native identity differs",
      );
    signal("resume");
    const running = await wait(
      () =>
        fs.existsSync(path.join(directory, "running.json")) &&
        read("running.json"),
    );
    exact(running, ["token", "pid", "jobAssignedBeforeResume"]);
    assert.equal(running.token, token);
    assert.equal(running.pid, started.pid);
    assert.equal(running.jobAssignedBeforeResume, true);
    // CIM may omit a suspended executable image. Native handle observations
    // establish image/time/SID before resume; exact actual argv is observed only
    // after resume, while the process is already contained by its retained job.
    const actual = await wait(() => {
      try {
        return nativeObservation(started.pid);
      } catch {
        return null;
      }
    });
    for (const field of ["pid", "parentPid", "commandLine", "sid"])
      assert.ok(
        actual[field] === started[field],
        `Independent running native ${field} differs`,
      );
    assert.ok(
      path.win32.isAbsolute(actual.executablePath) &&
        path.win32.isAbsolute(started.executablePath) &&
        path.win32.normalize(actual.executablePath).toLowerCase() ===
          path.win32.normalize(started.executablePath).toLowerCase(),
      "Independent running native image differs",
    );
    assert.equal(
      actual.creationTime.slice(0, 26),
      started.creationTime.slice(0, 26),
      "Native/CIM creation presentation differs",
    );
    resource.rootIdentity = actual;
    return resource;
  };
  resource.ready = startup();
  try {
    return await resource.ready;
  } catch (error) {
    try {
      await resource.stopAndDrain();
    } catch (cleanup) {
      throw new AggregateError(
        [error, cleanup],
        runIssued
          ? "Contained launch failed; native custody unresolved"
          : "Contained preparation failed; preserve original ownership",
      );
    }
    throw error;
  }
}
module.exports = {
  publishGate,
  verifyFailure,
  startContainedNativeProcess,
  assertCleanupSafe,
  quoteArgument,
  commandLine,
  verifyStarted,
  verifyClosed,
  nativeEnvironment,
  childEnvironment,
  REQUIRED_SOURCES,
};
