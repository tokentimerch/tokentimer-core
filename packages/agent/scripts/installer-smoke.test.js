"use strict";

/**
 * Installer smoke test: package the agent, extract it OUTSIDE the monorepo,
 * install production deps, and prove entrypoint imports resolve without any
 * monorepo-relative path layout.
 *
 * Also covers the actual install-agent.sh flow directly: that script never
 * runs npm/pnpm install at all (it tars this directory excluding
 * node_modules and swaps it into place), so a separate test below
 * re-extracts the same tarball with zero install step and boots the real
 * bin/tokentimer-agent.js entrypoint to catch missing-runtime-dependency
 * regressions the npm-install-based tests above cannot catch.
 */

const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const packageRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(packageRoot, "..", "..");

function npmCommand() {
  // On Windows, npm is a .cmd shim; shell:true is required for spawnSync.
  return "npm";
}

function runOrThrow(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    shell: process.platform === "win32",
    ...options,
  });
  if (result.error || result.status !== 0) {
    const detail = [
      `$ ${command} ${args.join(" ")}`,
      result.error ? String(result.error) : "",
      result.stdout || "",
      result.stderr || "",
    ].join("\n");
    throw new Error(
      `command failed (exit ${result.status}):\n${detail}`,
    );
  }
  return result;
}

describe("installer packaging smoke (B9)", () => {
  let stagingRoot;
  let extractedRoot;

  before(() => {
    stagingRoot = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-pack-"));
    // Guarantees the extract dir is outside the monorepo tree.
    assert.equal(
      path.relative(repoRoot, stagingRoot).startsWith("..") ||
        path.isAbsolute(path.relative(repoRoot, stagingRoot)),
      true,
      `staging dir must be outside the monorepo: ${stagingRoot}`,
    );

    const pack = runOrThrow(
      npmCommand(),
      ["pack", "--pack-destination", stagingRoot],
      { cwd: packageRoot },
    );
    const tarballName = pack.stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .pop();
    assert.ok(tarballName && tarballName.endsWith(".tgz"), `npm pack produced no tarball: ${pack.stdout}`);

    const tarballPath = path.join(stagingRoot, tarballName);
    assert.ok(fs.existsSync(tarballPath), `missing packed tarball ${tarballPath}`);

    runOrThrow(
      process.platform === "win32" ? "tar.exe" : "tar",
      ["-xzf", tarballPath, "-C", stagingRoot],
    );
    extractedRoot = path.join(stagingRoot, "package");
    assert.ok(fs.existsSync(path.join(extractedRoot, "package.json")));
    assert.ok(fs.existsSync(path.join(extractedRoot, "src", "index.js")));

    // Production install in isolation. Agent currently has no runtime npm
    // deps; this still materializes node_modules and proves package.json is
    // installable outside the workspace.
    runOrThrow(
      npmCommand(),
      ["install", "--omit=dev", "--ignore-scripts"],
      { cwd: extractedRoot },
    );
  });

  after(() => {
    if (stagingRoot) {
      fs.rmSync(stagingRoot, { recursive: true, force: true });
    }
  });

  it("loads the agent entry module with only package-local resolution", () => {
    const probe = `
      const path = require('node:path');
      const modulePath = path.join(process.cwd(), 'src', 'index.js');
      const mod = require(modulePath);
      if (typeof mod.runAgent !== 'function') {
        throw new Error('runAgent export missing after isolated require');
      }
      // Touch modules that historically imported monorepo paths.
      require(path.join(process.cwd(), 'src', 'evidence', 'index.js'));
      require(path.join(process.cwd(), 'src', 'keys', 'index.js'));
      require(path.join(process.cwd(), 'src', 'logging', 'index.js'));
      require(path.join(process.cwd(), 'src', 'signing', 'index.js'));
      require(path.join(process.cwd(), 'src', 'protocol', 'index.js'));
      require(path.join(process.cwd(), 'src', 'discovery', 'index.js'));
      require(path.join(process.cwd(), 'src', 'config', 'index.js'));
      console.log('installer-smoke: imports-ok');
    `;
    const result = spawnSync(process.execPath, ["-e", probe], {
      cwd: extractedRoot,
      encoding: "utf8",
      env: { ...process.env, NODE_PATH: "" },
    });
    assert.equal(
      result.status,
      0,
      `isolated require failed:\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
    assert.match(result.stdout, /installer-smoke: imports-ok/);
  });

  it("does not ship monorepo-relative secretMaterial or log-scrub requires", () => {
    const evidence = fs.readFileSync(
      path.join(extractedRoot, "src", "evidence", "index.js"),
      "utf8",
    );
    assert.doesNotMatch(
      evidence,
      /require\s*\(\s*["'][^"']*apps\/api\/utils\/secretMaterial/,
    );
    assert.doesNotMatch(
      evidence,
      /require\s*\(\s*["']\.\.\/\.\.\/\.\.\/log-scrub\//,
    );
    assert.match(
      evidence,
      /require\s*\(\s*["']\.\.\/\.\.\/vendor\/log-scrub\/secret-material\.js["']\s*\)/,
    );
    assert.ok(
      fs.existsSync(
        path.join(extractedRoot, "vendor", "log-scrub", "secret-material.js"),
      ),
    );
    assert.ok(
      fs.existsSync(
        path.join(extractedRoot, "vendor", "contracts", "canonical-json.cjs"),
      ),
    );
  });

  it("boots with NO install step at all, matching install-agent.sh's tar-copy-only flow", () => {
    // install-agent.sh never runs npm/pnpm install; it stages this package
    // directory with `tar --exclude=./node_modules` and swaps it into place
    // (see scripts/install-agent.sh). Re-extract a FRESH copy of the same
    // tarball with no node_modules whatsoever and prove the real entrypoint
    // (bin/tokentimer-agent.js, not just src/index.js in isolation) starts
    // far enough to reach config loading, i.e. it never throws
    // MODULE_NOT_FOUND for a missing runtime dependency.
    const noInstallRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-noinstall-"),
    );
    const tarball = fs.readdirSync(stagingRoot).find((name) => name.endsWith(".tgz"));
    assert.ok(tarball, "no packed tarball found to re-extract");
    runOrThrow(
      process.platform === "win32" ? "tar.exe" : "tar",
      ["-xzf", path.join(stagingRoot, tarball), "-C", noInstallRoot],
    );
    const noInstallExtracted = path.join(noInstallRoot, "package");
    assert.ok(
      !fs.existsSync(path.join(noInstallExtracted, "node_modules")),
      "precondition: this extraction must have no node_modules, matching install-agent.sh",
    );

    // Run the actual bin entrypoint with a bogus config dir and a short-lived
    // abort signal: it should fail on config/network, never on require().
    const configDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-agent-noinstall-config-"),
    );
    try {
      const result = spawnSync(
        process.execPath,
        [path.join(noInstallExtracted, "bin", "tokentimer-agent.js")],
        {
          encoding: "utf8",
          timeout: 5000,
          env: {
            ...process.env,
            NODE_PATH: "",
            TOKENTIMER_AGENT_CONFIG_DIR: configDir,
          },
        },
      );
      const output = `${result.stdout || ""}\n${result.stderr || ""}`;
      assert.doesNotMatch(
        output,
        /MODULE_NOT_FOUND/,
        `agent entrypoint failed to resolve a require() with no node_modules present:\n${output}`,
      );
    } finally {
      fs.rmSync(configDir, { recursive: true, force: true });
    }
    fs.rmSync(noInstallRoot, { recursive: true, force: true });
  });
});

/**
 * Windows service lifecycle smoke test (H-blocker regression guard).
 *
 * Registers a *real* uniquely named disposable service pointed at the built
 * windows-service-host binary + a mock agent child, then asserts it
 * actually reaches the Running state and survives a Stop-Service /
 * Start-Service cycle. This is the regression the reviewer flagged: a
 * plain node.exe binPath never calls StartServiceCtrlDispatcher, so the
 * SCM fails the start (error 1053) after ~30s and the failure/restart
 * policy in install-agent.ps1 turns that into a restart loop. Exercising
 * the real SCM (not a mock) is the only way to catch that class of bug.
 *
 * Uses the mock agent (windows-service-host/testdata/mock-agent.js)
 * rather than the real agent entrypoint so this test needs no network,
 * API URL, or bootstrap token: it is scoped to the SCM handshake and
 * process-lifecycle contract the host provides, which is exactly what
 * regressed. install-agent.ps1's own binPath-construction logic is
 * exercised indirectly, by hand-building the identical
 * "<host.exe>" "<node.exe>" "<entry.js>" argv shape it produces.
 *
 * Requires: Windows + an elevated (Administrator) process, because
 * creating/starting a LocalSystem service and writing HKLM requires
 * elevation. Skips (does not fail) otherwise, e.g. on Linux/macOS CI
 * runners or an unelevated local shell; the Windows-specific CI job is
 * expected to run this as Administrator.
 */
describe("Windows service lifecycle smoke (H-blocker regression guard)", () => {
  const SERVICE_NAME = `CertOpsQualification-${require("node:crypto").randomUUID()}`;
  const REG_KEY = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${SERVICE_NAME}`;

  function isWindowsElevated() {
    if (process.platform !== "win32") return false;
    // Inspect the actual token; `net session` also depends on the Server
    // service being enabled and incorrectly rejects some elevated runners.
    const probe = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
      "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
    ], { encoding: "utf8", timeout: 15000 });
    return probe.status === 0 && probe.stdout.trim() === "True";
  }

  function getServiceStatus() {
    const result = spawnSync("sc.exe", ["query", SERVICE_NAME], { encoding: "utf8" });
    if (result.status !== 0) return null;
    const match = /STATE\s*:\s*\d+\s+(\w+)/.exec(result.stdout || "");
    return match ? match[1] : null;
  }

  function waitForStatus(target, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (getServiceStatus() === target) return true;
      // Deliberately synchronous polling: this test has no event loop
      // work to interleave with, and node:test's own timeout is the
      // real ceiling on total runtime.
      spawnSync(process.execPath, ["-e", "setTimeout(()=>{}, 300)"], { timeout: 1000 });
    }
    return false;
  }

  // Even after the SCM reports STOPPED, a just-exited process's file
  // handles can take a moment longer to actually release on Windows (a
  // known gap between "process is gone" and "handle table is drained",
  // sometimes stretched further by an AV on-close scan) - so a bare
  // fs.rmSync right after STOPPED can still observe a transient EPERM/
  // EBUSY. Retry a few times with a short backoff rather than either
  // failing the whole suite on cleanup or silently swallowing a real,
  // permanent lock (e.g. a leaked handle bug) after the retries exhaust.
  function removeDirWithRetry(dir, attempts = 5, delayMs = 500) {
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
        return;
      } catch (err) {
        if (attempt === attempts || !["EPERM", "EBUSY"].includes(err.code)) throw err;
        spawnSync(process.execPath, ["-e", `setTimeout(()=>{}, ${delayMs})`], { timeout: delayMs + 1000 });
      }
    }
  }

  let skipReason = null;
  let hostExe;
  let mockAgentJs;
  let serviceConfigDir;
  let serviceOwned = false;

  before(() => {
    if (!isWindowsElevated()) {
      skipReason = "requires an elevated (Administrator) Windows process";
      if (process.env.CERTOPS_QUALIFICATION_STRICT === "1") throw new Error(skipReason);
      return;
    }
    if (getServiceStatus() !== null) {
      // Refuse to touch a pre-existing service of this name: it could be
      // a real dev install on this machine, and this test deletes the
      // service it creates when done.
      skipReason = `a "${SERVICE_NAME}" service already exists on this host; skipping rather than risk clobbering it`;
      if (process.env.CERTOPS_QUALIFICATION_STRICT === "1") throw new Error(skipReason);
      return;
    }

    serviceConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), "CertOps Qualification SCM "));
    const goarch = process.arch === "arm64" ? "arm64" : "amd64";
    hostExe = path.join(serviceConfigDir, "qualification-service-host.exe");
    const source = path.join(packageRoot, "windows-service-host", "service_windows.go");
    const fixtureSource = path.join(serviceConfigDir, "service_windows.go");
    const originalSource = fs.readFileSync(source, "utf8");
    assert.ok(originalSource.includes('const serviceName = "TokenTimerAgent"'));
    fs.writeFileSync(fixtureSource, originalSource.replace('const serviceName = "TokenTimerAgent"',
      `const serviceName = "${SERVICE_NAME}"`));
    const overlay = path.join(serviceConfigDir, "source-overlay.json");
    fs.writeFileSync(overlay, JSON.stringify({ Replace: { [source]: fixtureSource } }));
    const build = spawnSync("go", ["build", "-trimpath", "-buildvcs=false", `-overlay=${overlay}`,
      "-ldflags=-s -w -H=windowsgui", "-o", hostExe, "."], {
      cwd: path.join(packageRoot, "windows-service-host"), encoding: "utf8", timeout: 180000,
      env: { ...process.env, GOOS: "windows", GOARCH: goarch },
    });
    assert.equal(build.status, 0, "qualification service host build failed");
    assert.ok(fs.existsSync(hostExe), `expected built host binary at ${hostExe}`);

    mockAgentJs = path.join(packageRoot, "windows-service-host", "testdata", "mock-agent.js");
    assert.ok(fs.existsSync(mockAgentJs), `expected mock agent fixture at ${mockAgentJs}`);

  });

  after(() => {
    if (serviceOwned && getServiceStatus() !== null) {
      // A failed assertion or interrupted uninstall may leave it RUNNING.
      // `sc.exe stop` only *requests* a stop and returns immediately - it
      // does not wait for the SCM to actually tear the process down - so
      // deleting serviceConfigDir right after it, with no wait, raced the
      // mock agent's own file handles on that directory and intermittently
      // failed cleanup with EPERM. Wait for STOPPED (bounded, same 15s
      // ceiling the test body itself uses) before deleting the service.
      if (getServiceStatus() !== "STOPPED") {
        spawnSync("sc.exe", ["stop", SERVICE_NAME], { encoding: "utf8" });
        assert.ok(waitForStatus("STOPPED", 15000), "owned service did not stop during cleanup");
      }
      const deleted = spawnSync("sc.exe", ["delete", SERVICE_NAME], { encoding: "utf8" });
      assert.equal(deleted.status, 0, "owned service deletion failed");
      const deletionDeadline = Date.now() + 15000;
      while (getServiceStatus() !== null && Date.now() < deletionDeadline) {
        spawnSync(process.execPath, ["-e", "setTimeout(()=>{},300)"], { timeout: 1000 });
      }
      assert.equal(getServiceStatus(), null, "owned service remains after deletion");
    }
    if (serviceConfigDir) removeDirWithRetry(serviceConfigDir);
  });

  it("reaches Running and survives a Stop-Service / Start-Service cycle", (t) => {
    if (skipReason) {
      // skip-reason: no-host - requires an elevated Windows host to install a real service
      t.skip(skipReason);
      return;
    }

    const quotedHost = `"${hostExe}"`;
    const quotedNode = `"${process.execPath}"`;
    const quotedEntry = `"${mockAgentJs}"`;
    const binPath = `${quotedHost} ${quotedNode} ${quotedEntry}`;

    const create = spawnSync("sc.exe", [
      "create", SERVICE_NAME,
      "type=", "own",
      "start=", "demand",
      "obj=", "LocalSystem",
      "DisplayName=", "TokenTimer Agent Smoke Test",
      "binPath=", binPath,
    ], { encoding: "utf8" });
    assert.equal(create.status, 0, `sc.exe create failed:\n${create.stdout}\n${create.stderr}`);
    serviceOwned = true;

    // Mirrors Set-ServiceEnvironment in install-agent.ps1, including a
    // bootstrap-token-shaped value, so the Task 2 assertion below exercises
    // the exact registry shape the real installer produces.
    const setEnv = spawnSync("reg.exe", [
      "add", REG_KEY,
      "/v", "Environment",
      "/t", "REG_MULTI_SZ",
      "/d", [`TOKENTIMER_AGENT_CONFIG_DIR=${serviceConfigDir}`, "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=ttboot_smoketest",
        "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID=qualification-id", "QUALIFICATION_UNRELATED=preserved spaces",
        "PATH=C:\\0sdk;C:\\Windows\\System32"].join("|"),
      "/s", "|",
      "/f",
    ], { encoding: "utf8" });
    assert.equal(setEnv.status, 0, `reg.exe add failed:\n${setEnv.stdout}\n${setEnv.stderr}`);

    const start = spawnSync("sc.exe", ["start", SERVICE_NAME], { encoding: "utf8" });
    assert.equal(start.status, 0, `sc.exe start failed:\n${start.stdout}\n${start.stderr}`);

    assert.ok(
      waitForStatus("RUNNING", 15000),
      `service never reached RUNNING (last status: ${getServiceStatus()}); this is exactly the ` +
        "error-1053 regression this test guards against if it fails",
    );

    // --- Task 2 (bootstrap token retention) integration assertion ---
    // Exercise the real reg.exe path (not the mocked-spawn unit tests in
    // platform.test.js) against the Environment value the service is
    // actually running with.
    const { clearWindowsServiceBootstrapToken } = require("../src/platform/index.js");
    const registryCalls = [];
    const ownedRegistry = (file, args, options) => {
      // Keep released configuration fixed. Redirect only the registry target
      // through the existing test seam; every result comes from real reg.exe.
      assert.equal(file, "reg.exe");
      assert.equal(args[1], "HKLM\\SYSTEM\\CurrentControlSet\\Services\\TokenTimerAgent");
      registryCalls.push(args[0]);
      return spawnSync(file, [args[0], REG_KEY, ...args.slice(2)], options);
    };
    const beforeForeignScrub = spawnSync("reg.exe", ["query", REG_KEY, "/v", "Environment"], { encoding: "utf8" });
    assert.equal(beforeForeignScrub.status, 0);
    const foreignScrub = clearWindowsServiceBootstrapToken({ configDir: path.join(serviceConfigDir, "foreign-state"), spawn: ownedRegistry });
    assert.equal(foreignScrub.cleared, false);
    assert.equal(foreignScrub.reason, "service config directory does not match this agent");
    assert.deepEqual(registryCalls, ["query"], "foreign config must not write an installed service's environment");
    const afterForeignScrub = spawnSync("reg.exe", ["query", REG_KEY, "/v", "Environment"], { encoding: "utf8" });
    assert.equal(afterForeignScrub.status, 0);
    assert.equal(afterForeignScrub.stdout, beforeForeignScrub.stdout, "native environment must remain byte-identical after foreign scrub");
    registryCalls.length = 0;
    const scrubResult = clearWindowsServiceBootstrapToken({ configDir: serviceConfigDir, spawn: ownedRegistry });
    assert.deepEqual(scrubResult, { attempted: true, cleared: true });
    assert.deepEqual(registryCalls, ["query", "query", "add"]);

    const queryAfterScrub = spawnSync(
      "reg.exe",
      ["query", REG_KEY, "/v", "Environment"],
      { encoding: "utf8" },
    );
    assert.equal(queryAfterScrub.status, 0);
    assert.doesNotMatch(
      queryAfterScrub.stdout,
      /TOKENTIMER_AGENT_BOOTSTRAP_TOKEN/,
      "bootstrap token must not remain in the service Environment registry value after scrub",
    );
    assert.match(
      queryAfterScrub.stdout,
      /TOKENTIMER_AGENT_CONFIG_DIR/,
      "scrub must preserve the non-secret config dir entry",
    );
    assert.match(queryAfterScrub.stdout, /QUALIFICATION_UNRELATED=preserved spaces/);
    assert.ok(queryAfterScrub.stdout.includes("PATH=C:\\0sdk;C:\\Windows\\System32"), "scrub must not reinterpret a literal backslash-zero path as a separator");
    const typedEnvironment = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
      `$ErrorActionPreference='Stop'; $k=Get-Item -LiteralPath 'HKLM:${REG_KEY.slice(4)}'; if ([string]$k.GetValueKind('Environment') -ne 'MultiString') { throw 'Unexpected native environment type' }; $v=$k.GetValue('Environment',$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); ConvertTo-Json -InputObject @($v) -Compress`], { encoding: "utf8" });
    assert.equal(typedEnvironment.status, 0, "independent typed registry observation failed");
    assert.deepEqual(JSON.parse(typedEnvironment.stdout), [`TOKENTIMER_AGENT_CONFIG_DIR=${serviceConfigDir}`,
      "QUALIFICATION_UNRELATED=preserved spaces", "PATH=C:\\0sdk;C:\\Windows\\System32"]);

    // --- Task 1 (SCM handshake) Stop/Start cycle assertion ---
    const stop = spawnSync("sc.exe", ["stop", SERVICE_NAME], { encoding: "utf8" });
    assert.equal(stop.status, 0, `sc.exe stop failed:\n${stop.stdout}\n${stop.stderr}`);
    assert.ok(waitForStatus("STOPPED", 15000), `service never reached STOPPED (last status: ${getServiceStatus()})`);

    const restart = spawnSync("sc.exe", ["start", SERVICE_NAME], { encoding: "utf8" });
    assert.equal(restart.status, 0, `sc.exe start (restart) failed:\n${restart.stdout}\n${restart.stderr}`);
    assert.ok(
      waitForStatus("RUNNING", 15000),
      `service did not come back RUNNING after Stop-Service/Start-Service (last status: ${getServiceStatus()})`,
    );
    // Configure real SCM recovery and trigger a nonzero child exit. The
    // fresh child's receipt is stronger evidence than sampling RUNNING
    // immediately after the crash trigger while the old child is still up.
    const recovery = spawnSync("sc.exe", ["failure", SERVICE_NAME, "reset=", "60", "actions=", "restart/1000"], { encoding: "utf8" });
    assert.equal(recovery.status, 0, `SCM recovery configuration failed: ${recovery.stderr}`);
    const failureFlag = spawnSync("sc.exe", ["failureflag", SERVICE_NAME, "1"], { encoding: "utf8" });
    assert.equal(failureFlag.status, 0);
    const startsPath = path.join(serviceConfigDir, "fixture-starts.log");
    const childReadyDeadline = Date.now() + 15000;
    while ((!fs.existsSync(startsPath) || fs.readFileSync(startsPath, "utf8").trim().split(/\r?\n/).length < 2) && Date.now() < childReadyDeadline) {
      spawnSync(process.execPath, ["-e", "setTimeout(()=>{},300)"], { timeout: 1000 });
    }
    assert.ok(fs.existsSync(startsPath), "fixture child did not write startup receipt");
    const startsBefore = fs.readFileSync(startsPath, "utf8").trim().split(/\r?\n/).length;
    assert.ok(startsBefore >= 2, "restarted child did not write startup receipt");
    fs.writeFileSync(path.join(serviceConfigDir, "fixture-exit-code.txt"), "17");
    const recoveryDeadline = Date.now() + 30000;
    let recovered = false;
    while (Date.now() < recoveryDeadline) {
      const startsNow = fs.readFileSync(startsPath, "utf8").trim().split(/\r?\n/).length;
      if (startsNow > startsBefore && getServiceStatus() === "RUNNING") { recovered = true; break; }
      spawnSync(process.execPath, ["-e", "setTimeout(()=>{},300)"], { timeout: 1000 });
    }
    assert.ok(recovered, "SCM did not recover the host after child exit 17");
    const startsAfterRecovery = fs.readFileSync(startsPath, "utf8");
    fs.writeFileSync(path.join(serviceConfigDir, "fixture-exit-code.txt"), "86");
    assert.ok(waitForStatus("STOPPED", 15000), "retired exit 86 did not stop the service");
    // More than four times the configured recovery delay: verify the
    // successful retired exit did not accidentally schedule a restart.
    spawnSync(process.execPath, ["-e", "setTimeout(()=>{},5000)"], { timeout: 6000 });
    assert.equal(getServiceStatus(), "STOPPED", "SCM restarted a retired agent");
    assert.equal(fs.readFileSync(startsPath, "utf8"), startsAfterRecovery, "exit 86 created another child");
    // Real shipped entrypoint failure through SCM: disable automatic recovery
    // first so malformed configuration cannot create an unbounded restart loop.
    const noRecovery = spawnSync("sc.exe", ["failure", SERVICE_NAME, "reset=", "60", "actions=", ""], { encoding: "utf8" });
    assert.equal(noRecovery.status, 0, "could not disable owned service recovery");
    const configPath = path.join(serviceConfigDir, "config.json");
    const stateMarker = path.join(serviceConfigDir, "qualification-existing-state");
    fs.writeFileSync(stateMarker, "existing-state-preserved");
    fs.writeFileSync(configPath, "{");
    const shippedEntry = path.join(packageRoot, "bin", "tokentimer-agent.js");
    const badConfigPath = `${quotedHost} ${quotedNode} "${shippedEntry}"`;
    const badConfig = spawnSync("sc.exe", ["config", SERVICE_NAME, "binPath=", badConfigPath], { encoding: "utf8" });
    assert.equal(badConfig.status, 0, "could not select shipped entrypoint for owned service");
    spawnSync("sc.exe", ["start", SERVICE_NAME], { encoding: "utf8" });
    const badConfigDeadline = Date.now() + 15000;
    const hostLog = path.join(serviceConfigDir, "host.log");
    let rejectedConfig = false;
    while (Date.now() < badConfigDeadline) {
      if (getServiceStatus() === "STOPPED" && fs.existsSync(hostLog) &&
          /failed to parse/.test(fs.readFileSync(hostLog, "utf8"))) { rejectedConfig = true; break; }
      spawnSync(process.execPath, ["-e", "setTimeout(()=>{},300)"], { timeout: 1000 });
    }
    assert.ok(rejectedConfig, "SCM must stop and retain explicit shipped configuration failure evidence");
    assert.equal(fs.readFileSync(stateMarker, "utf8"), "existing-state-preserved");
    // Recovery uses the real configuration loader followed by the bounded
    // supporting child. This proves service/config repair, not API registration.
    fs.writeFileSync(configPath, JSON.stringify({ serverUrl: "https://127.0.0.1:1" }));
    const repairedEntry = path.join(serviceConfigDir, "repaired-config-child.js");
    fs.writeFileSync(repairedEntry, `require(${JSON.stringify(path.join(packageRoot, "src/config"))}).loadAgentConfig();require(${JSON.stringify(mockAgentJs)});`);
    const repairedPath = `${quotedHost} ${quotedNode} "${repairedEntry}"`;
    assert.equal(spawnSync("sc.exe", ["config", SERVICE_NAME, "binPath=", repairedPath], { encoding: "utf8" }).status, 0);
    assert.equal(spawnSync("sc.exe", ["start", SERVICE_NAME], { encoding: "utf8" }).status, 0);
    assert.ok(waitForStatus("RUNNING", 15000), "repaired owned service did not recover");
    const repairedDeadline = Date.now() + 15000;
    while (fs.readFileSync(startsPath, "utf8") === startsAfterRecovery && Date.now() < repairedDeadline) {
      spawnSync(process.execPath, ["-e", "setTimeout(()=>{},300)"], { timeout: 1000 });
    }
    assert.notEqual(fs.readFileSync(startsPath, "utf8"), startsAfterRecovery, "repaired loader never reached the supporting child");
    assert.equal(fs.readFileSync(stateMarker, "utf8"), "existing-state-preserved");
    assert.equal(spawnSync("sc.exe", ["stop", SERVICE_NAME], { encoding: "utf8" }).status, 0);
    assert.ok(waitForStatus("STOPPED", 15000));
    // Run the actual product uninstall logic with only its fixed resource
    // selectors mapped to this disposable fixture. No released configuration
    // changes or production service paths are needed to test preservation.
    const originalInstaller = fs.readFileSync(path.join(__dirname, "install-agent.ps1"), "utf8");
    const originalRoot = '$InstallRoot = "C:\\ProgramData\\TokenTimerAgent"';
    const originalService = '$ServiceName = "TokenTimerAgent"';
    assert.ok(originalInstaller.includes(originalRoot));
    assert.ok(originalInstaller.includes(originalService));
    const installerFixture = path.join(serviceConfigDir, "qualification-uninstall.ps1");
    fs.writeFileSync(installerFixture, "\uFEFF" + originalInstaller
      .replace(originalRoot, `$InstallRoot = '${serviceConfigDir.replace(/'/g, "''")}'`)
      .replace(originalService, `$ServiceName = '${SERVICE_NAME}'`));
    const preservedState = path.join(serviceConfigDir, "state");
    const removedApp = path.join(serviceConfigDir, "app");
    fs.mkdirSync(preservedState);
    fs.mkdirSync(removedApp);
    const marker = "disposable-state-preservation-marker";
    fs.writeFileSync(path.join(preservedState, "credential.fixture"), marker);
    fs.writeFileSync(path.join(removedApp, "candidate.fixture"), "owned disposable app marker");
    for (let replay = 0; replay < 2; replay++) {
      const uninstall = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", installerFixture, "--uninstall"], { encoding: "utf8", timeout: 60000 });
      assert.equal(uninstall.status, 0, "product fixture uninstall failed");
      const deletionDeadline = Date.now() + 15000;
      while (getServiceStatus() !== null && Date.now() < deletionDeadline) {
        spawnSync(process.execPath, ["-e", "setTimeout(()=>{},300)"], { timeout: 1000 });
      }
      assert.equal(getServiceStatus(), null, "product uninstall must delete its owned service");
      assert.equal(fs.existsSync(removedApp), false);
      assert.equal(fs.readFileSync(path.join(preservedState, "credential.fixture"), "utf8"), marker);
    }
  });
});
