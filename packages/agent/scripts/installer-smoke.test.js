"use strict";

/**
 * B9 installer smoke test: package the agent, extract it OUTSIDE the monorepo,
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
 * Registers a *real* "TokenTimerAgent" service pointed at the built
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
  const SERVICE_NAME = "TokenTimerAgent";
  const REG_KEY = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${SERVICE_NAME}`;

  function isWindowsElevated() {
    if (process.platform !== "win32") return false;
    // `net session` requires Administrator and fails fast (no prompt) when
    // run unelevated; this is the standard no-dependency elevation probe.
    const probe = spawnSync("net", ["session"], { encoding: "utf8" });
    return probe.status === 0;
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

  before(() => {
    if (!isWindowsElevated()) {
      skipReason = "requires an elevated (Administrator) Windows process";
      return;
    }
    if (getServiceStatus() !== null) {
      // Refuse to touch a pre-existing service of this name: it could be
      // a real dev install on this machine, and this test deletes the
      // service it creates when done.
      skipReason = `a "${SERVICE_NAME}" service already exists on this host; skipping rather than risk clobbering it`;
      return;
    }

    const { main: buildWindowsServiceHost, hostBinaryName } = require("./build-windows-service-host.js");
    buildWindowsServiceHost();
    const goarch = process.arch === "arm64" ? "arm64" : "amd64";
    hostExe = path.join(packageRoot, "bin", hostBinaryName(goarch));
    assert.ok(fs.existsSync(hostExe), `expected built host binary at ${hostExe}`);

    mockAgentJs = path.join(packageRoot, "windows-service-host", "testdata", "mock-agent.js");
    assert.ok(fs.existsSync(mockAgentJs), `expected mock agent fixture at ${mockAgentJs}`);

    serviceConfigDir = fs.mkdtempSync(path.join(os.tmpdir(), "tokentimer-agent-svc-state-"));
  });

  after(() => {
    if (getServiceStatus() !== null) {
      // The test body's own final assertion leaves the service RUNNING
      // (it stops/starts it once to prove the restart cycle, then ends).
      // `sc.exe stop` only *requests* a stop and returns immediately - it
      // does not wait for the SCM to actually tear the process down - so
      // deleting serviceConfigDir right after it, with no wait, raced the
      // mock agent's own file handles on that directory and intermittently
      // failed cleanup with EPERM. Wait for STOPPED (bounded, same 15s
      // ceiling the test body itself uses) before deleting the service.
      if (getServiceStatus() !== "STOPPED") {
        spawnSync("sc.exe", ["stop", SERVICE_NAME], { encoding: "utf8" });
        waitForStatus("STOPPED", 15000);
      }
      spawnSync("sc.exe", ["delete", SERVICE_NAME], { encoding: "utf8" });
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

    // Mirrors Set-ServiceEnvironment in install-agent.ps1, including a
    // bootstrap-token-shaped value, so the Task 2 assertion below exercises
    // the exact registry shape the real installer produces.
    const setEnv = spawnSync("reg.exe", [
      "add", REG_KEY,
      "/v", "Environment",
      "/t", "REG_MULTI_SZ",
      "/d", `TOKENTIMER_AGENT_CONFIG_DIR=${serviceConfigDir}\\0TOKENTIMER_AGENT_BOOTSTRAP_TOKEN=ttboot_smoketest`,
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
    const scrubResult = clearWindowsServiceBootstrapToken({ configDir: serviceConfigDir });
    assert.deepEqual(scrubResult, { attempted: true, cleared: true });

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
  });
});
