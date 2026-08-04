#!/usr/bin/env node
"use strict";

// `pnpm verify:deploy`, the second ("needs a real Postgres + API stack")
// tier of local CI parity, next to the first, static tier
// `pnpm verify:ci-guards` (scripts/ci-guards/run-all.cjs, no live infra).
// Together they are wired as `pnpm verify` in package.json.
//
// This is a Node script, not a shell script, for the same reason the
// ci-guards are `.cjs` instead of `.sh`: Windows is this repo's primary
// target platform, and scripts/run-tests.sh (bash) is not something a
// Windows-native contributor can run without installing a bash (Git
// Bash/WSL). This script does the same docker-compose lifecycle
// (down --volumes for a clean slate, up --build -d, wait for the API to
// answer, run tests, down --volumes unconditionally afterwards) using only
// `docker` (already required for local dev) and `node`.
//
// It deliberately does NOT shell out to `pnpm run test:ci` / `bash
// scripts/run-tests.sh`: that script owns its own compose up/down cycle
// internally and does not run the e2e agent suite, and nesting two
// independent compose lifecycles (this script's, and run-tests.sh's) would
// mean the stack gets torn down by run-tests.sh's own EXIT trap before this
// script's e2e step ever ran against it. Instead this script manages the
// compose lifecycle exactly once and then calls the same underlying
// scripts run-tests.sh and `pnpm test:e2e:agent` already call, so the
// actual test logic is reused, not reinvented:
//   - scripts/run-unit-tests.js       (same as `pnpm test:unit`)
//   - scripts/run-integration-suite.js core  (same "core" suite
//     run-tests.sh runs after its own compose up)
//   - tests/e2e/certops-agent-e2e.test.js    (same as `pnpm test:e2e:agent`)

const path = require("node:path");
const http = require("node:http");
const { spawnSync } = require("node:child_process");

const { loadEnvFile } = require("./load-root-env");

const repoRoot = path.resolve(__dirname, "..");
const composeFile = path.join(
  repoRoot,
  "deploy",
  "compose",
  "docker-compose.test.yml",
);
const isWindows = process.platform === "win32";

const API_HEALTH_MAX_WAIT_MS = 60_000;
const API_HEALTH_POLL_INTERVAL_MS = 2_000;

function log(message) {
  console.log(`[verify:deploy] ${message}`);
}

function loadTestEnv() {
  // Reuses scripts/load-root-env.js's exact .env parser (quote/escape
  // handling, inline-comment stripping) against .env.test instead of
  // .env, and never overrides a variable the caller already set.
  const envPath = path.join(repoRoot, ".env.test");
  const loaded = loadEnvFile(envPath);
  if (!loaded) {
    throw new Error(
      `${envPath} not found; cannot configure the test stack (see scripts/run-tests.sh, which requires the same file).`,
    );
  }
}

function runComposeSync(args, { allowFailure = false } = {}) {
  log(`docker compose ${args.join(" ")}`);
  const result = spawnSync(
    "docker",
    ["compose", "-f", composeFile, ...args],
    {
      cwd: repoRoot,
      stdio: "inherit",
      shell: isWindows,
      env: process.env,
    },
  );
  if (result.error) throw result.error;
  if (!allowFailure && result.status !== 0) {
    throw new Error(
      `docker compose ${args.join(" ")} exited with code ${result.status}`,
    );
  }
  return result.status || 0;
}

function composeDown() {
  // allowFailure: a teardown call must never itself throw, or a failure
  // here would mask the real test failure / leave the finally block
  // looking like it didn't run.
  runComposeSync(["down", "--volumes", "--remove-orphans"], {
    allowFailure: true,
  });
}

function composeUp() {
  const skipBuild =
    process.env.TT_SKIP_COMPOSE_BUILD === "1" ||
    process.env.TT_SKIP_COMPOSE_BUILD === "true";
  runComposeSync(skipBuild ? ["up", "-d"] : ["up", "--build", "-d"]);
}

function httpGetOk(url) {
  return new Promise((resolve) => {
    const req = http.get(url, (res) => {
      res.resume();
      resolve(res.statusCode >= 200 && res.statusCode < 500);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(3000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForApiHealthy() {
  const url = process.env.TEST_API_URL || "http://localhost:4000";
  log(`waiting for API at ${url} ...`);
  const deadline = Date.now() + API_HEALTH_MAX_WAIT_MS;
  for (;;) {
    if (await httpGetOk(url)) {
      log("API is ready.");
      return;
    }
    if (Date.now() >= deadline) {
      runComposeSync(["logs", "api"], { allowFailure: true });
      throw new Error(
        `API did not become ready at ${url} within ${API_HEALTH_MAX_WAIT_MS}ms`,
      );
    }
    await sleep(API_HEALTH_POLL_INTERVAL_MS);
  }
}

function runNodeScript(relScriptPath, args = []) {
  const abs = path.join(repoRoot, relScriptPath);
  log(`running ${relScriptPath} ${args.join(" ")}`.trim());
  const result = spawnSync(process.execPath, [abs, ...args], {
    cwd: repoRoot,
    stdio: "inherit",
    env: process.env,
  });
  if (result.error) throw result.error;
  return typeof result.status === "number" ? result.status : 1;
}

function runNodeTest(relTestPath) {
  const abs = path.join(repoRoot, relTestPath);
  log(`running node --test ${relTestPath}`);
  const result = spawnSync(process.execPath, ["--test", abs], {
    cwd: repoRoot,
    stdio: "inherit",
    env: process.env,
  });
  if (result.error) throw result.error;
  return typeof result.status === "number" ? result.status : 1;
}

// Returns the process exit code rather than calling process.exit itself:
// an early `return` from inside a try block still runs its `finally`
// (needed for the unconditional teardown below), but a `return`/`process.exit`
// written *inside* that try would either skip code after the try/finally or
// exit before the finally's teardown could run. Returning a plain value and
// letting the caller call process.exit once, after main() resolves, avoids
// both failure modes.
async function main() {
  loadTestEnv();

  log("tearing down any leftover test stack before starting...");
  composeDown();

  try {
    composeUp();
    await waitForApiHealthy();

    let exitCode = runNodeScript(path.join("scripts", "run-unit-tests.js"));
    if (exitCode !== 0) {
      log(`unit tests failed with exit code ${exitCode}; stopping.`);
      return exitCode;
    }

    exitCode = runNodeScript(
      path.join("scripts", "run-integration-suite.js"),
      ["core"],
    );
    if (exitCode !== 0) {
      log(`integration suite failed with exit code ${exitCode}; stopping.`);
      return exitCode;
    }

    exitCode = runNodeTest(path.join("tests", "e2e", "certops-agent-e2e.test.js"));
    if (exitCode !== 0) {
      log(`e2e agent suite failed with exit code ${exitCode}; stopping.`);
    }
    return exitCode;
  } catch (err) {
    console.error(`[verify:deploy] ${err.message}`);
    return 1;
  } finally {
    log("tearing down the test stack (unconditional)...");
    composeDown();
  }
}

main().then((exitCode) => process.exit(exitCode));
