"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { assertComposeWorkerStates } = require("../../scripts/lib/compose-worker-status");

const root = path.resolve(__dirname, "../..");
const id = "a".repeat(64);
const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "bash";
const slash = (value) => value.replace(/\\/g, "/");

function runController({ state = { Status: "exited", ExitCode: 1 },
  suiteExit = 0, listFailure = false, empty = false, service = "worker-endpoint-check" } = {}) {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "core-compose-worker-"));
  try {
    for (const directory of ["scripts/lib", "deploy/compose"]) {
      fs.mkdirSync(path.join(fixtureRoot, directory), { recursive: true });
    }
    fs.copyFileSync(path.join(root, "scripts/lib/compose-worker-status.js"),
      path.join(fixtureRoot, "scripts/lib/compose-worker-status.js"));
    fs.writeFileSync(path.join(fixtureRoot, ".env.test"), "# Synthetic controller fixture\n");
    fs.writeFileSync(path.join(fixtureRoot, "deploy/compose/docker-compose.test.yml"), "services: {}\n");
    const inspection = path.join(fixtureRoot, "inspection.json");
    fs.writeFileSync(inspection, JSON.stringify([{ Id: id,
      Config: { Labels: { "com.docker.compose.service": service } }, State: state }]));
    const events = path.join(fixtureRoot, "events.log");
    fs.writeFileSync(events, "");
    const preload = path.join(fixtureRoot, "transport.cjs");
    fs.writeFileSync(preload, `
const fs = require("node:fs");
require("node:child_process").spawnSync = (command, args) => {
  if (command !== "docker") throw new Error("Unexpected fixture command");
  if (args[0] === "compose" && args.includes("ps")) {
    fs.appendFileSync(process.env.TT_FIXTURE_EVENTS, "list\\n");
    return { status: process.env.TT_FIXTURE_LIST_FAILURE === "1" ? 1 : 0,
      stdout: process.env.TT_FIXTURE_EMPTY === "1" ? "" : process.env.TT_FIXTURE_ID };
  }
  if (args[0] === "inspect") {
    fs.appendFileSync(process.env.TT_FIXTURE_EVENTS, "inspect\\n");
    return { status: 0, stdout: fs.readFileSync(process.env.TT_FIXTURE_INSPECTION, "utf8") };
  }
  throw new Error("Unexpected fixture Docker command");
};
`);
    const transportFunctions = `
docker() {
  case "$4" in
    down) echo cleanup >> "$TT_FIXTURE_EVENTS" ;;
    logs) echo "synthetic Docker log" ;;
  esac
  return 0
}
node() {
  case "$1" in
    */scripts/lib/compose-worker-status.js)
      NODE_OPTIONS="--require=\\\"$TT_FIXTURE_PRELOAD\\\"" "$TT_FIXTURE_NODE" "$@" ;;
    scripts/run-unit-tests.js) return 0 ;;
    scripts/run-integration-suite.js) return "$TT_FIXTURE_SUITE_EXIT" ;;
    -e) return 0 ;;
    *) echo "Unexpected node command: $1" >&2; return 99 ;;
  esac
}
pnpm() { return 0; }
curl() { return 0; }
`;
    const controller = fs.readFileSync(path.join(root, "scripts/run-tests.sh"), "utf8");
    fs.writeFileSync(path.join(fixtureRoot, "scripts/run-tests.sh"),
      controller.replace(/^(#![^\n]*\n)/, (shebang) => shebang + transportFunctions));
    const result = spawnSync(bash, ["scripts/run-tests.sh"], {
      cwd: fixtureRoot,
      encoding: "utf8",
      timeout: 20000,
      env: { ...process.env,
        TT_SKIP_COMPOSE_BUILD: "1",
        TT_FIXTURE_NODE: slash(process.execPath),
        TT_FIXTURE_PRELOAD: slash(preload),
        TT_FIXTURE_EVENTS: slash(events),
        TT_FIXTURE_INSPECTION: slash(inspection),
        TT_FIXTURE_ID: id,
        TT_FIXTURE_SUITE_EXIT: String(suiteExit),
        TT_FIXTURE_LIST_FAILURE: listFailure ? "1" : "0",
        TT_FIXTURE_EMPTY: empty ? "1" : "0",
      },
    });
    assert.ifError(result.error);
    return { status: result.status, stdout: result.stdout, stderr: result.stderr,
      events: fs.readFileSync(events, "utf8").trim().split(/\r?\n/) };
  } finally {
    const resolvedFixture = path.resolve(fixtureRoot);
    assert.equal(path.dirname(resolvedFixture), path.resolve(os.tmpdir()));
    assert.match(path.basename(resolvedFixture), /^core-compose-worker-/);
    const fixtureStat = fs.lstatSync(resolvedFixture);
    assert.ok(fixtureStat.isDirectory() && !fixtureStat.isSymbolicLink());
    fs.rmSync(resolvedFixture, { recursive: true, force: true });
  }
}

test("the actual Bash controller fails a fatal worker after successful suites and still cleans up", () => {
  const result = runController();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /worker-endpoint-check/, result.stdout);
  assert.ok(result.events.includes("inspect"));
  assert.ok(result.events.indexOf("inspect") < result.events.lastIndexOf("cleanup"));
  assert.match(result.stdout, /Combined\s+:/);
});

test("the actual Bash controller preserves suite failures and cleanup when inspection fails", () => {
  const result = runController({ suiteExit: 7, listFailure: true });
  assert.equal(result.status, 7, result.stdout + result.stderr);
  assert.ok(result.events.includes("list"));
  assert.equal(result.events.at(-1), "cleanup");
});

test("the actual Bash controller fails closed on inspection errors after successful suites", () => {
  const result = runController({ listFailure: true });
  assert.equal(result.status, 1);
  assert.equal(result.events.at(-1), "cleanup");
});

test("successful running, completed and absent workers remain allowed by the actual controller", () => {
  for (const options of [
    { state: { Status: "running", ExitCode: 0 } },
    { state: { Status: "exited", ExitCode: 0 } },
    { empty: true },
    { service: "postgres" },
  ]) {
    const result = runController(options);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(result.events.at(-1), "cleanup");
  }
});

test("only this Compose file's container IDs and selected worker labels are inspected", () => {
  const composeFile = path.join(root, "deploy/compose/docker-compose.test.yml");
  const env = { SYNTHETIC_STATUS_PROBE: "1" };
  let calls = 0;
  assertComposeWorkerStates({ composeFile, cwd: root, env, run(command, args, options) {
    assert.equal(command, "docker");
    assert.equal(options.cwd, root);
    assert.equal(options.env, env);
    assert.equal(options.timeout, 15000);
    if (calls++ === 0) {
      assert.deepEqual(args, ["compose", "-f", composeFile, "ps", "--all", "--quiet"]);
      return { status: 0, stdout: id };
    }
    assert.deepEqual(args, ["inspect", id]);
    return { status: 0, stdout: JSON.stringify([
      { Id: "b".repeat(64), Config: { Labels: { "com.docker.compose.service": "worker-delivery" } }, State: { Status: "exited", ExitCode: 1 } },
      { Id: id, Config: { Labels: { "com.docker.compose.service": "postgres" } }, State: { Status: "exited", ExitCode: 1 } },
    ]) };
  } });
  assert.equal(calls, 2);
  assertComposeWorkerStates({ composeFile, workerServices: [], run() { assert.fail("No worker selection must not query Docker"); } });
});

test("each worker rejects nonzero exits, OOM and dead states", () => {
  for (const service of ["worker-endpoint-check", "worker-auto-sync", "worker-delivery"]) {
    for (const state of [
      { Status: "exited", ExitCode: 1 },
      { Status: "exited", ExitCode: 0, OOMKilled: true },
      { Status: "dead", ExitCode: 0 },
    ]) {
      assert.throws(() => assertComposeWorkerStates({ composeFile: "synthetic-compose.yml", run(command, args) {
        return args[0] === "compose" ? { status: 0, stdout: id } : { status: 0,
          stdout: JSON.stringify([{ Id: id, Config: { Labels: { "com.docker.compose.service": service } }, State: state }]) };
      } }), /Compose worker failure/);
    }
  }
});
