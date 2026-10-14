/**
 * Regression coverage: native cohort cleanup awaits an owned live child before state may be removed.
 * Local fixtures verify this contract; measured native/environment execution
 * is tracked separately in the qualification suites and their reports.
 */
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const { once } = require("node:events");
const {
  stopOwnedPreflightAgent,
} = require("../e2e/helpers/certops-adcs-preflight-cohorts");

test("native cohort cleanup awaits an owned live child before state may be removed", async () => {
  const child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
    stdio: "ignore",
  });
  try {
    await once(child, "spawn");
    await stopOwnedPreflightAgent(child);
    assert.ok(child.exitCode !== null || child.signalCode !== null);
  } finally {
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
  }
});
test("native cohort cleanup is idempotent after normal child exit", async () => {
  const child = spawn(process.execPath, ["-e", "process.exitCode=0"], {
    stdio: "ignore",
  });
  await once(child, "exit");
  await stopOwnedPreflightAgent(child);
  assert.equal(child.exitCode, 0);
});
test("native cohort cleanup recognizes an already signalled child without awaiting a lost event", async () => {
  const child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
    stdio: "ignore",
  });
  await once(child, "spawn");
  const exited = once(child, "exit");
  child.kill("SIGKILL");
  await exited;
  await stopOwnedPreflightAgent(child);
  assert.ok(child.exitCode !== null || child.signalCode !== null);
});

test("failed spawn with no native PID never waits for an exit event that cannot occur", async () => {
  const path = require("node:path"),
    os = require("node:os"),
    crypto = require("node:crypto");
  const child = spawn(
    path.join(os.tmpdir(), `missing-certops-${crypto.randomUUID()}.exe`),
    [],
    { stdio: "ignore" },
  );
  await once(child, "error");
  assert.equal(child.pid, undefined);
  await stopOwnedPreflightAgent(child, { graceMs: 1, killMs: 1 });
});
test("owned process-tree termination hook is awaited before cleanup can proceed", async () => {
  const child = spawn(process.execPath, ["-e", "setInterval(()=>{},1000)"], {
    stdio: "ignore",
  });
  await once(child, "spawn");
  let invoked = false;
  try {
    await stopOwnedPreflightAgent(child, {
      terminateTree: () => {
        invoked = true;
        child.kill("SIGKILL");
      },
    });
    assert.equal(invoked, true);
    assert.ok(child.exitCode !== null || child.signalCode !== null);
  } finally {
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
  }
});
test("a child without exit proof fails bounded cleanup instead of authorizing state deletion", async () => {
  const { EventEmitter } = require("node:events");
  const child = Object.assign(new EventEmitter(), {
    pid: 42,
    exitCode: null,
    signalCode: null,
    kill() {
      return true;
    },
  });
  await assert.rejects(
    stopOwnedPreflightAgent(child, { graceMs: 2, killMs: 2 }),
    /did not exit/,
  );
  assert.equal(child.listenerCount("exit"), 0);
});
test("native child identity refuses foreign PID parent executable account or process token", () => {
  const {
    validateNativeChildIdentity,
  } = require("../e2e/helpers/certops-adcs-preflight-cohorts");
  const expected = {
    pid: 42,
    parentPid: 19,
    executablePath: "C:\\node\\node.exe",
    entry: "C:\\candidate\\agent.js",
    token: "certops-preflight-owned-uuid",
  };
  const identity = {
    ...expected,
    sid: "S-1-5-18",
    creationTime: "2026-10-14T01:00:00.000Z",
    commandLine: `${expected.executablePath} --title=${expected.token} ${expected.entry}`,
  };
  assert.equal(validateNativeChildIdentity(identity, expected), identity);
  for (const changed of [
    { pid: 43 },
    { parentPid: 1 },
    { sid: "S-1-5-21-foreign" },
    { creationTime: "unknown" },
    { executablePath: "C:\\foreign\\node.exe" },
    { commandLine: "foreign process" },
  ])
    assert.throws(() =>
      validateNativeChildIdentity({ ...identity, ...changed }, expected),
    );
});
test("cohort environment forwards bootstrap only on first start and excludes unrelated secrets", () => {
  const {
    nativePreflightEnvironment,
  } = require("../e2e/helpers/certops-adcs-preflight-cohorts");
  const source = {
    PATH: "qualified-tools",
    SystemRoot: "C:\\Windows",
    NODE_EXTRA_CA_CERTS: "public-root.pem",
    DB_PASSWORD: "private-db",
    CERTOPS_SIGNING_ENCRYPTION_KEY: "private-signing-key",
    CERTOPS_ADCS_OFFICER_PASSWORD: "private-officer",
    NODE_OPTIONS: "unrelated-runtime-option",
  };
  const initial = nativePreflightEnvironment(source, "owned-state", {
    plaintextToken: "owned-bootstrap",
    token: { id: "owned-id" },
  });
  assert.equal(initial.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN, "owned-bootstrap");
  assert.equal(initial.NODE_EXTRA_CA_CERTS, "public-root.pem");
  for (const name of [
    "DB_PASSWORD",
    "CERTOPS_SIGNING_ENCRYPTION_KEY",
    "CERTOPS_ADCS_OFFICER_PASSWORD",
    "NODE_OPTIONS",
  ])
    assert.equal(initial[name], undefined);
  const restarted = nativePreflightEnvironment(source, "owned-state");
  assert.equal(restarted.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN, undefined);
  assert.equal(restarted.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID, undefined);
});

test("native containment must drain and release ownership before cohort state removal", async () => {
  const {
    stopContainedCohort,
  } = require("../e2e/helpers/certops-adcs-preflight-cohorts");
  let calls = 0;
  await assert.rejects(
    stopContainedCohort({ child: { pid: 42 } }),
    /Missing native containment/,
  );
  await stopContainedCohort({
    containment: {
      stopAndDrain() {
        calls++;
        return Promise.resolve();
      },
      hasOwnershipReceipt() {
        return false;
      },
    },
  });
  assert.equal(calls, 1);
  await assert.rejects(
    stopContainedCohort({
      containment: {
        stopAndDrain() {
          return Promise.reject(new Error("Retained job drainage unknown"));
        },
        hasOwnershipReceipt() {
          return false;
        },
      },
    }),
    /drainage unknown/,
  );
  await assert.rejects(
    stopContainedCohort({
      containment: {
        stopAndDrain() {
          return Promise.resolve();
        },
        hasOwnershipReceipt() {
          return true;
        },
      },
    }),
    /fully drain/,
  );
});
