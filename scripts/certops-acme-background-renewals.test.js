"use strict";
// Offline proof/observer controls only; no worker, native service or CA is run.
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  path = require("node:path");
const r = require("../tests/e2e/helpers/certops-acme-background-runner");
const h = require("../tests/e2e/helpers/certops-acme-background-renewals");
function lifecycle() {
  return {
    failed: false,
    starts: 1,
    tickElapsedMs: [30000, 90000],
    finishes: 2,
    summaries: 2,
    created: 2,
    stops: 1,
    exitCode: 0,
    groupDrained: true,
    closed: true,
    pidfdPinnedBeforeExec: true,
    pidfdSignalUsed: true,
    pidfdClosed: true,
    workerWaited: true,
  };
}
function proof() {
  return {
    scope: h.SCOPE,
    client: "certbot",
    schedulerInvocation: "actual-production-runner-default-cron",
    successfulAutomationCycles: 2,
    sourceProfileId: "12345678-1234-1234-1234-123456789abc",
    sourceProfileFingerprint: "a".repeat(64),
    jobIds: [
      "12345678-1234-1234-1234-123456789abc",
      "22345678-1234-1234-1234-123456789abc",
    ],
    fingerprints: ["a", "b", "c"].map((x) => x.repeat(64)),
    serials: ["A1", "B2", "C3"],
    spkiFingerprints: ["d", "e", "f"].map((x) => x.repeat(64)),
    expiryEpochs: [1000, 2000, 3000],
    workerLifecycle: lifecycle(),
    ...Object.fromEntries(h.FLAGS.map((key) => [key, true])),
  };
}
test("worker environment inherits only explicit connection keys and omits scheduling overrides", () => {
  const supplied = {
    DB_HOST: "owned",
    DB_PORT: "5432",
    DB_NAME: "owned",
    DB_USER: "owned",
    DB_PASSWORD: "private",
    CERTOPS_SIGNING_ENCRYPTION_KEY: "a".repeat(64),
    CERTOPS_REGISTRATION_ENCRYPTION_KEY: "b".repeat(64),
    UNRELATED_SECRET: "must-not-inherit",
    NODE_OPTIONS: "--require untrusted",
    WORKER_CERTOPS_CRON: "* * * * *",
    WORKER_CERTOPS_INTERVAL_MS: "1",
    WORKER_CERTOPS_RUN_ON_START: "true",
    WORKER_RUN_ONCE: "true",
  };
  const env = r.environment(supplied, "1".repeat(32));
  assert.equal(env.DB_PASSWORD, "private");
  for (const key of [
    "UNRELATED_SECRET",
    "NODE_OPTIONS",
    "WORKER_CERTOPS_CRON",
    "WORKER_CERTOPS_INTERVAL_MS",
    "WORKER_CERTOPS_RUN_ON_START",
    "WORKER_RUN_ONCE",
  ])
    assert.equal(Object.hasOwn(env, key), false);
  assert.equal(env.NODE_ENV, "production");
});
test("only real default cron lifecycle events qualify two successful cycles", () => {
  const state = {
    failed: false,
    starts: 0,
    tickElapsedMs: [],
    finishes: 0,
    summaries: 0,
    created: 0,
    stops: 0,
    exitCode: 0,
    groupDrained: true,
    closed: true,
    pidfdPinnedBeforeExec: true,
    pidfdSignalUsed: true,
    pidfdClosed: true,
    workerWaited: true,
  };
  r.observeRecord(
    state,
    {
      message: "worker-runner-worker-started",
      worker: "certops",
      scheduleMode: "cron",
      cronExpression: "*/1 * * * *",
      runOnStart: false,
    },
    0,
  );
  for (const at of [30000, 90000]) {
    r.observeRecord(
      state,
      {
        message: "worker-runner-job-start",
        worker: "certops",
        trigger: "cron",
      },
      at,
    );
    r.observeRecord(
      state,
      {
        message: "CertOps maintenance worker finished",
        renewalScheduler: { created: 1, errors: [] },
      },
      at + 10,
    );
    r.observeRecord(
      state,
      {
        message: "worker-runner-job-finish",
        worker: "certops",
        trigger: "cron",
      },
      at + 20,
    );
  }
  r.observeRecord(
    state,
    { message: "worker-runner-stopping", signal: "SIGTERM" },
    90030,
  );
  assert.equal(r.validateLifecycle(state), true);
  assert.throws(() =>
    r.observeRecord(
      { ...state },
      {
        message: "worker-runner-worker-started",
        worker: "certops",
        scheduleMode: "interval",
        intervalMs: 60000,
        runOnStart: false,
      },
      0,
    ),
  );
  for (const patch of [
    { tickElapsedMs: [1, 2] },
    { stops: 0 },
    { created: 1 },
    { closed: false },
    { groupDrained: false },
    { failed: true },
  ])
    assert.throws(() => r.validateLifecycle({ ...state, ...patch }));
});
test("closed native proof rejects every missing field, duplicate generation and broader scope", () => {
  assert.equal(h.verifyProof(proof()), true);
  for (const key of Object.keys(proof())) {
    const value = proof();
    delete value[key];
    assert.throws(() => h.verifyProof(value), key);
  }
  for (const patch of [
    { schedulerInvocation: "manual-sweep" },
    { successfulAutomationCycles: 1 },
    { fingerprints: ["a".repeat(64), "a".repeat(64), "b".repeat(64)] },
    { spkiFingerprints: ["a".repeat(64), "a".repeat(64), "b".repeat(64)] },
    { expiryEpochs: [1000, 1000, 3000] },
    { foreign: true },
  ])
    assert.throws(() => h.verifyProof({ ...proof(), ...patch }));
  const sameId = proof();
  sameId.jobIds = [
    "abcdefab-1234-1234-1234-123456789abc",
    "ABCDEFAB-1234-1234-1234-123456789ABC",
  ];
  assert.throws(() => h.verifyProof(sameId));
  for (const key of h.FLAGS)
    assert.throws(() => h.verifyProof({ ...proof(), [key]: false }));
});
test("a durable unresolved worker marker blocks parent private-state cleanup", () => {
  const root = fs.mkdtempSync(
    path.join(os.tmpdir(), "certops-acme-worker-guard-"),
  );
  const marker = path.join(root, ".preserve-acme-background-worker-owned.json");
  try {
    fs.writeFileSync(marker, "{}", { flag: "wx" });
    assert.throws(() => r.assertCleanupSafe(root));
    fs.unlinkSync(marker);
    r.assertCleanupSafe(root);
  } finally {
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
    fs.rmdirSync(root);
  }
});
// Execute the actual parent finally body with inert resources. This regression
// catches an early worker-error throw that would strand independent consumers,
// as well as any database/private deletion before the combined safety barrier.
test("parent drains independent consumers but preserves records on worker or browser uncertainty", async () => {
  const source = fs
    .readFileSync(
      path.resolve(__dirname, "../tests/e2e/acme-real-journey.js"),
      "utf8",
    )
    .replace(/\r\n/g, "\n");
  const start = source.indexOf("\n  finally {\n") + "\n  finally {\n".length,
    end = source.lastIndexOf("\n  }\n};");
  assert.ok(start > 20 && end > start);
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
  const names = [
    "ownedWorkers",
    "ownedBrowserResources",
    "primaryError",
    "tlsServer",
    "ownedTlsSockets",
    "agent",
    "gateway",
    "pool",
    "workspaceId",
    "ownedJobIds",
    "ownedCertificateIds",
    "publicSession",
    "barrierDirectory",
    "workDir",
    "fs",
    "path",
    "os",
    "assert",
    "waitUntil",
    "require",
    "repoRoot",
  ];
  const run = new AsyncFunction(...names, source.slice(start, end));
  for (const state of [
    { worker: false, browser: false, closeFails: false },
    { worker: true, browser: false, closeFails: false },
    { worker: false, browser: true, closeFails: false },
    { worker: true, browser: true, closeFails: false },
    { worker: false, browser: false, closeFails: true },
  ]) {
    const unresolved = state.worker || state.browser || state.closeFails;
    const calls = [];
    const agent = {
      exitCode: null,
      signalCode: null,
      kill(signal) {
        calls.push("agent-" + signal);
        if (signal === "SIGTERM") this.exitCode = 0;
        return true;
      },
    };
    const worker = {
      async stopAndDrain() {
        calls.push("worker");
        if (state.worker) throw Error("controlled unknown worker");
      },
    };
    const tlsServer = {
      close(callback) {
        calls.push("tls");
        callback();
      },
    };
    let browserClosed = false;
    const browser = {
      async close() {
        calls.push("browser");
        if (state.closeFails) throw Error("controlled browser closure failure");
        browserClosed = true;
      },
      hasLiveChild: () => !browserClosed,
      hasOwnershipReceipt: () => !browserClosed || state.browser,
      assertCleanupSafe() {
        calls.push("browser-guard");
        assert.equal(browserClosed, true);
        assert.equal(state.browser, false);
      },
    };
    const values = [
      [worker],
      [browser],
      null,
      tlsServer,
      new Set(),
      agent,
      {
        async close() {
          calls.push("proxy");
        },
      },
      {
        async query() {
          calls.push("database");
          return { rows: [] };
        },
      },
      "owned",
      ["job"],
      [],
      null,
      "/tmp/certops-real-acme-owned/barrier",
      "/tmp/certops-real-acme-owned",
      {
        readdirSync() {
          return [];
        },
        rmSync() {
          calls.push("private-delete");
        },
      },
      path,
      {
        tmpdir() {
          return "/tmp";
        },
      },
      assert,
      async (check) => {
        assert.equal(await check(), true);
      },
      () => ({
        assertCleanupSafe() {
          calls.push("guard");
          if (state.worker) throw Error("controlled unresolved marker");
        },
      }),
      "/owned-source",
    ];
    if (unresolved)
      await assert.rejects(run(...values), /preserve fixture state/);
    else await run(...values);
    for (const name of [
      "worker",
      "browser",
      "tls",
      "agent-SIGTERM",
      "proxy",
      "guard",
    ])
      assert.ok(calls.includes(name), name);
    assert.equal(calls.includes("database"), !unresolved);
    assert.equal(calls.includes("private-delete"), !unresolved);
    if (!unresolved) {
      assert.ok(calls.indexOf("database") > calls.indexOf("browser-guard"));
      assert.ok(calls.indexOf("database") > calls.indexOf("guard"));
    }
  }
});
