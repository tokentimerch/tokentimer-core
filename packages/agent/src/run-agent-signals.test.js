"use strict";
/** Execute the actual runAgent runtime with its real polling loop and actual
 * process signal listeners. Only configuration, network/native startup and log
 * transport are controlled; no service, CNG, certificate or API fixture runs. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
  os = require("node:os"),
  { EventEmitter } = require("node:events"),
  path = require("node:path"),
  vm = require("node:vm"),
  { createRequire } = require("node:module");
const entry = path.join(__dirname, "index.js"),
  realRequire = createRequire(entry);
function deferred() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
function runtime(platform, {
  failRegistration = false,
  configDir = path.join(__dirname, "nonexistent-signal-fixture"),
  execution = { enabled: false },
  moduleOverrides = {},
} = {}) {
  const heartbeat = deferred(),
    aborted = deferred(),
    drain = deferred(),
    releaseDrain = deferred();
  const originalProcess = process;
  const ownedProcess = new Proxy(process, {
    get(target, key) {
      if (key === "platform") return platform;
      if (key === "env") return {};
      const value = Reflect.get(target, key);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const config = {
    agentId: "actual-runtime-signal-fixture",
    serverUrl: "http://127.0.0.1",
    execution,
    heartbeatIntervalMs: 60000,
    pollIntervalMs: 60000,
    protocolVersion: "1.0",
    policy: {},
    dnsProviders: {},
    windowsDiscovery: { enabled: false },
    windows: { sweepIntervalMs: 60000, supersededRetentionHours: 24 },
  };
  const overrides = {
    "./config": {
      ...realRequire("./config"),
      resolveConfigDir: () => configDir,
      loadAgentConfig: () => config,
      readCredential: () =>
        failRegistration ? null : "public-supporting-credential",
      recoverPendingRegistration: () => null,
      clearRegistrationId: () => {},
      deleteBootstrapEnvFile: () => {},
      createSequenceAllocator: () => () => 1,
    },
    "./platform": { ...realRequire("./platform"), isWindows: () => false },
    "./job-journal": {
      ...realRequire("./job-journal"),
      scanUnresolvedJournalEntries: () => [],
    },
    "./issuers/adcs-enrollment-journal": {
      ...realRequire("./issuers/adcs-enrollment-journal"),
      listProtectedEnrollmentContainers: () => ({
        ok: true,
        containers: new Set(),
      }),
    },
    "./ntp": { checkNtpSynced: () => Promise.resolve(null) },
    "./logging": {
      ...realRequire("./logging"),
      defaultAgentLogger: { error() {} },
    },
    "./job-log-stream": {
      ...realRequire("./job-log-stream"),
      drainJobLogSessions: async () => {
        drain.resolve();
        await releaseDrain.promise;
      },
    },
    "./protocol": {
      ...realRequire("./protocol"),
      createProtocolClient: ({ signal }) => ({
        claim: async () => [],
        heartbeat: async () => {
          heartbeat.resolve();
          await new Promise((resolve) => {
            signal.addEventListener(
              "abort",
              () => {
                aborted.resolve();
                resolve();
              },
              { once: true },
            );
            if (signal.aborted) resolve();
          });
          return {};
        },
      }),
    },
  };
  const context = {
    module: { exports: {} },
    exports: {},
    require: (name) => moduleOverrides[name] || overrides[name] || realRequire(name),
    __dirname,
    __filename: entry,
    process: ownedProcess,
    console: { error() {}, log() {}, warn() {} },
    Buffer,
    AbortController,
    AbortSignal,
    URL,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    structuredClone,
  };
  vm.runInNewContext(fs.readFileSync(entry, "utf8"), context, {
    filename: entry,
  });
  return {
    run: context.module.exports.runAgent,
    heartbeat,
    aborted,
    drain,
    releaseDrain,
    originalProcess,
  };
}
for (const [platform, stopKind] of [
  ["win32", "SIGBREAK"],
  ["win32", "SIGINT"],
  ["win32", "SIGTERM"],
  ["win32", "external"],
  ["linux", "external"],
])
  test(
    `actual runAgent ${platform} ${stopKind} aborts transport, awaits drain and removes owned signal listeners`,
    { timeout: 10000 },
    async () => {
      const signals = ["SIGINT", "SIGTERM", "SIGBREAK"],
        before = Object.fromEntries(
          signals.map((s) => [s, process.listenerCount(s)]),
        ),
        r = runtime(platform),
        external = new AbortController();
      let finished = false;
      const running = r.run([], { signal: external.signal }).then(() => {
        finished = true;
      });
      try {
        await r.heartbeat.promise;
        assert.equal(
          process.listenerCount("SIGBREAK"),
          before.SIGBREAK + (platform === "win32" ? 1 : 0),
        );
        if (stopKind.startsWith("SIG"))
          assert.equal(process.emit(stopKind), true);
        else external.abort();
        await r.aborted.promise;
        await r.drain.promise;
        assert.equal(
          finished,
          false,
          "runtime must await real log drain phase",
        );
        r.releaseDrain.resolve();
        await running;
        for (const signal of signals)
          assert.equal(
            process.listenerCount(signal),
            before[signal],
            `owned ${signal} listener leaked`,
          );
      } finally {
        external.abort();
        r.releaseDrain.resolve();
        await running;
      }
    },
  );

for (const platform of ["win32", "linux"])
  test(`actual runAgent ${platform} registration failure removes every owned signal handler`, async () => {
    const signals = ["SIGINT", "SIGTERM", "SIGBREAK"],
      before = Object.fromEntries(
        signals.map((s) => [s, process.listenerCount(s)]),
      ),
      r = runtime(platform, { failRegistration: true });
    await assert.rejects(r.run([]), /no stored credential/);
    for (const signal of signals)
      assert.equal(process.listenerCount(signal), before[signal]);
  });
test("actual pre-aborted external signal never installs owned runtime handlers", async () => {
  const before = ["SIGINT", "SIGTERM", "SIGBREAK"].map((s) =>
      process.listenerCount(s),
    ),
    r = runtime("win32"),
    controller = new AbortController();
  controller.abort();
  await r.run([], { signal: controller.signal });
  assert.deepEqual(
    ["SIGINT", "SIGTERM", "SIGBREAK"].map((s) => process.listenerCount(s)),
    before,
  );
});

const maintenanceSteps = ["store lookup", "REQUEST cleanup", "survivor inventory", "key cleanup"];
const maintenanceEffects = ["pending request", "orphan key", "retention sweep"];
for (const { name, enabled, dryRun, preAborted, failRegistration, allowCleanup, interrupt, abortAfter } of [
  { name: "observe-only", enabled: false },
  { name: "dry-run", enabled: true, dryRun: true },
  { name: "real execution", enabled: true, dryRun: false, allowCleanup: true },
  { name: "pre-aborted", enabled: true, dryRun: false, preAborted: true },
  { name: "failed registration", enabled: true, dryRun: false, failRegistration: true },
  { name: "shutdown during the REQUEST lookup and restart", enabled: true, dryRun: false, interrupt: true },
  ...maintenanceSteps.map((step) => ({
    name: `shutdown after ${step} and restart`, enabled: true, dryRun: false, abortAfter: step,
  })),
]) {
  test(`actual runAgent applies Windows maintenance gate in ${name}`, { timeout: 30000 }, async (t) => {
    const configDir = fs.mkdtempSync(path.join(os.tmpdir(), "tt-cng-startup-"));
    t.after(() => fs.rmSync(configDir, { recursive: true, force: true }));
    const journal = realRequire("./job-journal");
    const containerName = "tokentimer-job-orphan-01";
    const thumbprint = "AB".repeat(20);
    const ids = { stateDir: configDir, jobId: "job-1", attemptId: "attempt-1" };
    journal.markSideEffectReached({ ...ids, stage: "keygen" });
    journal.recordWindowsCngContainer({ ...ids, containerName, store: "My" });
    const before = journal.scanUnresolvedJournalEntries(configDir);
    fs.mkdirSync(path.join(configDir, "windows-retention"));
    const certStore = realRequire("./windows-cert-store");
    const survivors = realRequire("./windows-key-survivors");
    const mutations = [];
    const completedSteps = [];
    let pending = true;
    let keyPresent = true;
    let interruptLookup = interrupt;
    let abortAfterStep = abortAfter;
    let inventoryStopped = false;
    let controller;
    function checkpoint(step, result) {
      completedSteps.push(step);
      if (abortAfterStep === step) controller.abort();
      return result;
    }
    const native = (file, args, _options, callback) => {
      if (args[0] === "--key-survivors") {
        const shared = abortAfterStep === "survivor inventory";
        return callback(null, JSON.stringify({
          complete: true, shared, storesScanned: 25, certificatesScanned: shared ? 1 : 0, matches: shared ? 1 : 0,
        }), "");
      }
      assert.equal(file, "certutil.exe");
      if (args[0] === "-store") {
        assert.deepEqual(args, ["-store", "-silent", "REQUEST"]);
        if (interruptLookup) {
          const child = new EventEmitter();
          child.kill = () => setImmediate(() => {
            inventoryStopped = true;
            child.emit("exit");
          });
          queueMicrotask(() => controller.abort());
          return child;
        }
        return callback(null, pending ? `==== 0 ====\nContainer = ${containerName}\nCert Hash(sha1): ${thumbprint}\n` : "", "");
      }
      if (args[0] === "-delstore") {
        assert.deepEqual(args, ["-delstore", "REQUEST", thumbprint]);
        pending = false;
        mutations.push("pending request");
      } else {
        assert.deepEqual(args, ["-csp", "Microsoft Software Key Storage Provider", "-delkey", containerName]);
        if (!keyPresent) {
          return callback(Object.assign(new Error("key absent"), { code: 1 }), "", "0x80090016 (NTE_BAD_KEYSET)");
        }
        keyPresent = false;
        mutations.push("orphan key");
      }
      return callback(null, "", "");
    };
    const options = {
      configDir, failRegistration, execution: {
        enabled, dryRun, outboxDir: path.join(configDir, "outbox"),
        replayStorePath: path.join(configDir, "replay.json"), clockDriftToleranceMs: 30000,
      },
      moduleOverrides: {
        "./job-journal": journal,
        "./issuers/adcs-enrollment-journal": realRequire("./issuers/adcs-enrollment-journal"),
        "./windows-discovery": {
          ...realRequire("./windows-discovery"),
          listMachineStoreCertificates: async () => checkpoint("store lookup", {
            ok: true, certificates: abortAfterStep === "store lookup" ? [{ keyContainer: containerName }] : [],
          }),
        },
        "./windows-key-survivors": {
          ...survivors,
          inspectMachineKeySurvivors: async (args) => checkpoint("survivor inventory",
            await survivors.inspectMachineKeySurvivors({ ...args, helperPath: __filename, execFileImpl: native })),
        },
        "./windows-cert-store": {
          ...certStore,
          removePendingRequestEntries: async (args) => checkpoint("REQUEST cleanup",
            await certStore.removePendingRequestEntries({ ...args, execFileImpl: native })),
          removeAbandonedKeyContainer: async (args) => checkpoint("key cleanup",
            await certStore.removeAbandonedKeyContainer({ ...args, keySurvivorHelperPath: __filename, execFileImpl: native })),
        },
        "./windows-retention": {
          ...realRequire("./windows-retention"),
          sweepLedger: async () => {
            mutations.push("retention sweep");
            return { removed: [], deferred: [] };
          },
        },
      },
    };
    async function startAndStop({ shouldClean, stopsBeforeHeartbeat, effects }) {
      controller = new AbortController();
      if (preAborted) controller.abort();
      const r = runtime("win32", options);
      r.releaseDrain.resolve();
      const running = r.run([], { signal: controller.signal });
      try {
        if (failRegistration) await assert.rejects(running, /no stored credential/);
        else if (stopsBeforeHeartbeat) await running;
        else await Promise.race([r.heartbeat.promise, running.then(() => assert.fail("expected a heartbeat"))]);
        assert.deepEqual(mutations, effects);
        const after = journal.scanUnresolvedJournalEntries(configDir);
        if (shouldClean) {
          assert.equal(after.length, 1, "key cleanup must leave the outcome unresolved");
          assert.equal(typeof after[0].windowsCngContainerReconciledAt, "string");
        } else {
          assert.deepEqual(after, before);
          assert.equal(pending, !effects.includes("pending request"));
          assert.equal(keyPresent, !effects.includes("orphan key"));
        }
      } finally {
        controller.abort();
        await running.catch(() => {});
      }
    }
    const index = maintenanceSteps.indexOf(abortAfter);
    await startAndStop({
      shouldClean: allowCleanup,
      stopsBeforeHeartbeat: preAborted || interrupt || abortAfter,
      effects: allowCleanup ? maintenanceEffects : maintenanceEffects.slice(0, index === 3 ? 2 : index > 0 ? 1 : 0),
    });
    if (interrupt || abortAfter) {
      if (interrupt) assert.equal(inventoryStopped, true);
      else assert.deepEqual(completedSteps, maintenanceSteps.slice(0, index + 1));
      interruptLookup = false;
      abortAfterStep = null;
      await startAndStop({ shouldClean: true, effects: maintenanceEffects });
    }
  });
}
