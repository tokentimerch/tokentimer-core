"use strict";
/** Execute the actual runAgent runtime with its real polling loop and actual
 * process signal listeners. Only configuration, network/native startup and log
 * transport are controlled; no service, CNG, certificate or API fixture runs. */
const test = require("node:test"),
  assert = require("node:assert/strict"),
  fs = require("node:fs"),
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
function runtime(platform, { failRegistration = false } = {}) {
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
    execution: { enabled: false },
    heartbeatIntervalMs: 60000,
    pollIntervalMs: 60000,
    protocolVersion: "1.0",
    policy: {},
    dnsProviders: {},
    windowsDiscovery: { enabled: false },
    windows: { enabled: false },
  };
  const overrides = {
    "./config": {
      ...realRequire("./config"),
      resolveConfigDir: () =>
        path.join(__dirname, "nonexistent-signal-fixture"),
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
    require: (name) => overrides[name] || realRequire(name),
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
