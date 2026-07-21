"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");

const {
  createHealthServer,
} = require(
  path.resolve(__dirname, "../../apps/k8s-controller/src/health-server.js"),
);
const {
  createControllerLifecycle,
} = require(path.resolve(__dirname, "../../apps/k8s-controller/src/lifecycle.js"));
const {
  createControllerRuntime,
} = require(path.resolve(__dirname, "../../apps/k8s-controller/src/runtime.js"));
const {
  runController,
} = require(path.resolve(__dirname, "../../apps/k8s-controller/src/index.js"));

function testLogger() {
  return { debug() {}, error() {}, info() {}, warn() {} };
}

function request(address, pathname) {
  return new Promise((resolve, reject) => {
    http.get(
      { host: "127.0.0.1", path: pathname, port: address.port },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode));
      },
    ).on("error", reject);
  });
}

describe("CertOps Kubernetes controller lifecycle", () => {
  it("keeps readiness false without concrete adapters and transitions health safely", async () => {
    let adaptersReady = false;
    const port = {
      async close() {},
      isAlive: () => true,
      isReady: () => adaptersReady,
      async start() {},
      async stopAcceptingWork() {},
    };
    const runtime = createControllerRuntime({
      kubernetesClient: port,
      reporter: port,
    });
    const exits = [];
    let lifecycle;
    const healthServer = createHealthServer({
      getStatus: () => lifecycle.status(),
      host: "127.0.0.1",
      port: 0,
    });
    lifecycle = createControllerLifecycle({
      exitProcess: (code) => exits.push(code),
      healthServer,
      logger: testLogger(),
      runtime,
      shutdownTimeoutMs: 20,
    });

    assert.deepEqual(lifecycle.status(), {
      healthy: false,
      phase: "starting",
      ready: false,
    });
    await lifecycle.start();
    const address = healthServer.server.address();
    assert.equal(await request(address, "/healthz"), 200);
    assert.equal(await request(address, "/readyz"), 503);

    adaptersReady = true;
    assert.equal(await request(address, "/readyz"), 200);
    assert.equal(await lifecycle.shutdown("SIGTERM"), 0);
    assert.deepEqual(exits, [0]);
    assert.deepEqual(lifecycle.status(), {
      healthy: false,
      phase: "stopped",
      ready: false,
    });
  });

  it("stops new work before waiting and bounds in-flight shutdown", async () => {
    const events = [];
    let resolveWork;
    const runtime = createControllerRuntime({
      clearTimeoutFn: clearTimeout,
      kubernetesClient: {
        async close() {
          events.push("kubernetes-close");
        },
        isAlive: () => true,
        isReady: () => true,
        async start() {},
        async stopAcceptingWork() {
          events.push("stop-accepting");
        },
      },
      reporter: {
        async close() {
          events.push("reporter-close");
        },
        isAlive: () => true,
        isReady: () => true,
        async start() {},
        async stopAcceptingWork() {},
      },
      setTimeoutFn: setTimeout,
    });
    await runtime.start();
    const active = runtime.trackWork(
      new Promise((resolve) => {
        resolveWork = resolve;
      }),
    );
    const exits = [];
    const lifecycle = createControllerLifecycle({
      exitProcess: (code) => exits.push(code),
      healthServer: { async close() { events.push("health-close"); }, async listen() {} },
      logger: testLogger(),
      runtime,
      shutdownTimeoutMs: 1,
    });

    const shutdown = lifecycle.shutdown("SIGINT");
    assert.throws(() => runtime.trackWork(Promise.resolve()), {
      code: "CONTROLLER_STOPPING",
    });
    assert.equal(await shutdown, 0);
    assert.equal(events[0], "stop-accepting");
    assert.equal(events.includes("health-close"), true);
    assert.deepEqual(exits, [0]);
    resolveWork();
    await active;
  });

  it("attempts both stop-accepting hooks before propagating the first failure", async () => {
    const events = [];
    const runtime = createControllerRuntime({
      kubernetesClient: {
        async stopAcceptingWork() {
          events.push("kubernetes-stop");
          throw new Error("kubernetes stop failed");
        },
      },
      reporter: {
        async stopAcceptingWork() {
          events.push("reporter-stop");
        },
      },
    });

    await assert.rejects(runtime.stopAcceptingWork(), /kubernetes stop failed/);
    assert.deepEqual(events, ["kubernetes-stop", "reporter-stop"]);
  });

  it("attempts both close hooks after a synchronous reporter close failure", async () => {
    const events = [];
    const reporterFailure = new Error("reporter close failed");
    const runtime = createControllerRuntime({
      kubernetesClient: {
        close() {
          events.push("kubernetes-close");
        },
      },
      reporter: {
        close() {
          events.push("reporter-close");
          throw reporterFailure;
        },
      },
    });

    await assert.rejects(runtime.close(), (error) => error === reporterFailure);
    assert.deepEqual(events, ["reporter-close", "kubernetes-close"]);
  });

  it("uses a non-zero exit code only when shutdown cleanup fails", async () => {
    const exits = [];
    const lifecycle = createControllerLifecycle({
      exitProcess: (code) => exits.push(code),
      healthServer: { async close() {}, async listen() {} },
      logger: testLogger(),
      runtime: {
        async close() {
          throw new Error("close failed");
        },
        isAlive: () => true,
        isReady: () => false,
        async start() {},
        async stopAcceptingWork() {},
        async waitForIdle() {
          return true;
        },
      },
      shutdownTimeoutMs: 10,
    });

    assert.equal(await lifecycle.shutdown(), 1);
    assert.deepEqual(exits, [1]);
  });

  it("routes SIGTERM through the lifecycle before exiting", async () => {
    const events = [];
    const processRef = new EventEmitter();
    const lifecycle = createControllerLifecycle({
      exitProcess: (code) => events.push(`exit:${code}`),
      healthServer: { async close() { events.push("health-close"); }, async listen() {} },
      logger: testLogger(),
      runtime: {
        async close() { events.push("close"); },
        isAlive: () => true,
        isReady: () => false,
        async start() {},
        async stopAcceptingWork() { events.push("stop-accepting"); },
        async waitForIdle() { events.push("wait"); return true; },
      },
      shutdownTimeoutMs: 10,
    });
    lifecycle.installSignalHandlers(processRef);
    processRef.emit("SIGTERM");
    await lifecycle.shutdown();

    assert.deepEqual(events, ["stop-accepting", "wait", "health-close", "close", "exit:0"]);
  });

  it("latches SIGTERM during deferred startup and closes the partial runtime once", async () => {
    const events = [];
    const processRef = new EventEmitter();
    let resolveStart;
    const lifecycle = createControllerLifecycle({
      exitProcess: (code) => events.push(`exit:${code}`),
      healthServer: {
        async close() {
          events.push("health-close");
        },
        async listen() {
          events.push("health-listen");
        },
      },
      logger: {
        debug() {},
        error() {},
        info(message) {
          events.push(message);
        },
        warn() {},
      },
      runtime: {
        async close() {
          events.push("runtime-close");
        },
        isAlive: () => true,
        isReady: () => true,
        async start() {
          events.push("runtime-start");
          await new Promise((resolve) => {
            resolveStart = resolve;
          });
          events.push("runtime-started");
        },
        async stopAcceptingWork() {
          events.push("stop-accepting");
        },
        async waitForIdle() {
          events.push("wait");
          return true;
        },
      },
      shutdownTimeoutMs: 10,
    });
    lifecycle.installSignalHandlers(processRef);

    const starting = lifecycle.start();
    await Promise.resolve();
    processRef.emit("SIGTERM");
    assert.deepEqual(lifecycle.status(), {
      healthy: false,
      phase: "stopping",
      ready: false,
    });

    resolveStart();
    await starting;
    assert.equal(await lifecycle.shutdown(), 0);

    assert.equal(events.includes("runtime-started"), true);
    assert.equal(events.includes("controller-started"), false);
    assert.equal(events.indexOf("runtime-started") < events.indexOf("stop-accepting"), true);
    assert.deepEqual(events.filter((event) => event === "stop-accepting"), ["stop-accepting"]);
    assert.deepEqual(events.filter((event) => event === "health-close"), ["health-close"]);
    assert.deepEqual(events.filter((event) => event === "runtime-close"), ["runtime-close"]);
    assert.deepEqual(events.filter((event) => event === "exit:0"), ["exit:0"]);
    assert.deepEqual(lifecycle.status(), {
      healthy: false,
      phase: "stopped",
      ready: false,
    });
  });

  it("returns a non-zero startup result without terminating injected tests", async () => {
    const temporaryDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "tokentimer-controller-startup-"),
    );
    const tokenFile = path.join(temporaryDirectory, "token");
    fs.writeFileSync(tokenFile, `ttx_${"a".repeat(16)}_${"b".repeat(64)}`, { mode: 0o600 });
    const exits = [];
    const processRef = new EventEmitter();
    const logger = { debug() {}, error() {}, info() {}, warn() {} };

    const application = await runController({
      createHealth: () => ({ async close() {}, async listen() {} }),
      createRuntime: () => ({
        async close() {},
        isAlive: () => false,
        isReady: () => false,
        async start() {
          throw Object.assign(new Error("startup failed"), {
            code: "CONTROLLER_STARTUP_FAILED",
          });
        },
        async stopAcceptingWork() {},
        async waitForIdle() {
          return true;
        },
      }),
      env: {
        TOKENTIMER_API_TOKEN_FILE: tokenFile,
        TOKENTIMER_API_URL: "https://tokentimer.example.test",
        TOKENTIMER_CLUSTER_ID: "cluster-1",
        TOKENTIMER_WORKSPACE_ID: "00000000-0000-4000-8000-000000000001",
        CERTOPS_WATCH_NAMESPACES: "default",
      },
      exitProcess: (code) => exits.push(code),
      logger,
      processRef,
    });
    fs.rmSync(temporaryDirectory, { force: true, recursive: true });

    assert.equal(application, null);
    assert.deepEqual(exits, [1]);
  });
});
