"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("path");
const { pathToFileURL } = require("url");

const runnerPath = path.join(
  __dirname,
  "..",
  "..",
  "apps",
  "worker",
  "src",
  "runner.js",
);
const runnerUrl = pathToFileURL(
  runnerPath,
).href;

const silentLogger = {
  info() {},
  warn() {},
  error() {},
};

function delay(ms = 0) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe("worker runner helpers", () => {
  it("parses positive interval values and uses defaults for unset values", async () => {
    const runner = await import(runnerUrl);

    assert.strictEqual(runner.parseIntervalMs(undefined, 123), 123);
    assert.strictEqual(runner.parseIntervalMs("", 123), 123);
    assert.strictEqual(
      runner.parseIntervalMs("60000", 123, "WORKER_TEST_INTERVAL_MS"),
      60000,
    );
    assert.throws(
      () => runner.parseIntervalMs("0", 123, "WORKER_TEST_INTERVAL_MS"),
      /WORKER_TEST_INTERVAL_MS must be a positive integer/,
    );
    assert.throws(
      () => runner.parseIntervalMs("abc", 123, "WORKER_TEST_INTERVAL_MS"),
      /WORKER_TEST_INTERVAL_MS must be a positive integer/,
    );
  });

  it("uses Kubernetes CronJob schedules as the default worker crons", async () => {
    const runner = await import(runnerUrl);

    assert.deepStrictEqual(runner.DEFAULT_WORKER_CRONS, {
      discovery: "*/5 * * * *",
      delivery: "1/5 * * * *",
      "auto-sync": "0 * * * *",
      "endpoint-check": "*/1 * * * *",
      "weekly-digest": "0 9 * * 1",
    });

    assert.deepStrictEqual(
      Object.fromEntries(
        Object.entries(runner.workerDefinitions).map(([name, worker]) => [
          name,
          worker.defaultCron,
        ]),
      ),
      runner.DEFAULT_WORKER_CRONS,
    );
  });

  it("calculates next runs for the default cron expressions", async () => {
    const runner = await import(runnerUrl);
    const mondayMorning = new Date(2026, 5, 1, 8, 59, 0, 0);
    const mondayNine = new Date(2026, 5, 1, 9, 0, 0, 0);

    assert.deepStrictEqual(
      runner.getNextCronRunAt("*/5 * * * *", mondayNine),
      new Date(2026, 5, 1, 9, 5, 0, 0),
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("1/5 * * * *", mondayNine),
      new Date(2026, 5, 1, 9, 1, 0, 0),
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("1/5 * * * *", new Date(2026, 5, 1, 9, 1)),
      new Date(2026, 5, 1, 9, 6, 0, 0),
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("*/1 * * * *", new Date(2026, 5, 1, 9, 0, 30)),
      new Date(2026, 5, 1, 9, 1, 0, 0),
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("0 * * * *", mondayNine),
      new Date(2026, 5, 1, 10, 0, 0, 0),
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("0 9 * * 1", mondayMorning),
      mondayNine,
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("0 9 * * 1", mondayNine),
      new Date(2026, 5, 8, 9, 0, 0, 0),
    );
    assert.deepStrictEqual(
      runner.getNextCronRunAt("0 9 * * 7", new Date(2026, 5, 6, 12, 0)),
      new Date(2026, 5, 7, 9, 0, 0, 0),
    );
  });

  it("uses cron scheduling by default and supports explicit interval fallback", async () => {
    const runner = await import(runnerUrl);
    const discovery = runner.workerDefinitions.discovery;

    assert.deepStrictEqual(
      runner.getWorkerConfig(discovery, {
        WORKER_DISCOVERY_RUN_ON_START: "true",
      }),
      {
        mode: "cron",
        cronExpression: "*/5 * * * *",
        cron: runner.parseCronExpression("*/5 * * * *", "WORKER_DISCOVERY_CRON"),
        runOnStart: true,
      },
    );

    const intervalConfig = runner.getWorkerConfig(discovery, {
      WORKER_DISCOVERY_CRON: "interval",
      WORKER_DISCOVERY_INTERVAL_MS: "2500",
    });

    assert.strictEqual(intervalConfig.mode, "interval");
    assert.strictEqual(intervalConfig.intervalMs, 2500);
    assert.strictEqual(intervalConfig.runOnStart, true);
  });

  it("fails unknown worker names with a clear error", async () => {
    const runner = await import(runnerUrl);

    assert.throws(
      () => runner.resolveWorkerNames("not-a-worker"),
      /Unknown worker "not-a-worker"/,
    );
  });

  it("keeps weekly digest from inheriting global run-on-start", async () => {
    const runner = await import(runnerUrl);
    const weeklyDigest = runner.workerDefinitions["weekly-digest"];

    assert.strictEqual(
      runner.getWorkerConfig(weeklyDigest, {}).runOnStart,
      false,
    );

    assert.strictEqual(
      runner.getWorkerConfig(weeklyDigest, {
        WORKER_RUN_ON_START: "true",
      }).runOnStart,
      false,
    );

    assert.strictEqual(
      runner.getWorkerConfig(weeklyDigest, {
        WORKER_WEEKLY_DIGEST_RUN_ON_START: "true",
      }).runOnStart,
      true,
    );
  });

  it("uses safer local defaults for auto-sync and endpoint checks", async () => {
    const runner = await import(runnerUrl);
    const autoSync = runner.workerDefinitions["auto-sync"];
    const endpointCheck = runner.workerDefinitions["endpoint-check"];

    assert.strictEqual(
      runner.getWorkerConfig(
        autoSync,
        { WORKER_RUN_ON_START: "true" },
        { safeLocalDefaults: true },
      ).runOnStart,
      false,
    );
    assert.strictEqual(
      runner.getWorkerConfig(
        endpointCheck,
        { WORKER_RUN_ON_START: "true" },
        { safeLocalDefaults: true },
      ).runOnStart,
      false,
    );
    assert.strictEqual(
      runner.getWorkerConfig(
        autoSync,
        {
          WORKER_AUTO_SYNC_RUN_ON_START: "true",
        },
        { safeLocalDefaults: true },
      ).runOnStart,
      true,
    );
  });

  it("parses the safe local defaults option", async () => {
    const runner = await import(runnerUrl);
    const parsed = runner.parseRunnerArgs(["all", "--safe-local-defaults"]);

    assert.deepStrictEqual(
      parsed.workerNames,
      Object.keys(runner.workerDefinitions),
    );
    assert.strictEqual(parsed.safeLocalDefaults, true);
  });

  it("runs every selected worker once for --once all", async () => {
    const runner = await import(runnerUrl);
    const calls = [];
    const definitions = {
      first: {
        name: "first",
        intervalEnv: "FIRST_INTERVAL_MS",
        runOnStartEnv: "FIRST_RUN_ON_START",
        defaultIntervalMs: 1000,
        runOnStartDefault: true,
        run: async () => calls.push("first"),
      },
      second: {
        name: "second",
        intervalEnv: "SECOND_INTERVAL_MS",
        runOnStartEnv: "SECOND_RUN_ON_START",
        defaultIntervalMs: 1000,
        runOnStartDefault: true,
        run: async () => calls.push("second"),
      },
    };

    const parsed = runner.parseRunnerArgs(["all", "--once"], {}, definitions);
    assert.deepStrictEqual(parsed.workerNames, ["first", "second"]);
    assert.strictEqual(parsed.runOnce, true);

    const results = await runner.runWorkersOnce(parsed.workerNames, {
      definitions,
      log: silentLogger,
    });

    assert.deepStrictEqual(calls, ["first", "second"]);
    assert.deepStrictEqual(
      results.map((result) => result.status),
      ["success", "success"],
    );
  });

  it("stops timers, waits for active runs, closes the pool, and exits", async () => {
    const runner = await import(runnerUrl);
    let releaseRun;
    let runStarted = false;
    let closePoolCount = 0;
    const exited = [];
    const timers = [];
    const clearedTimers = [];
    const definitions = {
      test: {
        name: "test",
        cronEnv: "TEST_CRON",
        intervalEnv: "TEST_INTERVAL_MS",
        runOnStartEnv: "TEST_RUN_ON_START",
        defaultIntervalMs: 1000,
        runOnStartDefault: true,
        run: () =>
          new Promise((resolve) => {
            runStarted = true;
            releaseRun = resolve;
          }),
      },
    };

    const controller = runner.startRunner(["test"], {
      definitions,
      env: { TEST_CRON: "interval" },
      log: silentLogger,
      setIntervalFn: (callback, intervalMs) => {
        const timer = { callback, intervalMs };
        timers.push(timer);
        return timer;
      },
      clearIntervalFn: (timer) => clearedTimers.push(timer),
      closePool: async () => {
        closePoolCount += 1;
      },
      exitProcess: (exitCode) => exited.push(exitCode),
    });

    await delay();
    assert.strictEqual(runStarted, true);
    assert.strictEqual(timers.length, 1);

    const stopPromise = controller.stop(0, "test");
    await delay();

    assert.deepStrictEqual(clearedTimers, timers);
    assert.deepStrictEqual(exited, []);

    releaseRun();
    await stopPromise;

    assert.strictEqual(closePoolCount, 1);
    assert.deepStrictEqual(exited, [0]);
    assert.strictEqual(controller.activeRuns.size, 0);
  });

  it("schedules cron workers with timeouts and without startup runs by default", async () => {
    const runner = await import(runnerUrl);
    let runCount = 0;
    let closePoolCount = 0;
    const exited = [];
    const timeouts = [];
    const clearedTimeouts = [];
    const definitions = {
      test: {
        name: "test",
        cronEnv: "TEST_CRON",
        defaultCron: "*/5 * * * *",
        intervalEnv: "TEST_INTERVAL_MS",
        runOnStartEnv: "TEST_RUN_ON_START",
        defaultIntervalMs: 1000,
        runOnStartDefault: true,
        cronRunOnStartDefault: false,
        run: async () => {
          runCount += 1;
        },
      },
    };

    const controller = runner.startRunner(["test"], {
      definitions,
      env: {},
      log: silentLogger,
      setIntervalFn: () => {
        throw new Error("cron worker should not use setInterval");
      },
      setTimeoutFn: (callback, delayMs) => {
        const timer = { callback, delayMs };
        timeouts.push(timer);
        return timer;
      },
      clearTimeoutFn: (timer) => clearedTimeouts.push(timer),
      closePool: async () => {
        closePoolCount += 1;
      },
      exitProcess: (exitCode) => exited.push(exitCode),
    });

    assert.strictEqual(runCount, 0);
    assert.strictEqual(timeouts.length, 1);
    assert.strictEqual(typeof timeouts[0].delayMs, "number");

    await controller.stop(0, "test");

    assert.deepStrictEqual(clearedTimeouts, timeouts);
    assert.strictEqual(closePoolCount, 1);
    assert.deepStrictEqual(exited, [0]);
  });

  it("prevents overlapping runs for the same worker", async () => {
    const runner = await import(runnerUrl);

    let release;
    const worker = {
      name: "test-worker",
      run: () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    };
    const state = { running: false };

    const firstRun = runner.runWorkerOnce(state, worker, {
      log: silentLogger,
      now: () => 1000,
    });
    assert.strictEqual(state.running, true);

    const secondRun = await runner.runWorkerOnce(state, worker, {
      log: silentLogger,
    });
    assert.strictEqual(secondRun.status, "skipped");

    release();
    const firstResult = await firstRun;
    assert.strictEqual(firstResult.status, "success");
    assert.strictEqual(state.running, false);
  });

  it("lazy-loads worker modules only when the worker runs", async () => {
    const runner = await import(runnerUrl);
    let importCount = 0;
    let runCount = 0;

    const run = runner.createLazyWorkerRun(
      async () => {
        importCount += 1;
        return {
          job: () => {
            runCount += 1;
            return "done";
          },
        };
      },
      ({ job }) => job,
    );

    assert.strictEqual(importCount, 0);
    assert.strictEqual(runCount, 0);

    assert.strictEqual(await run(), "done");
    assert.strictEqual(importCount, 1);
    assert.strictEqual(runCount, 1);

    assert.strictEqual(await run(), "done");
    assert.strictEqual(importCount, 1);
    assert.strictEqual(runCount, 2);
  });

  it("does not statically import worker job modules", () => {
    const source = fs.readFileSync(runnerPath, "utf8");
    const workerModules = [
      "queue-manager",
      "delivery-worker",
      "auto-sync-worker",
      "endpoint-check-worker",
      "weekly-digest",
    ];

    for (const moduleName of workerModules) {
      assert.doesNotMatch(
        source,
        new RegExp(`^import .*["']\\.\\/${moduleName}\\.js["'];?$`, "m"),
      );
      assert.match(source, new RegExp(`import\\("\\./${moduleName}\\.js"\\)`));
    }
  });
});
