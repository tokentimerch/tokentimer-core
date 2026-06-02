"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const { pathToFileURL } = require("url");

const runnerUrl = pathToFileURL(
  path.join(__dirname, "..", "..", "apps", "worker", "src", "runner.js"),
).href;

const silentLogger = {
  info() {},
  warn() {},
  error() {},
};

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
});
