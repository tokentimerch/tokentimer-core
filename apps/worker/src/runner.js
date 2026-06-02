#!/usr/bin/env node
import { pathToFileURL } from "url";
import { pool } from "./db.js";
import { logger } from "./logger.js";

const POSITIVE_INTEGER_PATTERN = /^\d+$/;

export function createLazyWorkerRun(importModule, selectRun) {
  let run;

  return async () => {
    if (!run) {
      run = selectRun(await importModule());
    }

    return run();
  };
}

export const workerDefinitions = {
  discovery: {
    name: "discovery",
    label: "alert-discovery",
    intervalEnv: "WORKER_DISCOVERY_INTERVAL_MS",
    runOnStartEnv: "WORKER_DISCOVERY_RUN_ON_START",
    defaultIntervalMs: 60_000,
    runOnStartDefault: true,
    run: createLazyWorkerRun(
      () => import("./queue-manager.js"),
      ({ queueDiscoveryJob }) => () => queueDiscoveryJob({ closePool: false }),
    ),
  },
  delivery: {
    name: "delivery",
    label: "alert-delivery",
    intervalEnv: "WORKER_DELIVERY_INTERVAL_MS",
    runOnStartEnv: "WORKER_DELIVERY_RUN_ON_START",
    defaultIntervalMs: 30_000,
    runOnStartDefault: true,
    run: createLazyWorkerRun(
      () => import("./delivery-worker.js"),
      ({ deliveryWorkerJob }) => () => deliveryWorkerJob({ closePool: false }),
    ),
  },
  "auto-sync": {
    name: "auto-sync",
    label: "auto-sync",
    intervalEnv: "WORKER_AUTO_SYNC_INTERVAL_MS",
    runOnStartEnv: "WORKER_AUTO_SYNC_RUN_ON_START",
    defaultIntervalMs: 300_000,
    runOnStartDefault: true,
    run: createLazyWorkerRun(
      () => import("./auto-sync-worker.js"),
      ({ runAutoSync }) => runAutoSync,
    ),
  },
  "endpoint-check": {
    name: "endpoint-check",
    label: "endpoint-check",
    intervalEnv: "WORKER_ENDPOINT_CHECK_INTERVAL_MS",
    runOnStartEnv: "WORKER_ENDPOINT_CHECK_RUN_ON_START",
    defaultIntervalMs: 60_000,
    runOnStartDefault: true,
    run: createLazyWorkerRun(
      () => import("./endpoint-check-worker.js"),
      ({ runEndpointChecks }) => runEndpointChecks,
    ),
  },
  "weekly-digest": {
    name: "weekly-digest",
    label: "weekly-digest",
    intervalEnv: "WORKER_WEEKLY_DIGEST_INTERVAL_MS",
    runOnStartEnv: "WORKER_WEEKLY_DIGEST_RUN_ON_START",
    defaultIntervalMs: 86_400_000,
    runOnStartDefault: false,
    run: createLazyWorkerRun(
      () => import("./weekly-digest.js"),
      ({ weeklyDigestJob }) => weeklyDigestJob,
    ),
  },
};

const workerAliases = {
  endpoint: "endpoint-check",
  weekly: "weekly-digest",
};

export function parseIntervalMs(value, defaultValue, envName = "interval") {
  if (value == null || value === "") return defaultValue;
  const text = String(value).trim();
  if (!POSITIVE_INTEGER_PATTERN.test(text)) {
    throw new Error(`${envName} must be a positive integer in milliseconds`);
  }

  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${envName} must be a positive integer in milliseconds`);
  }

  return parsed;
}

export function parseBoolean(value, defaultValue = false, envName = "value") {
  if (value == null || value === "") return defaultValue;
  const text = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(text)) return true;
  if (["0", "false", "no", "off"].includes(text)) return false;
  throw new Error(`${envName} must be true or false`);
}

export function resolveWorkerNames(command, definitions = workerDefinitions) {
  const selected = command || "all";
  if (selected === "all") return Object.keys(definitions);

  const workerName = workerAliases[selected] || selected;
  if (!definitions[workerName]) {
    const known = ["all", ...Object.keys(definitions)].join(", ");
    throw new Error(`Unknown worker "${selected}". Expected one of: ${known}`);
  }

  return [workerName];
}

export function getWorkerConfig(worker, env = process.env) {
  const runOnStartValue =
    env[worker.runOnStartEnv] ??
    (worker.runOnStartDefault ? env.WORKER_RUN_ON_START : undefined);

  return {
    intervalMs: parseIntervalMs(
      env[worker.intervalEnv],
      worker.defaultIntervalMs,
      worker.intervalEnv,
    ),
    runOnStart: parseBoolean(
      runOnStartValue,
      worker.runOnStartDefault,
      worker.runOnStartEnv,
    ),
  };
}

export async function runWorkerOnce(
  state,
  worker,
  {
    exitOnError = false,
    trigger = "manual",
    log = logger,
    now = () => Date.now(),
  } = {},
) {
  if (state.running) {
    log.warn("worker-runner-skip-overlap", {
      worker: worker.name,
      trigger,
    });
    return { status: "skipped" };
  }

  state.running = true;
  const startedAt = now();
  log.info("worker-runner-job-start", {
    worker: worker.name,
    trigger,
  });

  try {
    await worker.run();
    const durationMs = now() - startedAt;
    log.info("worker-runner-job-finish", {
      worker: worker.name,
      trigger,
      durationMs,
    });
    return { status: "success", durationMs };
  } catch (error) {
    const durationMs = now() - startedAt;
    log.error("worker-runner-job-failure", {
      worker: worker.name,
      trigger,
      durationMs,
      error: error.message,
      stack: error.stack,
    });
    if (exitOnError) throw error;
    return { status: "failed", error, durationMs };
  } finally {
    state.running = false;
  }
}

export function parseRunnerArgs(args, env = process.env) {
  const positional = [];
  let runOnce = parseBoolean(env.WORKER_RUN_ONCE, false, "WORKER_RUN_ONCE");

  for (const arg of args) {
    if (arg === "--once") {
      runOnce = true;
    } else if (arg === "--help" || arg === "-h") {
      return { help: true };
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option "${arg}"`);
    } else {
      positional.push(arg);
    }
  }

  if (positional.length > 1) {
    throw new Error("Expected at most one worker name");
  }

  return {
    workerNames: resolveWorkerNames(positional[0] || "all"),
    runOnce,
    exitOnError: parseBoolean(
      env.WORKER_EXIT_ON_ERROR,
      false,
      "WORKER_EXIT_ON_ERROR",
    ),
  };
}

export async function runWorkersOnce(workerNames, { exitOnError = false } = {}) {
  const results = [];
  for (const name of workerNames) {
    const worker = workerDefinitions[name];
    const state = { running: false };
    results.push(
      await runWorkerOnce(state, worker, {
        exitOnError,
        trigger: "once",
      }),
    );
  }
  return results;
}

export function startRunner(
  workerNames,
  {
    env = process.env,
    exitOnError = false,
    log = logger,
    setIntervalFn = setInterval,
    clearIntervalFn = clearInterval,
  } = {},
) {
  const timers = [];
  const states = new Map();
  const activeRuns = new Set();
  let stopping = false;

  const invoke = (worker, state, trigger, intervalMs) => {
    if (stopping) return;

    const promise = runWorkerOnce(state, worker, {
      exitOnError,
      trigger,
      log,
    })
      .then((result) => {
        if (!stopping && result.status !== "skipped") {
          log.info("worker-runner-next-run", {
            worker: worker.name,
            nextRunAt: new Date(Date.now() + intervalMs).toISOString(),
            intervalMs,
          });
        }
        return result;
      })
      .catch((error) => {
        if (exitOnError) {
          log.error("worker-runner-exit-on-error", {
            worker: worker.name,
            error: error.message,
          });
          void stop(1);
        }
      })
      .finally(() => {
        activeRuns.delete(promise);
      });

    activeRuns.add(promise);
  };

  async function stop(exitCode = 0, signal = "manual") {
    if (stopping) return;
    stopping = true;
    log.info("worker-runner-stopping", { signal });

    for (const timer of timers) clearIntervalFn(timer);
    await Promise.allSettled([...activeRuns]);

    try {
      await pool.end();
    } catch (error) {
      log.error("worker-runner-pool-close-failure", {
        error: error.message,
      });
      exitCode = exitCode || 1;
    }

    process.exit(exitCode);
  }

  for (const name of workerNames) {
    const worker = workerDefinitions[name];
    const config = getWorkerConfig(worker, env);
    const state = { running: false };
    states.set(name, state);

    log.info("worker-runner-worker-started", {
      worker: worker.name,
      intervalMs: config.intervalMs,
      runOnStart: config.runOnStart,
      exitOnError,
    });

    if (config.runOnStart) {
      invoke(worker, state, "startup", config.intervalMs);
    } else {
      log.info("worker-runner-next-run", {
        worker: worker.name,
        nextRunAt: new Date(Date.now() + config.intervalMs).toISOString(),
        intervalMs: config.intervalMs,
      });
    }

    timers.push(
      setIntervalFn(
        () => invoke(worker, state, "interval", config.intervalMs),
        config.intervalMs,
      ),
    );
  }

  process.once("SIGINT", () => void stop(0, "SIGINT"));
  process.once("SIGTERM", () => void stop(0, "SIGTERM"));

  return {
    stop,
    timers,
    states,
    activeRuns,
  };
}

function printHelp() {
  const workers = Object.keys(workerDefinitions).join(", ");
  console.log(`Usage: node src/runner.js [worker|all] [--once]\n`);
  console.log(`Workers: ${workers}`);
}

async function main() {
  try {
    const parsed = parseRunnerArgs(process.argv.slice(2));
    if (parsed.help) {
      printHelp();
      return;
    }

    if (parsed.runOnce) {
      const results = await runWorkersOnce(parsed.workerNames, {
        exitOnError: parsed.exitOnError,
      });
      await pool.end();
      const hasFailure = results.some((result) => result.status === "failed");
      process.exit(hasFailure ? 1 : 0);
    }

    startRunner(parsed.workerNames, {
      exitOnError: parsed.exitOnError,
    });
  } catch (error) {
    logger.error("worker-runner-start-failure", {
      error: error.message,
      stack: error.stack,
    });
    try {
      await pool.end();
    } catch (_err) {
      logger.debug("Non-critical operation failed", { error: _err.message });
    }
    process.exit(1);
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  void main();
}
