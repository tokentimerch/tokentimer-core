#!/usr/bin/env node
import { isNodeEntrypoint } from "./is-node-entrypoint.js";
import { pool } from "./db.js";
import { logger } from "./logger.js";

const POSITIVE_INTEGER_PATTERN = /^\d+$/;
const CRON_FIELD_COUNT = 5;
const CRON_LOOKAHEAD_MINUTES = 35 * 24 * 60;
const SHUTDOWN_TIMEOUT_MS = 30_000;
const MAX_DAYS_IN_MONTH = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
const INTERVAL_SCHEDULE_VALUES = new Set([
  "0",
  "false",
  "off",
  "interval",
  "interval-ms",
  "legacy",
]);

const CRON_FIELDS = [
  { key: "minute", label: "minute", min: 0, max: 59 },
  { key: "hour", label: "hour", min: 0, max: 23 },
  { key: "dayOfMonth", label: "day of month", min: 1, max: 31 },
  { key: "month", label: "month", min: 1, max: 12 },
  {
    key: "dayOfWeek",
    label: "day of week",
    min: 0,
    max: 7,
    normalize: (value) => (value === 7 ? 0 : value),
  },
];

export const DEFAULT_WORKER_CRONS = {
  discovery: "*/5 * * * *",
  delivery: "1/5 * * * *",
  "auto-sync": "*/1 * * * *",
  "endpoint-check": "*/1 * * * *",
  "weekly-digest": "0 9 * * 1",
};

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
    cronEnv: "WORKER_DISCOVERY_CRON",
    defaultCron: DEFAULT_WORKER_CRONS.discovery,
    intervalEnv: "WORKER_DISCOVERY_INTERVAL_MS",
    runOnStartEnv: "WORKER_DISCOVERY_RUN_ON_START",
    defaultIntervalMs: 60_000,
    runOnStartDefault: true,
    cronRunOnStartDefault: false,
    run: createLazyWorkerRun(
      () => import("./queue-manager.js"),
      ({ queueDiscoveryJob }) => () => queueDiscoveryJob({ closePool: false }),
    ),
  },
  delivery: {
    name: "delivery",
    label: "alert-delivery",
    cronEnv: "WORKER_DELIVERY_CRON",
    defaultCron: DEFAULT_WORKER_CRONS.delivery,
    intervalEnv: "WORKER_DELIVERY_INTERVAL_MS",
    runOnStartEnv: "WORKER_DELIVERY_RUN_ON_START",
    defaultIntervalMs: 30_000,
    runOnStartDefault: true,
    cronRunOnStartDefault: false,
    run: createLazyWorkerRun(
      () => import("./delivery-worker.js"),
      ({ deliveryWorkerJob }) => () => deliveryWorkerJob({ closePool: false }),
    ),
  },
  "auto-sync": {
    name: "auto-sync",
    label: "auto-sync",
    cronEnv: "WORKER_AUTO_SYNC_CRON",
    defaultCron: DEFAULT_WORKER_CRONS["auto-sync"],
    intervalEnv: "WORKER_AUTO_SYNC_INTERVAL_MS",
    runOnStartEnv: "WORKER_AUTO_SYNC_RUN_ON_START",
    defaultIntervalMs: 300_000,
    runOnStartDefault: true,
    cronRunOnStartDefault: false,
    localDevRunOnStartDefault: false,
    run: createLazyWorkerRun(
      () => import("./auto-sync-worker.js"),
      ({ runAutoSync }) => runAutoSync,
    ),
  },
  "endpoint-check": {
    name: "endpoint-check",
    label: "endpoint-check",
    cronEnv: "WORKER_ENDPOINT_CHECK_CRON",
    defaultCron: DEFAULT_WORKER_CRONS["endpoint-check"],
    intervalEnv: "WORKER_ENDPOINT_CHECK_INTERVAL_MS",
    runOnStartEnv: "WORKER_ENDPOINT_CHECK_RUN_ON_START",
    defaultIntervalMs: 60_000,
    runOnStartDefault: true,
    cronRunOnStartDefault: false,
    localDevRunOnStartDefault: false,
    run: createLazyWorkerRun(
      () => import("./endpoint-check-worker.js"),
      ({ runEndpointChecks }) => runEndpointChecks,
    ),
  },
  "weekly-digest": {
    name: "weekly-digest",
    label: "weekly-digest",
    cronEnv: "WORKER_WEEKLY_DIGEST_CRON",
    defaultCron: DEFAULT_WORKER_CRONS["weekly-digest"],
    intervalEnv: "WORKER_WEEKLY_DIGEST_INTERVAL_MS",
    runOnStartEnv: "WORKER_WEEKLY_DIGEST_RUN_ON_START",
    defaultIntervalMs: 86_400_000,
    runOnStartDefault: false,
    cronRunOnStartDefault: false,
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

function parseCronRawNumber(value, field, envName) {
  if (!POSITIVE_INTEGER_PATTERN.test(value)) {
    throw new Error(`${envName} ${field.label} value must be an integer`);
  }

  const parsed = Number(value);
  if (parsed < field.min || parsed > field.max) {
    throw new Error(
      `${envName} ${field.label} value must be between ${field.min} and ${field.max}`,
    );
  }

  return parsed;
}

function addCronRange(values, field, start, end, step) {
  for (let value = start; value <= end; value += step) {
    values.add(field.normalize ? field.normalize(value) : value);
  }
}

function parseCronField(value, field, envName) {
  const text = String(value).trim();
  if (!text) {
    throw new Error(`${envName} ${field.label} field cannot be empty`);
  }

  const values = new Set();
  const unrestricted = text === "*";

  for (const rawPart of text.split(",")) {
    const part = rawPart.trim();
    if (!part) {
      throw new Error(`${envName} ${field.label} field contains an empty item`);
    }

    const pieces = part.split("/");
    if (pieces.length > 2) {
      throw new Error(`${envName} ${field.label} field has an invalid step`);
    }

    const rangeText = pieces[0];
    const stepText = pieces[1];
    const step = stepText
      ? parseIntervalMs(stepText, 1, `${envName} ${field.label} step`)
      : 1;
    let start;
    let end;

    if (rangeText === "*") {
      start = field.min;
      end = field.max;
    } else if (rangeText.includes("-")) {
      const rangeParts = rangeText.split("-");
      if (rangeParts.length !== 2 || !rangeParts[0] || !rangeParts[1]) {
        throw new Error(`${envName} ${field.label} field has an invalid range`);
      }
      start = parseCronRawNumber(rangeParts[0], field, envName);
      end = parseCronRawNumber(rangeParts[1], field, envName);
      if (start > end) {
        throw new Error(
          `${envName} ${field.label} range start must be before range end`,
        );
      }
    } else {
      start = parseCronRawNumber(rangeText, field, envName);
      end = stepText ? field.max : start;
    }

    addCronRange(values, field, start, end, step);
  }

  return { values, unrestricted };
}

export function parseCronExpression(expression, envName = "cron") {
  const text = String(expression ?? "").trim();
  const parts = text.split(/\s+/).filter(Boolean);
  if (parts.length !== CRON_FIELD_COUNT) {
    throw new Error(`${envName} must be a five-field cron expression`);
  }

  const parsed = { expression: parts.join(" ") };
  for (let index = 0; index < CRON_FIELDS.length; index += 1) {
    const field = CRON_FIELDS[index];
    parsed[field.key] = parseCronField(parts[index], field, envName);
  }

  return parsed;
}

export function validateCronFeasibility(cron) {
  if (cron.dayOfMonth.unrestricted || cron.month.unrestricted) {
    return;
  }

  const months = [...cron.month.values];
  const days = [...cron.dayOfMonth.values];

  for (const month of months) {
    const maxDay = MAX_DAYS_IN_MONTH[month - 1];
    for (const day of days) {
      if (day <= maxDay) return;
    }
  }

  throw new Error(
    `Cron expression "${cron.expression}" cannot match any calendar date`,
  );
}

function cronMatchesDate(cron, date) {
  const dayOfMonthMatches = cron.dayOfMonth.values.has(date.getDate());
  const dayOfWeekMatches = cron.dayOfWeek.values.has(date.getDay());
  const dayMatches =
    !cron.dayOfMonth.unrestricted && !cron.dayOfWeek.unrestricted
      ? dayOfMonthMatches || dayOfWeekMatches
      : dayOfMonthMatches && dayOfWeekMatches;

  return (
    cron.minute.values.has(date.getMinutes()) &&
    cron.hour.values.has(date.getHours()) &&
    dayMatches &&
    cron.month.values.has(date.getMonth() + 1)
  );
}

export function getNextCronRunAt(expressionOrCron, from = new Date()) {
  if (!(from instanceof Date) || Number.isNaN(from.getTime())) {
    throw new Error("from must be a valid Date");
  }

  const cron =
    typeof expressionOrCron === "string"
      ? parseCronExpression(expressionOrCron)
      : expressionOrCron;
  validateCronFeasibility(cron);
  const candidate = new Date(from.getTime());
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1);

  for (let index = 0; index < CRON_LOOKAHEAD_MINUTES; index += 1) {
    if (cronMatchesDate(cron, candidate)) {
      return new Date(candidate.getTime());
    }
    candidate.setMinutes(candidate.getMinutes() + 1);
  }

  throw new Error(
    `No future run found for cron expression "${cron.expression}" within ${CRON_LOOKAHEAD_MINUTES} minutes`,
  );
}

export function getWorkerSchedule(worker, env = process.env) {
  const rawCronValue = worker.cronEnv ? env[worker.cronEnv] : undefined;
  const cronExpression =
    rawCronValue == null || String(rawCronValue).trim() === ""
      ? worker.defaultCron
      : String(rawCronValue).trim();

  if (
    cronExpression &&
    !INTERVAL_SCHEDULE_VALUES.has(cronExpression.toLowerCase())
  ) {
    return {
      mode: "cron",
      cronExpression,
      cron: parseCronExpression(cronExpression, worker.cronEnv || "cron"),
    };
  }

  return {
    mode: "interval",
    intervalMs: parseIntervalMs(
      env[worker.intervalEnv],
      worker.defaultIntervalMs,
      worker.intervalEnv,
    ),
  };
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

export function getWorkerConfig(
  worker,
  env = process.env,
  { safeLocalDefaults = false } = {},
) {
  const schedule = getWorkerSchedule(worker, env);
  const hasLocalRunOnStartDefault =
    safeLocalDefaults &&
    Object.prototype.hasOwnProperty.call(worker, "localDevRunOnStartDefault");
  let runOnStartDefault = hasLocalRunOnStartDefault
    ? worker.localDevRunOnStartDefault
    : worker.runOnStartDefault;
  if (schedule.mode === "cron" && !hasLocalRunOnStartDefault) {
    runOnStartDefault = worker.cronRunOnStartDefault ?? false;
  }
  const runOnStartValue =
    env[worker.runOnStartEnv] ??
    (worker.runOnStartDefault && !hasLocalRunOnStartDefault
      ? env.WORKER_RUN_ON_START
      : undefined);

  return {
    ...schedule,
    runOnStart: parseBoolean(
      runOnStartValue,
      runOnStartDefault,
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

export function parseRunnerArgs(
  args,
  env = process.env,
  definitions = workerDefinitions,
) {
  const positional = [];
  let runOnce = parseBoolean(env.WORKER_RUN_ONCE, false, "WORKER_RUN_ONCE");
  let safeLocalDefaults = false;

  for (const arg of args) {
    if (arg === "--once") {
      runOnce = true;
    } else if (arg === "--safe-local-defaults") {
      safeLocalDefaults = true;
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
    workerNames: resolveWorkerNames(positional[0] || "all", definitions),
    runOnce,
    safeLocalDefaults,
    exitOnError: parseBoolean(
      env.WORKER_EXIT_ON_ERROR,
      false,
      "WORKER_EXIT_ON_ERROR",
    ),
  };
}

export async function runWorkersOnce(
  workerNames,
  {
    exitOnError = false,
    definitions = workerDefinitions,
    log = logger,
  } = {},
) {
  const results = [];
  for (const name of workerNames) {
    const worker = definitions[name];
    const state = { running: false };
    results.push(
      await runWorkerOnce(state, worker, {
        exitOnError,
        log,
        trigger: "once",
      }),
    );
  }
  return results;
}

async function waitForActiveRuns(activeRuns, log, timeoutMs) {
  if (activeRuns.size === 0) return;

  let timeoutId;
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve("timeout"), timeoutMs);
  });
  const done = Promise.allSettled([...activeRuns]).then(() => "done");
  const result = await Promise.race([done, timeout]);
  clearTimeout(timeoutId);

  if (result === "timeout") {
    log.error("worker-runner-shutdown-timeout", {
      activeRuns: activeRuns.size,
      timeoutMs,
    });
  }
}

export function startRunner(
  workerNames,
  {
    env = process.env,
    exitOnError = false,
    safeLocalDefaults = false,
    definitions = workerDefinitions,
    closePool = () => pool.end(),
    exitProcess = (exitCode) => process.exit(exitCode),
    log = logger,
    setIntervalFn = setInterval,
    clearIntervalFn = clearInterval,
    setTimeoutFn = setTimeout,
    clearTimeoutFn = clearTimeout,
  } = {},
) {
  const timers = [];
  const timerClearers = new Map();
  const states = new Map();
  const activeRuns = new Set();
  let stopping = false;

  const addTimer = (timer, clearFn) => {
    timers.push(timer);
    timerClearers.set(timer, clearFn);
    return timer;
  };

  const removeTimer = (timer) => {
    timerClearers.delete(timer);
    const index = timers.indexOf(timer);
    if (index >= 0) timers.splice(index, 1);
  };

  const logNextIntervalRun = (worker, config) => {
    log.info("worker-runner-next-run", {
      worker: worker.name,
      scheduleMode: "interval",
      nextRunAt: new Date(Date.now() + config.intervalMs).toISOString(),
      intervalMs: config.intervalMs,
    });
  };

  const invoke = (worker, state, trigger, config, onSettled) => {
    if (stopping) return;

    const promise = runWorkerOnce(state, worker, {
      exitOnError,
      trigger,
      log,
    })
      .then((result) => {
        if (
          !stopping &&
          result.status !== "skipped" &&
          config.mode === "interval"
        ) {
          logNextIntervalRun(worker, config);
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
        if (!stopping && onSettled) onSettled();
      });

    activeRuns.add(promise);
  };

  const scheduleNextCronRun = (worker, state, config, from = new Date()) => {
    if (stopping) return;

    const nextRunAt = getNextCronRunAt(config.cron, from);
    const delayMs = Math.max(0, nextRunAt.getTime() - Date.now());
    log.info("worker-runner-next-run", {
      worker: worker.name,
      scheduleMode: "cron",
      cronExpression: config.cronExpression,
      nextRunAt: nextRunAt.toISOString(),
      delayMs,
    });

    const timer = setTimeoutFn(() => {
      removeTimer(timer);
      invoke(worker, state, "cron", config, () =>
        scheduleNextCronRun(worker, state, config),
      );
    }, delayMs);
    addTimer(timer, clearTimeoutFn);
  };

  async function stop(exitCode = 0, signal = "manual") {
    if (stopping) return;
    stopping = true;
    log.info("worker-runner-stopping", { signal });
    process.off("SIGINT", sigintHandler);
    process.off("SIGTERM", sigtermHandler);

    for (const timer of [...timers]) {
      const clearTimer = timerClearers.get(timer) || clearIntervalFn;
      clearTimer(timer);
      removeTimer(timer);
    }
    await waitForActiveRuns(activeRuns, log, SHUTDOWN_TIMEOUT_MS);

    try {
      await closePool();
    } catch (error) {
      log.error("worker-runner-pool-close-failure", {
        error: error.message,
      });
      exitCode = exitCode || 1;
    }

    exitProcess(exitCode);
  }

  for (const name of workerNames) {
    const worker = definitions[name];
    const config = getWorkerConfig(worker, env, { safeLocalDefaults });
    const state = { running: false };
    states.set(name, state);

    log.info("worker-runner-worker-started", {
      worker: worker.name,
      scheduleMode: config.mode,
      cronExpression: config.cronExpression,
      intervalMs: config.intervalMs,
      runOnStart: config.runOnStart,
      exitOnError,
    });

    if (config.mode === "cron") {
      if (config.runOnStart) {
        invoke(worker, state, "startup", config, () =>
          scheduleNextCronRun(worker, state, config),
        );
      } else {
        scheduleNextCronRun(worker, state, config);
      }
    } else {
      if (config.runOnStart) {
        invoke(worker, state, "startup", config);
      } else {
        logNextIntervalRun(worker, config);
      }

      addTimer(
        setIntervalFn(
          () => invoke(worker, state, "interval", config),
          config.intervalMs,
        ),
        clearIntervalFn,
      );
    }
  }

  const sigintHandler = () => void stop(0, "SIGINT");
  const sigtermHandler = () => void stop(0, "SIGTERM");
  process.once("SIGINT", sigintHandler);
  process.once("SIGTERM", sigtermHandler);

  return {
    stop,
    timers,
    states,
    activeRuns,
  };
}

function printHelp() {
  const workers = Object.keys(workerDefinitions).join(", ");
  console.log(
    `Usage: node src/runner.js [worker|all] [--once] [--safe-local-defaults]\n`,
  );
  console.log(`Workers: ${workers}`);
  console.log(`Default scheduling uses five-field cron expressions.`);
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
      safeLocalDefaults: parsed.safeLocalDefaults,
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

if (isNodeEntrypoint(import.meta.url)) {
  void main();
}
