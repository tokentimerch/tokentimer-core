"use strict";

const crypto = require("node:crypto");
const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");
const { loadApiTokenFromFile, parseApiUrl } = require("./config");
const {
  MAX_ATTEMPTS,
  MAX_RESPONSE_BYTES,
  MAX_TOTAL_DELAY_MS,
  REQUEST_TIMEOUT_MS,
  isTransientError,
  isTransientStatus,
  parseRetryAfter,
  retryDelay,
} = require("./observation-reporter");

function commandClientError(code) {
  const error = new Error(`Controller provisioning command failed: ${code}`);
  error.code = code;
  return error;
}

async function boundedJson(response) {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
    throw commandClientError("CONTROLLER_PROVISIONING_INVALID_RESPONSE");
  }
  try { return JSON.parse(text); } catch (_) {
    throw commandClientError("CONTROLLER_PROVISIONING_INVALID_RESPONSE");
  }
}

function stableId(jobId, stage) {
  return crypto.createHash("sha256").update(`${jobId}:${stage}`, "utf8").digest("hex").slice(0, 48);
}

function stableOccurredAt(jobId, stage) {
  const value = crypto.createHash("sha256").update(`${jobId}:${stage}:time`, "utf8").digest().readUInt32BE(0);
  const start = Date.UTC(2020, 0, 1);
  const span = 20 * 366 * 24 * 60 * 60 * 1000;
  return new Date(start + (value / 0xffffffff) * span).toISOString();
}

function validateCommand(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).length !== 1 || !value.command || typeof value.command !== "object") {
    throw commandClientError("CONTROLLER_PROVISIONING_INVALID_RESPONSE");
  }
  const command = value.command;
  const allowed = new Set([
    "schemaVersion", "workspaceId", "clusterId", "jobId", "managedCertificateId",
    "namespace", "certificateName", "secretName", "issuerRef", "dnsNames",
  ]);
  if (Object.keys(command).some((key) => !allowed.has(key)) || command.schemaVersion !== 1 ||
      !Array.isArray(command.dnsNames) || !command.issuerRef || typeof command.issuerRef !== "object") {
    throw commandClientError("CONTROLLER_PROVISIONING_INVALID_RESPONSE");
  }
  if (containsPrivateKeyMaterial(command)) {
    throw commandClientError("PRIVATE_KEY_MATERIAL_REJECTED");
  }
  return command;
}

function createControllerProvisioningCommandClient({
  apiTokenFile,
  apiUrl,
  fetchImpl = globalThis.fetch,
  fsOptions,
  now = () => Date.now(),
  random = Math.random,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  requestTimeoutMs = REQUEST_TIMEOUT_MS,
  sleep,
} = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetch is required");
  const root = parseApiUrl(apiUrl);
  const commandEndpoint = new URL("/api/v1/certops/executor/provisioning-commands/next", root).toString();
  let acceptingWork = false;
  let started = false;
  const abortControllers = new Map();
  const retryWaiters = new Set();

  function stoppingError() { return commandClientError("CONTROLLER_PROVISIONING_STOPPING"); }
  function cancelRetryWaits() {
    for (const waiter of [...retryWaiters]) waiter.cancel();
  }
  async function sleepBeforeRetry(delay) {
    if (!acceptingWork) throw stoppingError();
    let rejectCancellation;
    const cancellation = new Promise((_, reject) => { rejectCancellation = reject; });
    const waiter = {
      timeout: null,
      cancel() {
        if (waiter.timeout !== null) clearTimeoutFn(waiter.timeout);
        retryWaiters.delete(waiter);
        rejectCancellation(stoppingError());
      },
    };
    retryWaiters.add(waiter);
    try {
      const wait = typeof sleep === "function" ? Promise.resolve(sleep(delay)) : new Promise((resolve) => {
        waiter.timeout = setTimeoutFn(resolve, delay);
      });
      await Promise.race([wait, cancellation]);
    } finally {
      if (waiter.timeout !== null) clearTimeoutFn(waiter.timeout);
      retryWaiters.delete(waiter);
    }
    if (!acceptingWork) throw stoppingError();
  }
  async function request(url, body = undefined) {
    let totalDelay = 0;
    let lastError = null;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      if (!acceptingWork) throw stoppingError();
      const controller = new AbortController();
      const state = { timeout: null, timedOut: false, stopping: false };
      abortControllers.set(controller, state);
      state.timeout = setTimeoutFn(() => { state.timedOut = true; controller.abort(); }, requestTimeoutMs);
      let delay = null;
      try {
        const token = loadApiTokenFromFile(apiTokenFile, fsOptions);
        const response = await fetchImpl(url, {
          method: "POST", redirect: "error", signal: controller.signal,
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        if (state.stopping) throw stoppingError();
        if (response.status === 204) return null;
        if (response.status >= 200 && response.status < 300) return boundedJson(response);
        if (!isTransientStatus(response.status)) throw commandClientError(`CONTROLLER_PROVISIONING_HTTP_${response.status}`);
        lastError = commandClientError(`CONTROLLER_PROVISIONING_HTTP_${response.status}`);
        delay = response.status === 429
          ? parseRetryAfter(response.headers.get("retry-after"), now()) ?? retryDelay(attempt, random)
          : retryDelay(attempt, random);
      } catch (error) {
        if (!acceptingWork || state.stopping) throw stoppingError();
        if (!state.timedOut && !isTransientError(error)) throw error;
        lastError = commandClientError("CONTROLLER_PROVISIONING_TRANSPORT_FAILED");
        delay = retryDelay(attempt, random);
      } finally {
        clearTimeoutFn(state.timeout);
        abortControllers.delete(controller);
      }
      if (delay === null || attempt === MAX_ATTEMPTS - 1 || totalDelay + delay > MAX_TOTAL_DELAY_MS) break;
      totalDelay += delay;
      await sleepBeforeRetry(delay);
    }
    throw lastError || commandClientError("CONTROLLER_PROVISIONING_TRANSPORT_FAILED");
  }
  return Object.freeze({
    async close() {
      acceptingWork = false;
      for (const [controller, state] of abortControllers) {
        state.stopping = true;
        clearTimeoutFn(state.timeout);
        controller.abort();
      }
      cancelRetryWaits();
    },
    isAlive: () => true,
    isReady: () => started && acceptingWork,
    async nextCommand() {
      const result = await request(commandEndpoint, {});
      return result === null ? null : validateCommand(result);
    },
    async reportEvent(command, stage, { status, eventType, message, evidence } = {}) {
      const event = {
        schemaVersion: 1,
        eventId: stableId(command.jobId, stage),
        jobId: command.jobId,
        workspaceId: command.workspaceId,
        certificateId: command.managedCertificateId,
        executorId: command.clusterId,
        status,
        eventType,
        occurredAt: stableOccurredAt(command.jobId, stage),
        ...(message ? { message } : {}),
        ...(evidence ? { evidence: [evidence] } : {}),
      };
      return request(new URL(`/api/v1/certops/jobs/${encodeURIComponent(command.jobId)}/events`, root).toString(), event);
    },
    async start() {
      loadApiTokenFromFile(apiTokenFile, fsOptions);
      started = true;
      acceptingWork = true;
    },
    async stopAcceptingWork() { acceptingWork = false; },
  });
}

module.exports = {
  createControllerProvisioningCommandClient,
  stableId,
  stableOccurredAt,
  validateCommand,
};
