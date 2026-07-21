"use strict";

const {
  loadApiTokenFromFile,
  parseApiUrl,
} = require("./config");
const { createObservationEnvelope } = require("./observation-envelope");

const MAX_ATTEMPTS = 4;
const MAX_RETRY_AFTER_MS = 30_000;
const MAX_TOTAL_DELAY_MS = 60_000;
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 8 * 1024;

function reporterError(code) {
  const error = new Error(`Controller observation report failed: ${code}`);
  error.code = code;
  return error;
}

function isUuid(value) {
  return typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

function parseRetryAfter(value, nowMs = Date.now()) {
  if (typeof value !== "string") return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(MAX_RETRY_AFTER_MS, Math.floor(seconds * 1000));
  }
  const date = Date.parse(value);
  if (Number.isNaN(date)) return null;
  return Math.min(MAX_RETRY_AFTER_MS, Math.max(0, date - nowMs));
}

function retryDelay(attempt, random = Math.random) {
  const base = Math.min(10_000, 250 * 2 ** Math.max(0, attempt));
  return Math.min(MAX_RETRY_AFTER_MS, base + Math.floor(Math.max(0, Math.min(1, random())) * 250));
}

function isTransientStatus(status) {
  return status === 408 || status === 429 || status >= 500;
}

function isTransientError(error) {
  return error?.name === "AbortError" ||
    ["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EAI_AGAIN", "ENOTFOUND"].includes(error?.code);
}

function validateResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw reporterError("CONTROLLER_REPORTER_INVALID_RESPONSE");
  }
  const allowed = new Set([
    "managedCertificateId",
    "targetId",
    "certificateInstanceId",
    "duplicate",
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)) || typeof value.duplicate !== "boolean") {
    throw reporterError("CONTROLLER_REPORTER_INVALID_RESPONSE");
  }
  for (const field of ["managedCertificateId", "targetId", "certificateInstanceId"]) {
    if (value[field] !== null && !isUuid(value[field])) {
      throw reporterError("CONTROLLER_REPORTER_INVALID_RESPONSE");
    }
  }
  return {
    managedCertificateId: value.managedCertificateId || null,
    targetId: value.targetId || null,
    certificateInstanceId: value.certificateInstanceId || null,
    duplicate: value.duplicate,
  };
}

async function boundedJson(response) {
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_RESPONSE_BYTES) {
    throw reporterError("CONTROLLER_REPORTER_INVALID_RESPONSE");
  }
  try {
    return JSON.parse(text);
  } catch (_error) {
    throw reporterError("CONTROLLER_REPORTER_INVALID_RESPONSE");
  }
}

function createControllerObservationReporter({
  apiTokenFile,
  apiUrl,
  fetchImpl = globalThis.fetch,
  fsOptions,
  now = () => Date.now(),
  random = Math.random,
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  requestTimeoutMs = REQUEST_TIMEOUT_MS,
  sleep = (delay) => new Promise((resolve) => setTimeoutFn(resolve, delay)),
} = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetch is required");
  const normalizedApiUrl = parseApiUrl(apiUrl);
  const endpoint = new URL("/api/v1/certops/executor/observations", normalizedApiUrl).toString();
  let acceptingWork = false;
  let started = false;
  const abortControllers = new Set();

  async function report(observation, { idempotencyKey } = {}) {
    if (!acceptingWork) throw reporterError("CONTROLLER_REPORTER_STOPPING");
    const envelope = createObservationEnvelope(observation);
    if (idempotencyKey && idempotencyKey !== envelope.idempotencyKey) {
      throw reporterError("CONTROLLER_REPORTER_IDEMPOTENCY_MISMATCH");
    }
    const body = JSON.stringify(envelope);
    let totalDelay = 0;
    let lastError = null;
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt += 1) {
      if (!acceptingWork) throw reporterError("CONTROLLER_REPORTER_STOPPING");
      const controller = new AbortController();
      abortControllers.add(controller);
      const timeout = setTimeoutFn(() => controller.abort(), requestTimeoutMs);
      try {
        // Re-read the mounted credential for each delivery so Kubernetes Secret
        // volume rotation takes effect without ever retaining the token.
        const token = loadApiTokenFromFile(apiTokenFile, fsOptions);
        const response = await fetchImpl(endpoint, {
          method: "POST",
          redirect: "error",
          signal: controller.signal,
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            "Idempotency-Key": envelope.idempotencyKey,
          },
          body,
        });
        if (response.status === 200 || response.status === 201) {
          return validateResponse(await boundedJson(response));
        }
        if (!isTransientStatus(response.status)) {
          throw reporterError(`CONTROLLER_REPORTER_HTTP_${response.status}`);
        }
        lastError = reporterError(`CONTROLLER_REPORTER_HTTP_${response.status}`);
        const retryAfter = response.status === 429
          ? parseRetryAfter(response.headers.get("retry-after"), now())
          : null;
        const delay = retryAfter ?? retryDelay(attempt, random);
        if (attempt === MAX_ATTEMPTS - 1 || totalDelay + delay > MAX_TOTAL_DELAY_MS) break;
        totalDelay += delay;
        await sleep(delay);
      } catch (error) {
        if (!isTransientError(error)) throw error;
        lastError = reporterError("CONTROLLER_REPORTER_TRANSPORT_FAILED");
        const delay = retryDelay(attempt, random);
        if (attempt === MAX_ATTEMPTS - 1 || totalDelay + delay > MAX_TOTAL_DELAY_MS) break;
        totalDelay += delay;
        await sleep(delay);
      } finally {
        clearTimeoutFn(timeout);
        abortControllers.delete(controller);
      }
    }
    throw lastError || reporterError("CONTROLLER_REPORTER_TRANSPORT_FAILED");
  }

  return Object.freeze({
    async close() {
      acceptingWork = false;
      for (const controller of abortControllers) controller.abort();
    },
    isAlive: () => true,
    isReady: () => started && acceptingWork,
    async start() {
      // Validate initial mount readiness without caching the token.
      loadApiTokenFromFile(apiTokenFile, fsOptions);
      started = true;
      acceptingWork = true;
    },
    async stopAcceptingWork() {
      acceptingWork = false;
    },
    report,
  });
}

module.exports = {
  MAX_ATTEMPTS,
  MAX_RESPONSE_BYTES,
  MAX_RETRY_AFTER_MS,
  MAX_TOTAL_DELAY_MS,
  REQUEST_TIMEOUT_MS,
  createControllerObservationReporter,
  isTransientError,
  isTransientStatus,
  parseRetryAfter,
  retryDelay,
  validateResponse,
};
