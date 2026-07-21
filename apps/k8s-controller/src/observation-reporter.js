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
const TRANSIENT_NETWORK_CODES = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "ETIMEDOUT",
  "EAI_AGAIN",
  "ENOTFOUND",
  "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT",
  "UND_ERR_SOCKET",
]);

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
  const visited = new Set();
  let current = error;
  for (let depth = 0; current && depth < 4 && !visited.has(current); depth += 1) {
    visited.add(current);
    if (typeof current.code === "string" && TRANSIENT_NETWORK_CODES.has(current.code)) {
      return true;
    }
    current = current.cause;
  }
  return false;
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

async function readBoundedJsonResponse(response, {
  errorFactory = reporterError,
  maxResponseBytes = MAX_RESPONSE_BYTES,
  allowTextFallback = false,
  invalidResponseCode = "CONTROLLER_REPORTER_INVALID_RESPONSE",
} = {}) {
  let text;
  const body = response?.body;
  if (body && typeof body.getReader === "function") {
    const reader = body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        totalBytes += chunk.length;
        if (totalBytes > maxResponseBytes) {
          if (typeof reader.cancel === "function") {
            try {
              await reader.cancel();
            } catch (_error) {
              // The response is already rejected; cancellation is best effort.
            }
          }
          throw errorFactory(invalidResponseCode);
        }
        chunks.push(chunk);
      }
      text = Buffer.concat(chunks, totalBytes).toString("utf8");
    } catch (error) {
      if (error?.code === invalidResponseCode) throw error;
      // Preserve transport failures so callers can apply their normal retry
      // classification while the request timeout remains active.
      throw error;
    } finally {
      if (typeof reader.releaseLock === "function") reader.releaseLock();
    }
  } else if (allowTextFallback) {
    // Test doubles without a Fetch ReadableStream retain the legacy text()
    // path. Real Fetch responses always use the bounded streaming path above.
    try {
      text = await response.text();
    } catch (_error) {
      throw errorFactory(invalidResponseCode);
    }
    if (Buffer.byteLength(text, "utf8") > maxResponseBytes) {
      throw errorFactory(invalidResponseCode);
    }
  } else {
    throw errorFactory(invalidResponseCode);
  }
  try {
    return JSON.parse(text);
  } catch (_error) {
    throw errorFactory(invalidResponseCode);
  }
}

async function boundedJson(response) {
  return readBoundedJsonResponse(response, { allowTextFallback: true });
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
  sleep,
} = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetch is required");
  const normalizedApiUrl = parseApiUrl(apiUrl);
  const endpoint = new URL("/api/v1/certops/executor/observations", normalizedApiUrl).toString();
  let acceptingWork = false;
  let started = false;
  const abortControllers = new Map();
  const retryWaiters = new Set();

  function stoppingError() {
    return reporterError("CONTROLLER_REPORTER_STOPPING");
  }

  function stopInFlightRequests() {
    for (const [controller, state] of abortControllers) {
      state.stopping = true;
      if (state.timeout !== null) clearTimeoutFn(state.timeout);
      controller.abort();
    }
  }

  function cancelRetryWaits() {
    for (const waiter of [...retryWaiters]) {
      waiter.cancel();
    }
  }

  async function sleepBeforeRetry(delay) {
    if (!acceptingWork) throw stoppingError();
    let rejectCancellation;
    const cancellation = new Promise((_, reject) => {
      rejectCancellation = reject;
    });
    const waiter = {
      timeout: null,
      cancel() {
        if (waiter.timeout !== null) clearTimeoutFn(waiter.timeout);
        retryWaiters.delete(waiter);
        rejectCancellation(stoppingError());
      },
    };
    retryWaiters.add(waiter);
    let wait;
    try {
      // Production waits use this tracked timer; the injected sleep seam keeps
      // deterministic unit tests fast without changing delivery semantics.
      wait = typeof sleep === "function"
        ? Promise.resolve(sleep(delay))
        : new Promise((resolve) => {
          waiter.timeout = setTimeoutFn(resolve, delay);
        });
      await Promise.race([wait, cancellation]);
    } finally {
      if (waiter.timeout !== null) clearTimeoutFn(waiter.timeout);
      retryWaiters.delete(waiter);
    }
    if (!acceptingWork) throw stoppingError();
  }

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
      if (!acceptingWork) throw stoppingError();
      const controller = new AbortController();
      const requestState = { stopping: false, timedOut: false, timeout: null };
      abortControllers.set(controller, requestState);
      const timeout = setTimeoutFn(() => {
        requestState.timedOut = true;
        controller.abort();
      }, requestTimeoutMs);
      requestState.timeout = timeout;
      let delay = null;
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
        if (requestState.stopping) throw stoppingError();
        if (response.status === 200 || response.status === 201) {
          return validateResponse(await boundedJson(response));
        }
        if (!acceptingWork) throw stoppingError();
        if (!isTransientStatus(response.status)) {
          throw reporterError(`CONTROLLER_REPORTER_HTTP_${response.status}`);
        }
        lastError = reporterError(`CONTROLLER_REPORTER_HTTP_${response.status}`);
        const retryAfter = response.status === 429
          ? parseRetryAfter(response.headers.get("retry-after"), now())
          : null;
        delay = retryAfter ?? retryDelay(attempt, random);
      } catch (error) {
        if (!acceptingWork || requestState.stopping) throw stoppingError();
        // A timeout we initiated is retriable; an arbitrary AbortError is not.
        if (!requestState.timedOut && !isTransientError(error)) throw error;
        lastError = reporterError("CONTROLLER_REPORTER_TRANSPORT_FAILED");
        delay = retryDelay(attempt, random);
      } finally {
        clearTimeoutFn(timeout);
        abortControllers.delete(controller);
      }
      if (!acceptingWork) throw stoppingError();
      if (delay === null || attempt === MAX_ATTEMPTS - 1 || totalDelay + delay > MAX_TOTAL_DELAY_MS) {
        break;
      }
      totalDelay += delay;
      await sleepBeforeRetry(delay);
    }
    throw lastError || reporterError("CONTROLLER_REPORTER_TRANSPORT_FAILED");
  }

  return Object.freeze({
    async close() {
      acceptingWork = false;
      stopInFlightRequests();
      cancelRetryWaits();
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
  TRANSIENT_NETWORK_CODES,
  boundedJson,
  readBoundedJsonResponse,
  createControllerObservationReporter,
  isTransientError,
  isTransientStatus,
  parseRetryAfter,
  retryDelay,
  validateResponse,
};
