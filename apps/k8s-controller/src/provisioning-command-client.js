"use strict";

const crypto = require("node:crypto");
const { containsPrivateKeyMaterial } = require("@tokentimer/log-scrub");
const { loadApiTokenFromFile, parseApiUrl } = require("./config");
const {
  MAX_ATTEMPTS,
  MAX_TOTAL_DELAY_MS,
  REQUEST_TIMEOUT_MS,
  isTransientError,
  isTransientStatus,
  parseRetryAfter,
  readBoundedJsonResponse,
  retryDelay,
} = require("./observation-reporter");

// These values mirror the public M3-A7 provisioning command schema. The
// response additionally carries up to three persisted ISO-8601 event times,
// so it cannot share the observation reporter's deliberately smaller 8 KiB
// response limit.
const PROVISIONING_COMMAND_SCHEMA_LIMITS = Object.freeze({
  clusterOrNamespaceLength: 63,
  dnsNameCount: 100,
  dnsNameLength: 253,
  kubernetesNameLength: 253,
});
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const RFC1123_LABEL_PATTERN = /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/;
const RFC1123_SUBDOMAIN_PATTERN =
  /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/;
const DNS_NAME_PATTERN =
  /^(\*\.)?[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)*$/;
const RFC3339_TIMESTAMP_PATTERN =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/;
const MAX_EVENT_TIMESTAMP_LENGTH = 64;
const RESPONSE_FIELDS = new Set(["command", "eventTimestamps"]);
const COMMAND_FIELDS = new Set([
  "schemaVersion", "workspaceId", "clusterId", "jobId", "managedCertificateId",
  "namespace", "certificateName", "secretName", "issuerRef", "dnsNames",
]);
const ISSUER_FIELDS = new Set(["group", "kind", "name"]);
const EVENT_TIMESTAMP_FIELDS = new Set(["started", "completed", "failed"]);

function maximumKubernetesName(index = 0) {
  const suffix = index.toString(36);
  return [
    `${"a".repeat(63 - suffix.length)}${suffix}`,
    "b".repeat(63),
    "c".repeat(63),
    "d".repeat(61),
  ].join(".");
}

function maximumProvisioningResponseEnvelope() {
  const limits = PROVISIONING_COMMAND_SCHEMA_LIMITS;
  const timestamp = "2026-07-21T12:00:00.000Z";
  return {
    command: {
      schemaVersion: 1,
      workspaceId: "00000000-0000-4000-8000-000000000000",
      clusterId: "a".repeat(limits.clusterOrNamespaceLength),
      jobId: "00000000-0000-4000-8000-000000000001",
      managedCertificateId: "00000000-0000-4000-8000-000000000002",
      namespace: "a".repeat(limits.clusterOrNamespaceLength),
      certificateName: maximumKubernetesName(0),
      secretName: maximumKubernetesName(1),
      issuerRef: {
        group: maximumKubernetesName(2),
        kind: "ClusterIssuer",
        name: maximumKubernetesName(3),
      },
      dnsNames: Array.from(
        { length: limits.dnsNameCount },
        (_, index) => maximumKubernetesName(index),
      ),
    },
    eventTimestamps: {
      started: timestamp,
      completed: timestamp,
      failed: timestamp,
    },
  };
}

// This is the exact compact JSON size of the largest public command envelope
// the API can emit: 100 x 253-byte DNS identities plus all fixed command
// fields and the three first-seen persisted timestamps.
const MAX_PROVISIONING_RESPONSE_BYTES = Buffer.byteLength(
  JSON.stringify(maximumProvisioningResponseEnvelope()),
  "utf8",
);

function commandClientError(code) {
  const error = new Error(`Controller provisioning command failed: ${code}`);
  error.code = code;
  return error;
}

function stableId(jobId, stage) {
  return crypto.createHash("sha256").update(`${jobId}:${stage}`, "utf8").digest("hex").slice(0, 48);
}

function isPlainObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function invalidResponse() {
  throw commandClientError("CONTROLLER_PROVISIONING_INVALID_RESPONSE");
}

function assertKnownFields(value, allowed) {
  if (!isPlainObject(value) || Object.keys(value).some((field) => !allowed.has(field))) {
    invalidResponse();
  }
}

function uuid(value) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) invalidResponse();
  return value.toLowerCase();
}

function kubernetesLabel(value) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > PROVISIONING_COMMAND_SCHEMA_LIMITS.clusterOrNamespaceLength ||
    !RFC1123_LABEL_PATTERN.test(value)
  ) {
    invalidResponse();
  }
  return value;
}

function kubernetesName(value) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > PROVISIONING_COMMAND_SCHEMA_LIMITS.kubernetesNameLength ||
    !RFC1123_SUBDOMAIN_PATTERN.test(value) ||
    !value.split(".").every((label) => label.length <= 63)
  ) {
    invalidResponse();
  }
  return value;
}

function dnsNames(value) {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > PROVISIONING_COMMAND_SCHEMA_LIMITS.dnsNameCount
  ) {
    invalidResponse();
  }
  const normalized = [];
  const identities = new Set();
  for (const item of value) {
    if (
      typeof item !== "string" ||
      item.length < 1 ||
      item.length > PROVISIONING_COMMAND_SCHEMA_LIMITS.dnsNameLength ||
      !DNS_NAME_PATTERN.test(item)
    ) {
      invalidResponse();
    }
    const identity = item.toLowerCase();
    if (identities.has(identity)) invalidResponse();
    identities.add(identity);
    normalized.push(item);
  }
  return Object.freeze(normalized);
}

function issuerRef(value) {
  assertKnownFields(value, ISSUER_FIELDS);
  if (value.kind !== "Issuer" && value.kind !== "ClusterIssuer") invalidResponse();
  return Object.freeze({
    group: kubernetesName(value.group),
    kind: value.kind,
    name: kubernetesName(value.name),
  });
}

function rfc3339Timestamp(value) {
  if (typeof value !== "string" || value.length > MAX_EVENT_TIMESTAMP_LENGTH) {
    invalidResponse();
  }
  const match = RFC3339_TIMESTAMP_PATTERN.exec(value);
  const timestamp = new Date(value);
  const offsetHours = Number(match?.[10]);
  const offsetMinutes = Number(match?.[11]);
  if (
    !match ||
    Number.isNaN(timestamp.getTime()) ||
    Number(match[1]) < 2000 ||
    Number(match[1]) > 2100 ||
    Number(match[2]) < 1 ||
    Number(match[2]) > 12 ||
    Number(match[3]) < 1 ||
    Number(match[3]) > new Date(Date.UTC(Number(match[1]), Number(match[2]), 0)).getUTCDate() ||
    Number(match[4]) > 23 ||
    Number(match[5]) > 59 ||
    Number(match[6]) > 59 ||
    (match[8] !== "Z" &&
      (offsetHours > 14 ||
        offsetMinutes > 59 ||
        (offsetHours === 14 && offsetMinutes !== 0)))
  ) {
    invalidResponse();
  }
  return timestamp.toISOString();
}

function validateCommand(value) {
  if (containsPrivateKeyMaterial(value)) {
    throw commandClientError("PRIVATE_KEY_MATERIAL_REJECTED");
  }
  assertKnownFields(value, RESPONSE_FIELDS);
  assertKnownFields(value.command, COMMAND_FIELDS);
  const command = value.command;
  if (command.schemaVersion !== 1) invalidResponse();

  const normalizedCommand = Object.freeze({
    schemaVersion: 1,
    workspaceId: uuid(command.workspaceId),
    clusterId: kubernetesLabel(command.clusterId),
    jobId: uuid(command.jobId),
    managedCertificateId: uuid(command.managedCertificateId),
    namespace: kubernetesLabel(command.namespace),
    certificateName: kubernetesName(command.certificateName),
    secretName: kubernetesName(command.secretName),
    issuerRef: issuerRef(command.issuerRef),
    dnsNames: dnsNames(command.dnsNames),
  });

  const eventTimestamps = value.eventTimestamps === undefined ? {} : value.eventTimestamps;
  assertKnownFields(eventTimestamps, EVENT_TIMESTAMP_FIELDS);
  const normalizedEventTimestamps = Object.freeze(Object.fromEntries(
    Object.entries(eventTimestamps).map(([stage, timestamp]) => [
      stage,
      rfc3339Timestamp(timestamp),
    ]),
  ));
  const normalized = Object.freeze({
    command: normalizedCommand,
    eventTimestamps: normalizedEventTimestamps,
  });
  if (containsPrivateKeyMaterial(normalized)) {
    throw commandClientError("PRIVATE_KEY_MATERIAL_REJECTED");
  }
  return normalized;
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
  clock = () => new Date(),
} = {}) {
  if (typeof fetchImpl !== "function") throw new TypeError("fetch is required");
  const root = parseApiUrl(apiUrl);
  const commandEndpoint = new URL("/api/v1/certops/executor/provisioning-commands/next", root).toString();
  let acceptingWork = false;
  let started = false;
  const abortControllers = new Map();
  const retryWaiters = new Set();
  const stageTimestampCache = new Map();
  const MAX_STAGE_TIMESTAMPS = 256;

  function stageTimestampKey(command, stage) {
    return `${command.jobId}:${stage}`;
  }
  function rememberStageTimestamp(command, stage, timestamp) {
    if (typeof timestamp !== "string" || Number.isNaN(Date.parse(timestamp))) return null;
    const key = stageTimestampKey(command, stage);
    stageTimestampCache.delete(key);
    stageTimestampCache.set(key, timestamp);
    while (stageTimestampCache.size > MAX_STAGE_TIMESTAMPS) {
      stageTimestampCache.delete(stageTimestampCache.keys().next().value);
    }
    return timestamp;
  }
  function occurredAtFor(command, stage) {
    const persisted = command.eventTimestamps?.[stage];
    const cached = stageTimestampCache.get(stageTimestampKey(command, stage));
    if (persisted || cached) return rememberStageTimestamp(command, stage, persisted || cached);

    const current = clock().toISOString();
    const started = command.eventTimestamps?.started ||
      stageTimestampCache.get(stageTimestampKey(command, "started"));
    // A terminal event may be retried after an injected/system clock moves
    // backwards. Preserve a truthful timeline by using the known start as the
    // lower bound, while still using the current clock when it is later.
    const timestamp = ["completed", "failed"].includes(stage) && started &&
      Date.parse(current) < Date.parse(started)
      ? started
      : current;
    return rememberStageTimestamp(command, stage, timestamp);
  }

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
        if (response.status >= 200 && response.status < 300) {
          return await readBoundedJsonResponse(response, {
            errorFactory: commandClientError,
            maxResponseBytes: MAX_PROVISIONING_RESPONSE_BYTES,
            invalidResponseCode: "CONTROLLER_PROVISIONING_INVALID_RESPONSE",
          });
        }
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
    async authorizeMutation(command) {
      if (containsPrivateKeyMaterial(command)) {
        throw commandClientError("PRIVATE_KEY_MATERIAL_REJECTED");
      }
      const jobId = uuid(command?.jobId);
      return request(
        new URL(
          `/api/v1/certops/executor/provisioning-commands/${encodeURIComponent(jobId)}/authorize-mutation`,
          root,
        ).toString(),
        {},
      );
    },
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
      if (result === null) return null;
      const delivery = validateCommand(result);
      for (const [stage, timestamp] of Object.entries(delivery.eventTimestamps)) {
        rememberStageTimestamp(delivery.command, stage, timestamp);
      }
      return Object.freeze({
        ...delivery.command,
        eventTimestamps: delivery.eventTimestamps,
      });
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
        occurredAt: occurredAtFor(command, stage),
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
  MAX_PROVISIONING_RESPONSE_BYTES,
  PROVISIONING_COMMAND_SCHEMA_LIMITS,
  createControllerProvisioningCommandClient,
  maximumProvisioningResponseEnvelope,
  stableId,
  validateCommand,
};
