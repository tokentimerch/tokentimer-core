"use strict";

/**
 * Outbound-only CertOps agent protocol client.
 *
 * This is the final agent-side wire boundary: every envelope is deep-scanned
 * for prohibited key material, generic secrets in allowed text fields are
 * redacted, and the complete schema shape is checked immediately before the
 * bytes are handed to transport. No agent job execution lives here.
 */

const https = require("node:https");
const { URL } = require("node:url");
const {
  assertNoPrivateKeyMaterial,
  redactGenericSecrets,
} = require("../../../log-scrub/secret-material.js");
const { defaultAgentLogger } = require("../logging");

const SCHEMA_VERSION = 1;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_OUTBOUND_ENVELOPE_BYTES = 512 * 1024;

const ROUTES = Object.freeze({
  REGISTER: "/api/v1/certops/agent/register",
  HEARTBEAT: "/api/v1/certops/agent/heartbeat",
  CLAIM: "/api/v1/certops/agent/jobs/claim",
  RESULTS: "/api/v1/certops/agent/jobs/results",
});

const MESSAGE_TYPES = Object.freeze({
  REGISTER: "register",
  HEARTBEAT: "heartbeat",
  CLAIM: "claim",
  RESULT: "result",
  EVIDENCE: "evidence",
});

class AgentProtocolError extends Error {
  constructor(message, code, options = {}) {
    super(message);
    this.name = "AgentProtocolError";
    this.code = code;
    if (options.status !== undefined) this.status = options.status;
    if (options.cause !== undefined) this.cause = options.cause;
  }
}

const AGENT_PROTOCOL_ERROR_CODES = Object.freeze({
  NETWORK_ERROR: "network_error",
  HTTP_ERROR: "http_error",
  RETIRED: "retired",
  INVALID_MESSAGE: "invalid_message",
  INVALID_RESPONSE: "invalid_response",
});

const PROTOCOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const ISO_DATE_TIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const CREDENTIAL_PATTERN = /^ttagent_([A-Za-z0-9_.:-]{1,128})_([A-Za-z0-9._~+\/-]{16,1024})$/;
const MESSAGE_TYPE_VALUES = new Set(Object.values(MESSAGE_TYPES));
const ACTION_VALUES = new Set(["renew", "deploy", "reload", "revoke", "noop"]);
const RESULT_STATUS_VALUES = new Set(["succeeded", "failed", "rejected", "blocked"]);
const REJECTION_REASON_VALUES = new Set([
  "job_integrity_failed",
  "job_replay_rejected",
  "target_out_of_scope",
  "command_not_allowlisted",
  "path_not_allowlisted",
  "ca_endpoint_not_allowlisted",
  "dns_zone_not_allowlisted",
  "dns_provider_not_allowlisted",
  "key_export_requested",
  "clock_drift_suspected",
]);
const EVENT_TYPE_VALUES = new Set([
  "certificate.observed",
  "deployment.checked",
  "deployment.updated",
  "validation.passed",
  "validation.failed",
  "policy.checked",
]);
const METADATA_NAME_PATTERN = /^(?!.*(?:[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy]|[Ee][Nn][Cc][Rr][Yy][Pp][Tt][Ee][Dd][-_]?[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy]|[Kk][Ee][Yy][-_]?[Mm][Aa][Tt][Ee][Rr][Ii][Aa][Ll]|[Pp][Ff][Xx][-_]?[Bb][Ll][Oo][Bb]|[Jj][Kk][Ss][-_]?[Bb][Ll][Oo][Bb]|[Tt][Ll][Ss][-_]?[Kk][Ee][Yy]|[Cc][Aa][-_]?[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy]|[Kk][Ee][Yy][Ss][Tt][Oo][Rr][Ee][-_]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][-_]?[Kk][Ee][Yy][-_]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Kk][Ee][Yy][-_]?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Kk][Ee][Yy][-_]?[Pp][Ee][Mm]|[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll]))[A-Za-z0-9_.:-]{1,64}$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isIsoDateTime(value) {
  return typeof value === "string" && ISO_DATE_TIME_PATTERN.test(value) && !Number.isNaN(Date.parse(value));
}

function checkExactObject(value, allowedKeys, requiredKeys, label, problems) {
  if (!isPlainObject(value)) {
    problems.push(`${label} must be an object`);
    return false;
  }
  for (const key of Object.keys(value)) {
    if (!allowedKeys.has(key)) problems.push(`${label} has unknown field "${key}"`);
  }
  for (const key of requiredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) {
      problems.push(`${label} is missing required field "${key}"`);
    }
  }
  return true;
}

function checkString(value, label, problems, { min = 0, max, pattern } = {}) {
  if (typeof value !== "string") {
    problems.push(`${label} must be a string`);
    return;
  }
  if (value.length < min) problems.push(`${label} must have at least ${min} characters`);
  if (max !== undefined && value.length > max) problems.push(`${label} exceeds ${max} characters`);
  if (pattern && !pattern.test(value)) problems.push(`${label} has an invalid format`);
}

function checkNullableString(value, label, problems, options = {}) {
  if (value === null) return;
  checkString(value, label, problems, options);
}

function validateMetadata(metadata, problems, label) {
  if (!Array.isArray(metadata)) {
    problems.push(`${label} must be an array`);
    return;
  }
  if (metadata.length > 32) problems.push(`${label} has more than 32 entries`);
  metadata.forEach((entry, index) => {
    const entryLabel = `${label}[${index}]`;
    if (!checkExactObject(entry, new Set(["name", "value"]), ["name", "value"], entryLabel, problems)) return;
    checkString(entry.name, `${entryLabel}.name`, problems, { min: 1, max: 64, pattern: METADATA_NAME_PATTERN });
    const value = entry.value;
    if (value !== null && typeof value !== "string" && typeof value !== "boolean" && (typeof value !== "number" || !Number.isFinite(value))) {
      problems.push(`${entryLabel}.value must be string, finite number, boolean, or null`);
    }
    if (typeof value === "string" && value.length > 512) {
      problems.push(`${entryLabel}.value exceeds 512 characters`);
    }
  });
}

function validateEnvelopeShape(message) {
  const problems = [];
  const envelopeKeys = new Set([
    "schemaVersion",
    "protocolVersion",
    "messageType",
    "agentId",
    "workspaceId",
    "sentAt",
    "clockOffsetMs",
    "body",
  ]);
  if (!checkExactObject(message, envelopeKeys, ["schemaVersion", "protocolVersion", "messageType", "agentId", "sentAt"], "message", problems)) {
    return problems;
  }
  if (message.schemaVersion !== SCHEMA_VERSION) problems.push(`schemaVersion must be ${SCHEMA_VERSION}`);
  checkString(message.protocolVersion, "protocolVersion", problems, { min: 1, max: 32, pattern: PROTOCOL_VERSION_PATTERN });
  if (!MESSAGE_TYPE_VALUES.has(message.messageType)) problems.push("messageType is invalid");
  checkString(message.agentId, "agentId", problems, { min: 1, max: 128, pattern: AGENT_ID_PATTERN });
  if (!isIsoDateTime(message.sentAt)) problems.push("sentAt must be an ISO date-time string");
  if (message.workspaceId !== undefined && message.workspaceId !== null) {
    checkString(message.workspaceId, "workspaceId", problems, { pattern: UUID_PATTERN });
  }
  if (message.clockOffsetMs !== undefined && message.clockOffsetMs !== null && !Number.isInteger(message.clockOffsetMs)) {
    problems.push("clockOffsetMs must be an integer or null");
  }

  if (!MESSAGE_TYPE_VALUES.has(message.messageType)) return problems;
  validateEnvelopeBody(message.messageType, message.body, problems);
  return problems;
}

function validateEnvelopeBody(messageType, body, problems) {
  const label = `${messageType} body`;
  if (!isPlainObject(body)) {
    problems.push(`${label} must be an object`);
    return;
  }

  if (messageType === MESSAGE_TYPES.REGISTER) {
    if (!checkExactObject(body, new Set(["bootstrapTokenId", "agentVersion", "hostname", "platform", "nodeVersion", "declaredTargetSelectors", "declaredCommandProfileNames"]), ["bootstrapTokenId", "agentVersion"], label, problems)) return;
    checkString(body.bootstrapTokenId, "register body.bootstrapTokenId", problems, { min: 1, max: 128, pattern: AGENT_ID_PATTERN });
    checkString(body.agentVersion, "register body.agentVersion", problems, { min: 1, max: 32 });
    if (body.hostname !== undefined) checkNullableString(body.hostname, "register body.hostname", problems, { max: 255 });
    if (body.platform !== undefined && body.platform !== null && !["linux", "darwin", "win32"].includes(body.platform)) problems.push("register body.platform is invalid");
    if (body.nodeVersion !== undefined) checkNullableString(body.nodeVersion, "register body.nodeVersion", problems, { max: 32 });
    validateStringArray(body.declaredTargetSelectors, "register body.declaredTargetSelectors", problems, 64, 256);
    validateStringArray(body.declaredCommandProfileNames, "register body.declaredCommandProfileNames", problems, 64, 128, AGENT_ID_PATTERN);
    return;
  }

  if (messageType === MESSAGE_TYPES.HEARTBEAT) {
    if (!checkExactObject(body, new Set(["agentVersion", "ntpSynced", "uptimeSeconds", "pinnedSigningKeyId"]), ["agentVersion"], label, problems)) return;
    checkString(body.agentVersion, "heartbeat body.agentVersion", problems, { min: 1, max: 32 });
    if (body.ntpSynced !== undefined && body.ntpSynced !== null && typeof body.ntpSynced !== "boolean") problems.push("heartbeat body.ntpSynced must be boolean or null");
    if (body.uptimeSeconds !== undefined && body.uptimeSeconds !== null && (!Number.isInteger(body.uptimeSeconds) || body.uptimeSeconds < 0)) problems.push("heartbeat body.uptimeSeconds must be a non-negative integer or null");
    if (body.pinnedSigningKeyId !== undefined) checkNullableString(body.pinnedSigningKeyId, "heartbeat body.pinnedSigningKeyId", problems, { max: 128, pattern: AGENT_ID_PATTERN });
    return;
  }

  if (messageType === MESSAGE_TYPES.CLAIM) {
    if (!checkExactObject(body, new Set(["maxJobs", "supportedActions"]), [], label, problems)) return;
    if (body.maxJobs !== undefined && (!Number.isInteger(body.maxJobs) || body.maxJobs < 1 || body.maxJobs > 16)) problems.push("claim body.maxJobs must be an integer between 1 and 16");
    if (body.supportedActions !== undefined) {
      if (!Array.isArray(body.supportedActions) || body.supportedActions.length > 16 || body.supportedActions.some((action) => !ACTION_VALUES.has(action))) {
        problems.push("claim body.supportedActions must contain at most 16 known actions");
      }
    }
    return;
  }

  if (messageType === MESSAGE_TYPES.RESULT) {
    if (!checkExactObject(body, new Set(["jobId", "attemptId", "status", "rejectionReason", "keyRotated", "errorMessage"]), ["jobId", "attemptId", "status"], label, problems)) return;
    checkString(body.jobId, "result body.jobId", problems, { min: 1, max: 128, pattern: AGENT_ID_PATTERN });
    checkString(body.attemptId, "result body.attemptId", problems, { min: 1, max: 128, pattern: AGENT_ID_PATTERN });
    if (!RESULT_STATUS_VALUES.has(body.status)) problems.push("result body.status is invalid");
    if (body.rejectionReason !== undefined && body.rejectionReason !== null && !REJECTION_REASON_VALUES.has(body.rejectionReason)) problems.push("result body.rejectionReason is invalid");
    if (body.keyRotated !== undefined && body.keyRotated !== null && typeof body.keyRotated !== "boolean") problems.push("result body.keyRotated must be boolean or null");
    if (body.errorMessage !== undefined) checkNullableString(body.errorMessage, "result body.errorMessage", problems, { max: 1024 });
    return;
  }

  if (!checkExactObject(body, new Set(["jobId", "evidenceItems"]), ["evidenceItems"], label, problems)) return;
  if (body.jobId !== undefined) checkNullableString(body.jobId, "evidence body.jobId", problems, { max: 128, pattern: AGENT_ID_PATTERN });
  if (!Array.isArray(body.evidenceItems) || body.evidenceItems.length < 1 || body.evidenceItems.length > 16) {
    problems.push("evidence body.evidenceItems must contain 1 to 16 entries");
    return;
  }
  body.evidenceItems.forEach((item, index) => {
    const itemLabel = `evidence body.evidenceItems[${index}]`;
    if (!checkExactObject(item, new Set(["eventType", "observedAt", "fingerprintSha256", "summary", "metadata"]), ["eventType", "observedAt"], itemLabel, problems)) return;
    if (!EVENT_TYPE_VALUES.has(item.eventType)) problems.push(`${itemLabel}.eventType is invalid`);
    if (!isIsoDateTime(item.observedAt)) problems.push(`${itemLabel}.observedAt must be an ISO date-time string`);
    if (item.fingerprintSha256 !== undefined) checkNullableString(item.fingerprintSha256, `${itemLabel}.fingerprintSha256`, problems, { pattern: /^[a-f0-9]{64}$/ });
    if (item.summary !== undefined) checkNullableString(item.summary, `${itemLabel}.summary`, problems, { max: 1024 });
    if (item.metadata !== undefined) validateMetadata(item.metadata, problems, `${itemLabel}.metadata`);
  });
}

function validateStringArray(value, label, problems, maxItems, maxItemLength, pattern) {
  if (!Array.isArray(value)) {
    problems.push(`${label} must be an array`);
    return;
  }
  if (value.length > maxItems) problems.push(`${label} has more than ${maxItems} entries`);
  value.forEach((item, index) => checkString(item, `${label}[${index}]`, problems, { min: 1, max: maxItemLength, pattern }));
}

function prepareOutboundEnvelope(envelope) {
  assertNoPrivateKeyMaterial(envelope);
  const sanitized = redactGenericSecrets(envelope);
  const problems = validateEnvelopeShape(sanitized);
  if (problems.length > 0) {
    throw new AgentProtocolError(
      `refusing to send malformed envelope: ${problems.join("; ")}`,
      AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
    );
  }
  const serialized = JSON.stringify(sanitized);
  if (Buffer.byteLength(serialized, "utf8") > MAX_OUTBOUND_ENVELOPE_BYTES) {
    throw new AgentProtocolError(
      `refusing to send oversized envelope (max ${MAX_OUTBOUND_ENVELOPE_BYTES} bytes)`,
      AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
    );
  }
  return { envelope: sanitized, serialized };
}

function buildEnvelope({ agentId, protocolVersion, messageType, body = null, workspaceId = null, clockOffsetMs = null }) {
  const envelope = {
    schemaVersion: SCHEMA_VERSION,
    protocolVersion,
    messageType,
    agentId,
    workspaceId,
    sentAt: new Date().toISOString(),
    clockOffsetMs,
    body,
  };
  return prepareOutboundEnvelope(envelope).envelope;
}

function jitteredDelay(baseMs, jitterRatio = 0.2) {
  const safeBase = Number.isFinite(baseMs) && baseMs > 0 ? baseMs : 0;
  const ratio = Number.isFinite(jitterRatio) && jitterRatio >= 0 ? jitterRatio : 0;
  return Math.max(0, Math.round(safeBase + (Math.random() * 2 - 1) * safeBase * ratio));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function withRetry(fn, options = {}) {
  const maxAttempts = options.maxAttempts ?? 5;
  const baseDelayMs = options.baseDelayMs ?? 250;
  const maxDelayMs = options.maxDelayMs ?? 30_000;
  const shouldRetry = options.shouldRetry ?? (() => true);
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (attempt >= maxAttempts || !shouldRetry(err, attempt)) throw err;
      await sleep(Math.min(maxDelayMs, jitteredDelay(Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1)), 1)));
    }
  }
  throw lastError;
}

async function startPollLoop({ intervalMs, jitterRatio = 0.2, signal, onTick, onError = (err) => defaultAgentLogger.error("poll loop tick failed", err), startImmediately = true }) {
  if (!signal) {
    throw new AgentProtocolError("startPollLoop requires an AbortSignal", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  const waitJittered = () => abortableSleep(jitteredDelay(intervalMs, jitterRatio), signal);
  // Correct semantics: true means tick now; false means wait one interval.
  if (!startImmediately) await waitJittered();
  while (!signal.aborted) {
    try {
      await onTick();
    } catch (err) {
      onError(err);
    }
    if (!signal.aborted) await waitJittered();
  }
}

function abortableSleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function isLocalHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127(?:\.\d{1,3}){3}$/.test(host);
}

function parseServerUrl(serverUrl, { allowInsecureLocalHttp = false } = {}) {
  if (typeof serverUrl !== "string" || serverUrl.length === 0 || serverUrl.trim() !== serverUrl) {
    throw new AgentProtocolError("serverUrl must be a non-empty, unpadded URL", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  let parsed;
  try {
    parsed = new URL(serverUrl);
  } catch {
    throw new AgentProtocolError("serverUrl must be an absolute URL", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  if (parsed.username || parsed.password || parsed.hash || parsed.search || (parsed.pathname !== "/" && parsed.pathname !== "")) {
    throw new AgentProtocolError("serverUrl must not contain credentials, a query, fragment, or path", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  if (parsed.protocol === "https:") return parsed.origin;
  if (parsed.protocol === "http:" && allowInsecureLocalHttp === true && isLocalHost(parsed.hostname)) {
    return parsed.origin;
  }
  throw new AgentProtocolError("serverUrl must use HTTPS (HTTP is allowed only for explicit local development)", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
}

function combinedAbortSignal(signal, timeoutMs) {
  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
}

function createCaAwareFetch({ caBundlePem, baseFetch = fetch, maxResponseBytes = MAX_RESPONSE_BYTES } = {}) {
  if (typeof caBundlePem !== "string" || caBundlePem.length === 0) {
    throw new AgentProtocolError("createCaAwareFetch requires a non-empty CA bundle", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  return (url, init = {}) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return baseFetch(url, init);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        init.signal?.removeEventListener("abort", onAbort);
        fn(value);
      };
      const onAbort = () => request.destroy(new Error("request aborted"));
      const request = https.request({
        protocol: "https:",
        hostname: parsed.hostname,
        port: parsed.port || 443,
        path: parsed.pathname,
        method: init.method || "GET",
        headers: init.headers || {},
        ca: caBundlePem,
        rejectUnauthorized: true,
      }, (response) => {
        const chunks = [];
        let total = 0;
        response.on("data", (chunk) => {
          total += chunk.length;
          if (total > maxResponseBytes) {
            response.destroy(new Error("response body exceeds limit"));
            return;
          }
          chunks.push(chunk);
        });
        response.on("error", (err) => finish(reject, err));
        response.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          finish(resolve, {
            ok: response.statusCode >= 200 && response.statusCode < 300,
            status: response.statusCode || 0,
            headers: { get: (name) => response.headers[String(name).toLowerCase()] || null },
            __readBoundedJson: () => parseJsonText(text),
          });
        });
      });
      request.on("error", (err) => finish(reject, err));
      if (init.signal?.aborted) return onAbort();
      init.signal?.addEventListener("abort", onAbort, { once: true });
      if (init.body !== undefined && init.body !== null) request.write(init.body);
      request.end();
    });
  };
}

function parseJsonText(text) {
  if (text.length === 0) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function readBoundedResponseJson(response) {
  const declaredLength = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw new AgentProtocolError("control-plane response exceeds the size limit", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  if (typeof response.__readBoundedJson === "function") return response.__readBoundedJson();
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw new AgentProtocolError("control-plane response exceeds the size limit", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
        }
        chunks.push(Buffer.from(value));
      }
    } finally {
      reader.releaseLock?.();
    }
    return parseJsonText(Buffer.concat(chunks).toString("utf8"));
  }
  // Test doubles without a body stream are intentionally supported; real
  // Node fetch responses always take the bounded reader path above.
  try {
    return await response.json();
  } catch {
    return null;
  }
}

async function postJson(url, { token, envelope, signal, requestTimeoutMs = REQUEST_TIMEOUT_MS, fetchImpl = fetch }) {
  const { envelope: safeEnvelope, serialized } = prepareOutboundEnvelope(envelope);
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers,
      body: serialized,
      signal: combinedAbortSignal(signal, requestTimeoutMs),
      redirect: "error",
    });
  } catch (err) {
    throw new AgentProtocolError("network request to control plane failed", AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR, { cause: err });
  }
  if (response.status >= 300 && response.status < 400) {
    throw new AgentProtocolError("control-plane redirect was refused", AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status: response.status });
  }
  const json = await readBoundedResponseJson(response);
  return { status: response.status, ok: response.ok, json, envelope: safeEnvelope };
}

function validateRegistrationResponse(json, expectedProtocolVersion) {
  if (!isPlainObject(json)) {
    throw new AgentProtocolError("registration response must be an object", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  const expectedKeys = new Set(["agentId", "credential", "protocolVersion"]);
  const keys = Object.keys(json);
  if (keys.length !== expectedKeys.size || keys.some((key) => !expectedKeys.has(key))) {
    throw new AgentProtocolError("registration response contains unknown or missing fields", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  if (typeof json.agentId !== "string" || !AGENT_ID_PATTERN.test(json.agentId)) {
    throw new AgentProtocolError("registration response contains an invalid agentId", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  const credentialMatch = typeof json.credential === "string" ? CREDENTIAL_PATTERN.exec(json.credential) : null;
  if (!credentialMatch || credentialMatch[1] !== json.agentId) {
    throw new AgentProtocolError("registration response contains an invalid credential", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  if (typeof json.protocolVersion !== "string" || !PROTOCOL_VERSION_PATTERN.test(json.protocolVersion) || json.protocolVersion !== expectedProtocolVersion) {
    throw new AgentProtocolError("registration response contains an unsupported protocolVersion", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  return { agentId: json.agentId, credential: json.credential, protocolVersion: json.protocolVersion };
}

async function resolveCredential(getCredential) {
  return typeof getCredential === "function" ? await getCredential() : null;
}

function createProtocolClient({ serverUrl, agentId, protocolVersion, getCredential, signal, requestTimeoutMs = REQUEST_TIMEOUT_MS, fetchImpl = fetch, allowInsecureLocalHttp = false } = {}) {
  const baseUrl = parseServerUrl(serverUrl, { allowInsecureLocalHttp });
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 120_000) {
    throw new AgentProtocolError("requestTimeoutMs must be an integer between 1 and 120000", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  const routeUrl = (route) => `${baseUrl}${route}`;
  const send = (route, token, envelope) => postJson(routeUrl(route), { token, envelope, signal, requestTimeoutMs, fetchImpl });

  async function register({ bootstrapToken, bootstrapTokenId, agentVersion, hostname = null, platform = null, nodeVersion = null, declaredTargetSelectors = [], declaredCommandProfileNames = [] } = {}) {
    if (typeof bootstrapToken !== "string" || bootstrapToken.length === 0) {
      throw new AgentProtocolError("register requires a bootstrapToken", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
    }
    const { status, ok, json } = await send(ROUTES.REGISTER, bootstrapToken, buildEnvelope({
      agentId,
      protocolVersion,
      messageType: MESSAGE_TYPES.REGISTER,
      body: { bootstrapTokenId, agentVersion, hostname, platform, nodeVersion, declaredTargetSelectors, declaredCommandProfileNames },
    }));
    if (!ok) throw new AgentProtocolError(`agent registration failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return validateRegistrationResponse(json, protocolVersion);
  }

  async function heartbeat({ agentVersion, ntpSynced = null, uptimeSeconds = null, pinnedSigningKeyId = null, clockOffsetMs = null } = {}) {
    const { status, ok, json } = await send(ROUTES.HEARTBEAT, await resolveCredential(getCredential), buildEnvelope({ agentId, protocolVersion, messageType: MESSAGE_TYPES.HEARTBEAT, clockOffsetMs, body: { agentVersion, ntpSynced, uptimeSeconds, pinnedSigningKeyId } }));
    if (status === 410) return { retired: true };
    if (!ok) throw new AgentProtocolError(`heartbeat failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return json ?? {};
  }

  async function claim({ maxJobs = 1, supportedActions = [] } = {}) {
    const { status, ok, json } = await send(ROUTES.CLAIM, await resolveCredential(getCredential), buildEnvelope({ agentId, protocolVersion, messageType: MESSAGE_TYPES.CLAIM, body: { maxJobs, supportedActions } }));
    if (!ok) throw new AgentProtocolError(`claim failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    if (json !== null && !isPlainObject(json)) throw new AgentProtocolError("claim response must be an object", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    if (json?.jobs !== undefined && !Array.isArray(json.jobs)) throw new AgentProtocolError("claim response jobs must be an array", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    if (Array.isArray(json?.jobs) && json.jobs.length > 16) throw new AgentProtocolError("claim response contains too many jobs", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    return json?.jobs ?? [];
  }

  async function reportResult({ jobId, attemptId, status: jobStatus, rejectionReason = null, keyRotated = null, errorMessage = null, clockOffsetMs = null } = {}) {
    const { status, ok, json } = await send(ROUTES.RESULTS, await resolveCredential(getCredential), buildEnvelope({ agentId, protocolVersion, messageType: MESSAGE_TYPES.RESULT, clockOffsetMs, body: { jobId, attemptId, status: jobStatus, rejectionReason, keyRotated, errorMessage } }));
    if (!ok) throw new AgentProtocolError(`reportResult failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return json ?? {};
  }

  async function reportEvidence({ jobId = null, evidenceItems } = {}) {
    const { status, ok, json } = await send(ROUTES.RESULTS, await resolveCredential(getCredential), buildEnvelope({ agentId, protocolVersion, messageType: MESSAGE_TYPES.EVIDENCE, body: { jobId, evidenceItems } }));
    if (!ok) throw new AgentProtocolError(`reportEvidence failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return json ?? {};
  }

  return { register, heartbeat, claim, reportResult, reportEvidence };
}

module.exports = {
  ROUTES,
  MESSAGE_TYPES,
  AGENT_PROTOCOL_ERROR_CODES,
  AgentProtocolError,
  REQUEST_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  MAX_OUTBOUND_ENVELOPE_BYTES,
  validateEnvelopeShape,
  prepareOutboundEnvelope,
  validateRegistrationResponse,
  parseServerUrl,
  createCaAwareFetch,
  jitteredDelay,
  withRetry,
  startPollLoop,
  createProtocolClient,
};
