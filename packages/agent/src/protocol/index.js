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
const crypto = require("node:crypto");
const { URL } = require("node:url");
const {
  assertNoPrivateKeyMaterial,
  redactGenericSecrets,
} = require("../../vendor/log-scrub/secret-material.js");
const { defaultAgentLogger } = require("../logging");
const { validateAgentProtocolMessage } = require("./schemaValidation");

const SCHEMA_VERSION = 1;
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 64 * 1024;
const MAX_OUTBOUND_ENVELOPE_BYTES = 512 * 1024;

const ROUTES = Object.freeze({
  REGISTER: "/api/v1/certops/agent/register",
  HEARTBEAT: "/api/v1/certops/agent/heartbeat",
  CLAIM: "/api/v1/certops/agent/jobs/claim",
  RESULTS: "/api/v1/certops/agent/jobs/results",
  // B6: plain POST (no message envelope). Path is jobs/:jobId/lease.
  LEASE: "/api/v1/certops/agent/jobs",
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
  // B6: lease renew rejected because this agent/claim no longer owns the job.
  CLAIM_OWNERSHIP_MISMATCH: "claim_ownership_mismatch",
});

const PROTOCOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]{1,128}$/;
const CREDENTIAL_PATTERN = /^ttagent_([A-Za-z0-9_.:-]{1,128})_([A-Za-z0-9._~+\/-]{16,1024})$/;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Shape/enum/type validation for outbound envelopes. Delegates to the
 * AJV-compiled agent-protocol schema (single source of truth).
 *
 * @param {*} message
 * @returns {string[]} human-readable problems (empty when valid)
 */
function validateEnvelopeShape(message) {
  const { valid, errors } = validateAgentProtocolMessage(message);
  return valid ? [] : errors;
}

// B18: evidence items require a client-generated idempotency key so retried
// submissions (e.g. after a transport failure) are safely no-op'd by the
// control plane instead of creating duplicate evidence rows. The key is a
// stable hash of the bounded, non-secret fields that identify the same
// logical observation, so the same observation retried later reproduces the
// same id. Callers that already supply evidenceId (e.g. replaying a batch)
// are left untouched.
function computeEvidenceId(jobId, item) {
  const stable = {
    jobId: jobId ?? null,
    eventType: item?.eventType ?? null,
    observedAt: item?.observedAt ?? null,
    fingerprintSha256: item?.fingerprintSha256 ?? null,
    summary: item?.summary ?? null,
  };
  return crypto.createHash("sha256").update(JSON.stringify(stable)).digest("hex");
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

function buildEnvelope({ agentId, protocolVersion, messageType, body = null, workspaceId = null, clockOffsetMs = null, sequence = null }) {
  const envelope = {
    schemaVersion: SCHEMA_VERSION,
    protocolVersion,
    messageType,
    agentId,
    workspaceId,
    sentAt: new Date().toISOString(),
    clockOffsetMs,
    // Optional in the schema (plain integer, not nullable): carried only
    // when the caller provides a valid counter value.
    ...(Number.isInteger(sequence) && sequence >= 1 ? { sequence } : {}),
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

async function postJson(url, { token, envelope, signal, requestTimeoutMs = REQUEST_TIMEOUT_MS, fetchImpl = fetch, onServerDate = null }) {
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
  if (response.ok && typeof onServerDate === "function") {
    const dateHeaderValue = response.headers?.get?.("date");
    if (dateHeaderValue) {
      try {
        onServerDate(dateHeaderValue, Date.now());
      } catch (_err) {
        // A clock-sampling callback failure must never fail the protocol
        // request itself; the sample is simply lost.
      }
    }
  }
  const json = await readBoundedResponseJson(response);
  return { status: response.status, ok: response.ok, json, envelope: safeEnvelope };
}

/**
 * Plain JSON POST for routes that do NOT use the agent-protocol message
 * envelope (B6 lease renew). Same transport hardening as postJson
 * (timeout, redirect refuse, bounded response, auth header) without the
 * envelope schema gate.
 */
async function postPlainJson(url, { token, body, signal, requestTimeoutMs = REQUEST_TIMEOUT_MS, fetchImpl = fetch, onServerDate = null }) {
  if (!isPlainObject(body)) {
    throw new AgentProtocolError("plain POST body must be an object", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  assertNoPrivateKeyMaterial(body);
  const sanitized = redactGenericSecrets(body);
  const serialized = JSON.stringify(sanitized);
  if (Buffer.byteLength(serialized, "utf8") > MAX_OUTBOUND_ENVELOPE_BYTES) {
    throw new AgentProtocolError(
      `refusing to send oversized plain body (max ${MAX_OUTBOUND_ENVELOPE_BYTES} bytes)`,
      AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
    );
  }
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
  if (response.ok && typeof onServerDate === "function") {
    const dateHeaderValue = response.headers?.get?.("date");
    if (dateHeaderValue) {
      try {
        onServerDate(dateHeaderValue, Date.now());
      } catch (_err) {
        // Clock sample must never fail the protocol request.
      }
    }
  }
  const json = await readBoundedResponseJson(response);
  return { status: response.status, ok: response.ok, json, body: sanitized };
}

function validateRegistrationResponse(json, expectedProtocolVersion) {
  if (!isPlainObject(json)) {
    throw new AgentProtocolError("registration response must be an object", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  // signingKeyId/signingPublicKeyPem carry the control plane's job-signing
  // key pin (ADR-0003 trust-on-first-use); optional so a server that does
  // not sign dispatch yet still registers cleanly.
  const requiredKeys = new Set(["agentId", "credential", "protocolVersion"]);
  const optionalKeys = new Set(["signingKeyId", "signingPublicKeyPem"]);
  const keys = Object.keys(json);
  if (keys.some((key) => !requiredKeys.has(key) && !optionalKeys.has(key)) || [...requiredKeys].some((key) => !keys.includes(key))) {
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
  let signingKeyId = null;
  let signingPublicKeyPem = null;
  if (json.signingKeyId !== undefined && json.signingKeyId !== null) {
    if (typeof json.signingKeyId !== "string" || !AGENT_ID_PATTERN.test(json.signingKeyId)) {
      throw new AgentProtocolError("registration response contains an invalid signingKeyId", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    }
    signingKeyId = json.signingKeyId;
  }
  if (json.signingPublicKeyPem !== undefined && json.signingPublicKeyPem !== null) {
    if (
      typeof json.signingPublicKeyPem !== "string" ||
      json.signingPublicKeyPem.length === 0 ||
      json.signingPublicKeyPem.length > 8192 ||
      !json.signingPublicKeyPem.includes("BEGIN PUBLIC KEY") ||
      json.signingPublicKeyPem.includes("PRIVATE KEY")
    ) {
      throw new AgentProtocolError("registration response contains an invalid signingPublicKeyPem", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    }
    signingPublicKeyPem = json.signingPublicKeyPem;
  }
  if ((signingKeyId === null) !== (signingPublicKeyPem === null)) {
    throw new AgentProtocolError("registration response must provide signingKeyId and signingPublicKeyPem together", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
  }
  return { agentId: json.agentId, credential: json.credential, protocolVersion: json.protocolVersion, signingKeyId, signingPublicKeyPem };
}

/**
 * H3: normalize an optional heartbeat.signingKeyRotation notice. Malformed
 * notices become null (never adopted) rather than failing the whole
 * heartbeat — a bad rotation payload must not stop last_seen_at updates.
 *
 * @param {*} rotation
 * @returns {object|null}
 */
function normalizeSigningKeyRotation(rotation) {
  if (rotation === null || rotation === undefined) return null;
  if (!isPlainObject(rotation)) return null;
  const pendingSigningKeyId = rotation.pendingSigningKeyId;
  const pendingPublicKeyPem = rotation.pendingPublicKeyPem;
  if (
    typeof pendingSigningKeyId !== "string" ||
    !AGENT_ID_PATTERN.test(pendingSigningKeyId) ||
    typeof pendingPublicKeyPem !== "string" ||
    pendingPublicKeyPem.length === 0 ||
    pendingPublicKeyPem.length > 8192 ||
    !pendingPublicKeyPem.includes("BEGIN PUBLIC KEY") ||
    pendingPublicKeyPem.includes("PRIVATE KEY")
  ) {
    return null;
  }
  const normalized = {
    pendingSigningKeyId,
    pendingPublicKeyPem,
  };
  if (rotation.supersedesSigningKeyId !== undefined && rotation.supersedesSigningKeyId !== null) {
    if (
      typeof rotation.supersedesSigningKeyId !== "string" ||
      !AGENT_ID_PATTERN.test(rotation.supersedesSigningKeyId)
    ) {
      return null;
    }
    normalized.supersedesSigningKeyId = rotation.supersedesSigningKeyId;
  }
  if (rotation.status !== undefined && rotation.status !== null) {
    if (typeof rotation.status !== "string" || rotation.status.length === 0 || rotation.status.length > 64) {
      return null;
    }
    normalized.status = rotation.status;
  }
  return normalized;
}

/**
 * Light validation for heartbeat responses. Unlike registration, the
 * control plane may add fleet-ops fields over time; unknown keys are
 * preserved. signingKeyRotation is shape-checked (H3) before the runtime
 * may adopt it.
 *
 * @param {*} json
 * @returns {object}
 */
function validateHeartbeatResponse(json) {
  if (json === null || json === undefined) return {};
  if (!isPlainObject(json)) {
    throw new AgentProtocolError(
      "heartbeat response must be an object",
      AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE,
    );
  }
  if (!Object.prototype.hasOwnProperty.call(json, "signingKeyRotation")) {
    return json;
  }
  return {
    ...json,
    signingKeyRotation: normalizeSigningKeyRotation(json.signingKeyRotation),
  };
}

async function resolveCredential(getCredential) {
  return typeof getCredential === "function" ? await getCredential() : null;
}

function createProtocolClient({ serverUrl, agentId, protocolVersion, getCredential, signal, requestTimeoutMs = REQUEST_TIMEOUT_MS, fetchImpl = fetch, allowInsecureLocalHttp = false, onServerDate = null, sequenceAllocator = null } = {}) {
  const baseUrl = parseServerUrl(serverUrl, { allowInsecureLocalHttp });
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1 || requestTimeoutMs > 120_000) {
    throw new AgentProtocolError("requestTimeoutMs must be an integer between 1 and 120000", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  if (sequenceAllocator !== null && typeof sequenceAllocator?.next !== "function") {
    throw new AgentProtocolError("sequenceAllocator must expose a next() function when provided", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
  }
  const routeUrl = (route) => `${baseUrl}${route}`;
  const send = (route, token, envelope) => postJson(routeUrl(route), { token, envelope, signal, requestTimeoutMs, fetchImpl, onServerDate });
  const sendPlain = (route, token, body) => postPlainJson(routeUrl(route), { token, body, signal, requestTimeoutMs, fetchImpl, onServerDate });

  // Per-agent monotonically increasing message counter, included as the
  // envelope's `sequence` field on every outbound message (register,
  // heartbeat, claim, result, evidence) and as the plain-body `sequence`
  // on lease renew (B6). The runtime injects a shared,
  // crash-safe persisted allocator (config.createSequenceAllocator) so
  // registration and steady-state clients draw from ONE stream and a
  // process restart NEVER reuses a value (the control plane hard-rejects
  // regressions). The in-memory fallback exists only for isolated
  // unit-test clients.
  let inMemorySequence = 0;
  function nextSequence() {
    if (sequenceAllocator) return sequenceAllocator.next();
    inMemorySequence += 1;
    return inMemorySequence;
  }

  // Sequence-bearing requests are strictly serialized: the sequence value
  // is allocated inside the queue immediately before its request is sent,
  // and the next request cannot allocate until the current one settled.
  // Without this, concurrent heartbeat/claim/discovery loops could deliver
  // a higher sequence before a lower one and get the lower one rejected as
  // a regression.
  let sendQueue = Promise.resolve();
  function enqueueSequencedSend(performSend) {
    const run = sendQueue.then(() => performSend(nextSequence()));
    // Keep the chain alive whether the send succeeds or fails; failures
    // propagate to the caller through `run` itself.
    sendQueue = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  async function register({
    bootstrapToken,
    bootstrapTokenId,
    agentVersion,
    hostname = null,
    platform = null,
    nodeVersion = null,
    declaredTargetSelectors = [],
    declaredCommandProfileNames = [],
    registrationId = null,
    supportedDnsProviders = undefined,
  } = {}) {
    if (typeof bootstrapToken !== "string" || bootstrapToken.length === 0) {
      throw new AgentProtocolError("register requires a bootstrapToken", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
    }
    const { status, ok, json } = await enqueueSequencedSend((sequence) =>
      send(ROUTES.REGISTER, bootstrapToken, buildEnvelope({
        agentId,
        protocolVersion,
        messageType: MESSAGE_TYPES.REGISTER,
        sequence,
        body: {
          bootstrapTokenId,
          agentVersion,
          hostname,
          platform,
          nodeVersion,
          declaredTargetSelectors,
          declaredCommandProfileNames,
          ...(registrationId !== null && registrationId !== undefined
            ? { registrationId }
            : {}),
          ...(Array.isArray(supportedDnsProviders)
            ? { supportedDnsProviders }
            : {}),
        },
      })),
    );
    if (!ok) throw new AgentProtocolError(`agent registration failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return validateRegistrationResponse(json, protocolVersion);
  }

  async function heartbeat({
    agentVersion,
    ntpSynced = null,
    uptimeSeconds = null,
    pinnedSigningKeyId = null,
    clockOffsetMs = null,
    supportedDnsProviders = undefined,
  } = {}) {
    const token = await resolveCredential(getCredential);
    const { status, ok, json } = await enqueueSequencedSend((sequence) =>
      send(ROUTES.HEARTBEAT, token, buildEnvelope({
        agentId,
        protocolVersion,
        messageType: MESSAGE_TYPES.HEARTBEAT,
        clockOffsetMs,
        sequence,
        body: {
          agentVersion,
          ntpSynced,
          uptimeSeconds,
          pinnedSigningKeyId,
          ...(Array.isArray(supportedDnsProviders)
            ? { supportedDnsProviders }
            : {}),
        },
      })),
    );
    if (status === 410) return { retired: true };
    if (!ok) throw new AgentProtocolError(`heartbeat failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return validateHeartbeatResponse(json ?? {});
  }

  async function claim({ maxJobs = 1, supportedActions = [], supportedDnsProviders = undefined } = {}) {
    const token = await resolveCredential(getCredential);
    const { status, ok, json } = await enqueueSequencedSend((sequence) =>
      send(ROUTES.CLAIM, token, buildEnvelope({
        agentId,
        protocolVersion,
        messageType: MESSAGE_TYPES.CLAIM,
        sequence,
        body: {
          maxJobs,
          supportedActions,
          ...(Array.isArray(supportedDnsProviders)
            ? { supportedDnsProviders }
            : {}),
        },
      })),
    );
    if (!ok) throw new AgentProtocolError(`claim failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    if (json !== null && !isPlainObject(json)) throw new AgentProtocolError("claim response must be an object", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    if (json?.jobs !== undefined && !Array.isArray(json.jobs)) throw new AgentProtocolError("claim response jobs must be an array", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    if (Array.isArray(json?.jobs) && json.jobs.length > 16) throw new AgentProtocolError("claim response contains too many jobs", AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE);
    return json?.jobs ?? [];
  }

  /**
   * B6: renew the job lease (and transition claimed→running on first call).
   * This route does NOT use the message envelope; body is { claimId, sequence }.
   * Sequence is always allocated from the shared counter (once any sequenced
   * message has been sent, omitting it is rejected server-side).
   *
   * 409 (ownership / sequence) and 410 (retired) return a distinguishable
   * `{ ok: false, status, code }` so the runtime can abort the job cleanly
   * without treating them as uncaught transport errors. Other non-2xx still
   * throw AgentProtocolError.
   *
   * @param {{ jobId: string, claimId: string }} params
   * @returns {Promise<object|{ ok: false, status: number, code: string|null }>}
   */
  async function renewLease({ jobId, claimId } = {}) {
    if (typeof jobId !== "string" || jobId.length === 0 || !AGENT_ID_PATTERN.test(jobId)) {
      throw new AgentProtocolError("renewLease requires a valid jobId", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
    }
    if (typeof claimId !== "string" || claimId.length === 0 || !AGENT_ID_PATTERN.test(claimId)) {
      throw new AgentProtocolError("renewLease requires a valid claimId", AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE);
    }
    const token = await resolveCredential(getCredential);
    const leasePath = `${ROUTES.LEASE}/${encodeURIComponent(jobId)}/lease`;
    const { status, ok, json } = await enqueueSequencedSend((sequence) =>
      sendPlain(leasePath, token, { claimId, sequence }),
    );
    if (status === 409 || status === 410) {
      return {
        ok: false,
        status,
        code: isPlainObject(json) && typeof json.code === "string" ? json.code : null,
      };
    }
    if (!ok) {
      throw new AgentProtocolError(
        `lease renew failed with HTTP ${status}`,
        AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR,
        { status },
      );
    }
    return json ?? {};
  }

  /**
   * Reports the terminal outcome of a job attempt.
   *
   * claimId is the server-assigned claim id from the signed dispatch payload;
   * the control plane re-proves claim ownership with it (ADR-0003). nonce is
   * the single-use dispatch nonce consumed server-side by the replay ledger.
   * Both are included in the body only when non-null so a bootstrap-mode
   * report stays schema-minimal (the results route falls back to attemptId
   * when claimId is absent).
   */
  async function reportResult({ jobId, attemptId, status: jobStatus, rejectionReason = null, keyRotated = null, errorMessage = null, claimId = null, nonce = null, clockOffsetMs = null } = {}) {
    const body = {
      jobId,
      attemptId,
      status: jobStatus,
      rejectionReason,
      keyRotated,
      errorMessage,
      ...(claimId !== null ? { claimId } : {}),
      ...(nonce !== null ? { nonce } : {}),
    };
    const token = await resolveCredential(getCredential);
    const { status, ok, json } = await enqueueSequencedSend((sequence) =>
      send(ROUTES.RESULTS, token, buildEnvelope({ agentId, protocolVersion, messageType: MESSAGE_TYPES.RESULT, clockOffsetMs, sequence, body })),
    );
    if (!ok) throw new AgentProtocolError(`reportResult failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return json ?? {};
  }

  async function reportEvidence({ jobId = null, evidenceItems } = {}) {
    const itemsWithIds = Array.isArray(evidenceItems)
      ? evidenceItems.map((item) =>
          item && typeof item.evidenceId === "string" && item.evidenceId.length > 0
            ? item
            : { ...item, evidenceId: computeEvidenceId(jobId, item) },
        )
      : evidenceItems;
    const token = await resolveCredential(getCredential);
    const { status, ok, json } = await enqueueSequencedSend((sequence) =>
      send(ROUTES.RESULTS, token, buildEnvelope({ agentId, protocolVersion, messageType: MESSAGE_TYPES.EVIDENCE, sequence, body: { jobId, evidenceItems: itemsWithIds } })),
    );
    if (!ok) throw new AgentProtocolError(`reportEvidence failed with HTTP ${status}`, AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR, { status });
    return json ?? {};
  }

  return { register, heartbeat, claim, renewLease, reportResult, reportEvidence };
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
  validateHeartbeatResponse,
  parseServerUrl,
  createCaAwareFetch,
  jitteredDelay,
  withRetry,
  startPollLoop,
  createProtocolClient,
};
