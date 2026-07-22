"use strict";

/**
 * CertOps agent protocol client (agent bootstrap scope).
 *
 * Implements the outbound-only HTTP client for register/heartbeat/claim/
 * result/evidence per packages/contracts/certops/agent-protocol.schema.json
 * and docs/adr/0002-certops-agent-protocol.md (outbound-only model) and
 * docs/adr/0003-certops-job-signing-and-replay-protection.md (replay
 * protection; signature verification itself is signed-dispatch runtime work and is
 * intentionally out of scope here).
 *
 * This module is self-contained: it does not import sibling src/ modules
 * (config, policy, etc). Callers pass in everything it needs (server URL,
 * agent id, credential accessor, ...) as plain parameters/options.
 *
 * Uses Node's built-in global fetch (Node >=22, see package.json engines).
 */

const SCHEMA_VERSION = 1;

/**
 * Route paths under the frozen agent namespace
 * (packages/contracts/api/certops-route-compat.contract.json,
 * packages/contracts/openapi/openapi.yaml). Exported so callers/tests can
 * assert against them without hardcoding strings.
 */
const ROUTES = Object.freeze({
  REGISTER: "/api/v1/certops/agent/register",
  HEARTBEAT: "/api/v1/certops/agent/heartbeat",
  CLAIM: "/api/v1/certops/agent/jobs/claim",
  RESULTS: "/api/v1/certops/agent/jobs/results",
});

/** messageType values a caller of this module may send outbound. */
const MESSAGE_TYPES = Object.freeze({
  REGISTER: "register",
  HEARTBEAT: "heartbeat",
  CLAIM: "claim",
  RESULT: "result",
  EVIDENCE: "evidence",
});

/**
 * Typed error for protocol-level failures, distinct from programmer errors.
 * `code` is one of:
 *   - "network_error": fetch itself threw (DNS, TCP, TLS, abort, ...)
 *   - "http_error": server responded with a non-2xx status the caller must
 *     treat as a failure (i.e. not the special retired/410 case)
 *   - "retired": reserved for documentation; callers get { retired: true }
 *     instead of this error for the 410 case, but the code constant is
 *     exported for consistency/future use.
 *   - "invalid_message": the outgoing envelope failed the local shape check
 *   - "invalid_response": the server response body was not usable JSON or
 *     was missing required fields
 */
class AgentProtocolError extends Error {
  constructor(message, code, options = {}) {
    super(message);
    this.name = "AgentProtocolError";
    this.code = code;
    if (options.status !== undefined) this.status = options.status;
    if (options.cause !== undefined) this.cause = options.cause;
    if (options.body !== undefined) this.body = options.body;
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
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const MESSAGE_TYPE_VALUES = new Set(Object.values(MESSAGE_TYPES));

/**
 * Minimal shape-checking helper for outgoing envelopes: defense in depth,
 * NOT a full JSON Schema validator (the schema is the source of truth and
 * is enforced server-side / in contract tests elsewhere in the monorepo).
 * Checks only the envelope-level required fields and formats described in
 * agent-protocol.schema.json's top-level `required`/`properties`.
 *
 * @param {object} message candidate envelope
 * @returns {string[]} list of human-readable problems; empty means "looks ok"
 */
function validateEnvelopeShape(message) {
  const problems = [];
  if (!message || typeof message !== "object") {
    return ["message must be an object"];
  }
  if (message.schemaVersion !== SCHEMA_VERSION) {
    problems.push(`schemaVersion must be ${SCHEMA_VERSION}`);
  }
  if (
    typeof message.protocolVersion !== "string" ||
    !PROTOCOL_VERSION_PATTERN.test(message.protocolVersion)
  ) {
    problems.push("protocolVersion must be a semver string (x.y.z)");
  }
  if (!MESSAGE_TYPE_VALUES.has(message.messageType)) {
    problems.push(
      `messageType must be one of: ${[...MESSAGE_TYPE_VALUES].join(", ")}`,
    );
  }
  if (
    typeof message.agentId !== "string" ||
    message.agentId.length < 1 ||
    message.agentId.length > 128 ||
    !AGENT_ID_PATTERN.test(message.agentId)
  ) {
    problems.push("agentId must be a non-empty id matching ^[A-Za-z0-9_.:-]+$");
  }
  if (typeof message.sentAt !== "string" || Number.isNaN(Date.parse(message.sentAt))) {
    problems.push("sentAt must be an ISO date-time string");
  }
  return problems;
}

/**
 * Builds the shared envelope fields and validates the result before it is
 * ever handed to fetch.
 *
 * @param {object} params
 * @param {string} params.agentId
 * @param {string} params.protocolVersion
 * @param {string} params.messageType
 * @param {object|null} [params.body]
 * @param {string|null} [params.workspaceId]
 * @param {number|null} [params.clockOffsetMs]
 * @returns {object} the envelope
 */
function buildEnvelope({
  agentId,
  protocolVersion,
  messageType,
  body = null,
  workspaceId = null,
  clockOffsetMs = null,
}) {
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
  const problems = validateEnvelopeShape(envelope);
  if (problems.length > 0) {
    throw new AgentProtocolError(
      `refusing to send malformed ${messageType} envelope: ${problems.join("; ")}`,
      AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
    );
  }
  return envelope;
}

/**
 * Returns baseMs adjusted by +/- a random jitter fraction, floored at 0.
 * Used to avoid fleet thundering herd on heartbeat/poll cadences and on
 * retry backoff.
 *
 * @param {number} baseMs
 * @param {number} [jitterRatio=0.2] fraction of baseMs to jitter by, e.g.
 *   0.2 means the result is in [baseMs * 0.8, baseMs * 1.2]
 * @returns {number}
 */
function jitteredDelay(baseMs, jitterRatio = 0.2) {
  const safeBase = Number.isFinite(baseMs) && baseMs > 0 ? baseMs : 0;
  const ratio = Number.isFinite(jitterRatio) && jitterRatio >= 0 ? jitterRatio : 0;
  const jitterSpan = safeBase * ratio;
  const jitter = (Math.random() * 2 - 1) * jitterSpan;
  return Math.max(0, Math.round(safeBase + jitter));
}

/**
 * Runs `fn` with exponential backoff and full jitter on failure.
 *
 * @param {() => Promise<any>} fn
 * @param {object} [options]
 * @param {number} [options.maxAttempts=5]
 * @param {number} [options.baseDelayMs=250]
 * @param {number} [options.maxDelayMs=30000]
 * @param {(err: Error, attempt: number) => boolean} [options.shouldRetry]
 *   predicate deciding whether a given failure is retryable; defaults to
 *   always retry. Callers can use this to avoid retrying e.g. 4xx errors.
 * @returns {Promise<any>} resolves with fn()'s result
 * @throws the last error, once maxAttempts is exhausted
 */
async function withRetry(fn, options = {}) {
  const maxAttempts = options.maxAttempts ?? 5;
  const baseDelayMs = options.baseDelayMs ?? 250;
  const maxDelayMs = options.maxDelayMs ?? 30000;
  const shouldRetry = options.shouldRetry ?? (() => true);

  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const isLastAttempt = attempt >= maxAttempts;
      if (isLastAttempt || !shouldRetry(err, attempt)) {
        throw err;
      }
      const exponential = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
      const delayMs = jitteredDelay(exponential, 1);
      await sleep(Math.min(delayMs, maxDelayMs));
    }
  }
  throw lastError;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Minimal outbound polling loop scaffold. Repeatedly awaits onTick() on a
 * jittered interval until `signal` aborts. Errors thrown by onTick are
 * caught and logged, never propagated, so a single failed tick (e.g. one
 * dropped heartbeat) does not kill the loop -- matching the outbound-only,
 * resilient-poller intent.
 *
 * Generic on purpose: heartbeat and claim polling both need this shape, so
 * this helper does not know or care which endpoint onTick calls.
 *
 * @param {object} params
 * @param {number} params.intervalMs base interval between ticks
 * @param {number} [params.jitterRatio=0.2]
 * @param {AbortSignal} params.signal used for clean shutdown
 * @param {() => Promise<void>} params.onTick called on every tick
 * @param {(err: Error) => void} [params.onError] override the default
 *   console.error-based error logging
 * @param {boolean} [params.startImmediately=true] whether the first tick
 *   fires immediately (after startup jitter) rather than waiting a full
 *   interval first
 * @returns {Promise<void>} resolves once `signal` aborts
 */
async function startPollLoop({
  intervalMs,
  jitterRatio = 0.2,
  signal,
  onTick,
  onError = defaultPollLoopErrorHandler,
  startImmediately = true,
}) {
  if (!signal) {
    throw new AgentProtocolError(
      "startPollLoop requires an AbortSignal",
      AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
    );
  }

  const waitJittered = async (ms) => {
    const delay = jitteredDelay(ms, jitterRatio);
    await abortableSleep(delay, signal);
  };

  if (startImmediately) {
    await waitJittered(intervalMs);
  }

  while (!signal.aborted) {
    try {
      await onTick();
    } catch (err) {
      onError(err);
    }
    if (signal.aborted) break;
    await waitJittered(intervalMs);
  }
}

function defaultPollLoopErrorHandler(err) {
  console.error(`tokentimer-agent: poll loop tick failed: ${err?.message || err}`);
}

/**
 * sleep() that resolves early (without throwing) if `signal` aborts first.
 */
function abortableSleep(ms, signal) {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * Performs a single JSON POST with a Bearer Authorization header and
 * translates fetch-level failures / non-2xx responses into
 * AgentProtocolError, except for the special 410 "retired" case which the
 * caller (heartbeat) turns into a distinct return value instead of a throw.
 *
 * @param {string} url
 * @param {object} params
 * @param {string|null} params.token raw bearer token; null/omitted sends
 *   no Authorization header
 * @param {object} params.envelope JSON body to send
 * @returns {Promise<{ status: number, ok: boolean, json: any }>}
 */
async function postJson(url, { token, envelope }) {
  const headers = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;

  let response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(envelope),
    });
  } catch (err) {
    throw new AgentProtocolError(
      `network error calling ${url}: ${err?.message || err}`,
      AGENT_PROTOCOL_ERROR_CODES.NETWORK_ERROR,
      { cause: err },
    );
  }

  let json = null;
  try {
    json = await response.json();
  } catch {
    json = null;
  }

  return { status: response.status, ok: response.ok, json };
}

/**
 * Resolves the current raw credential via the caller-supplied
 * `getCredential` accessor, which may be sync or async. This module never
 * reads/writes credential storage itself (per spec: config module owns
 * that); it only ever uses the returned string as a Bearer token.
 *
 * @param {(() => (string|null|Promise<string|null>))|undefined} getCredential
 * @returns {Promise<string|null>}
 */
async function resolveCredential(getCredential) {
  if (typeof getCredential !== "function") return null;
  return await getCredential();
}

/**
 * Factory for the outbound-only protocol client. See module doc comment
 * for the overall design; this is agent bootstrap scope: real job execution
 * and Ed25519 signature verification are signed-dispatch runtime work (see
 * docs/adr/0003-certops-job-signing-and-replay-protection.md) and are only
 * stubbed/passed through here.
 *
 * @param {object} params
 * @param {string} params.serverUrl base URL of the control plane, no
 *   trailing slash required (a trailing slash is tolerated/stripped)
 * @param {string} params.agentId stable agent identifier; for a
 *   not-yet-registered agent this is the client-generated candidate id
 *   echoed back by the control plane on register (schema note)
 * @param {string} params.protocolVersion semver string this agent build
 *   speaks (version negotiation)
 * @param {() => (string|null|Promise<string|null>)} [params.getCredential]
 *   returns the current per-agent credential (raw `ttagent_<id>_<secret>`
 *   string) or null if not yet registered. Required for heartbeat/claim/
 *   result/evidence; unused by register itself (which uses bootstrapToken).
 * @param {(rawCredential: string) => (void|Promise<void>)} [params.onCredentialIssued]
 *   called with the raw credential string returned by a successful
 *   register() call, so the caller can persist it. This module never
 *   persists credentials itself.
 * @returns {object} client with register/heartbeat/claim/reportResult/reportEvidence
 */
function createProtocolClient({
  serverUrl,
  agentId,
  protocolVersion,
  getCredential,
  onCredentialIssued,
}) {
  if (!serverUrl || typeof serverUrl !== "string") {
    throw new AgentProtocolError(
      "createProtocolClient requires a serverUrl string",
      AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
    );
  }
  const baseUrl = serverUrl.replace(/\/+$/, "");
  const routeUrl = (path) => `${baseUrl}${path}`;

  /**
   * @param {object} params
   * @param {string} params.bootstrapToken raw bootstrap token, sent as
   *   Authorization: Bearer <bootstrapToken> (never in the body)
   * @param {string} params.bootstrapTokenId opaque non-secret reference to
   *   the bootstrap token, used for correlation/audit only (distinct from
   *   the token itself; the caller is responsible for having obtained this
   *   id separately when the bootstrap token was issued -- see
   *   registerBody in agent-protocol.schema.json)
   * @param {string} params.agentVersion
   * @param {string|null} [params.hostname]
   * @param {("linux"|"darwin"|"win32"|null)} [params.platform]
   * @param {string|null} [params.nodeVersion]
   * @param {string[]} [params.declaredTargetSelectors]
   * @param {string[]} [params.declaredCommandProfileNames]
   * @returns {Promise<{ agentId: string, credential: string, protocolVersion: string }>}
   */
  async function register({
    bootstrapToken,
    bootstrapTokenId,
    agentVersion,
    hostname = null,
    platform = null,
    nodeVersion = null,
    declaredTargetSelectors = [],
    declaredCommandProfileNames = [],
  }) {
    if (!bootstrapToken) {
      throw new AgentProtocolError(
        "register requires a bootstrapToken",
        AGENT_PROTOCOL_ERROR_CODES.INVALID_MESSAGE,
      );
    }

    const envelope = buildEnvelope({
      agentId,
      protocolVersion,
      messageType: MESSAGE_TYPES.REGISTER,
      body: {
        bootstrapTokenId,
        agentVersion,
        hostname,
        platform,
        nodeVersion,
        declaredTargetSelectors,
        declaredCommandProfileNames,
      },
    });

    const { status, ok, json } = await postJson(routeUrl(ROUTES.REGISTER), {
      token: bootstrapToken,
      envelope,
    });

    if (!ok) {
      throw new AgentProtocolError(
        `agent registration failed with HTTP ${status}`,
        AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR,
        { status, body: json },
      );
    }

    const assignedAgentId = json?.agentId;
    const credential = json?.credential;
    const assignedProtocolVersion = json?.protocolVersion || protocolVersion;

    if (!assignedAgentId || !credential) {
      throw new AgentProtocolError(
        "agent registration response missing agentId/credential",
        AGENT_PROTOCOL_ERROR_CODES.INVALID_RESPONSE,
        { body: json },
      );
    }

    if (typeof onCredentialIssued === "function") {
      await onCredentialIssued(credential);
    }

    return {
      agentId: assignedAgentId,
      credential,
      protocolVersion: assignedProtocolVersion,
    };
  }

  /**
   * @param {object} params
   * @param {string} params.agentVersion
   * @param {boolean|null} [params.ntpSynced]
   * @param {number|null} [params.uptimeSeconds]
   * @param {string|null} [params.pinnedSigningKeyId] job-signing public
   *   key id currently pinned locally; signature verification
   *   itself is signed-dispatch runtime work, this module only reports the id.
   * @param {number|null} [params.clockOffsetMs] agent-reported offset vs
   *   control-plane time. The schema expects this on heartbeat and result
   *   envelopes for clock-drift detection; measuring the offset is signed-dispatch
   *   runtime work, so callers pass it through here when they have it.
   * @returns {Promise<{ retired: true } | object>} `{ retired: true }` on
   *   HTTP 410 (caller should exit cleanly, no respawn loop, per ADR-0002
   *   ); otherwise the parsed response body.
   */
  async function heartbeat({
    agentVersion,
    ntpSynced = null,
    uptimeSeconds = null,
    pinnedSigningKeyId = null,
    clockOffsetMs = null,
  }) {
    const token = await resolveCredential(getCredential);
    const envelope = buildEnvelope({
      agentId,
      protocolVersion,
      messageType: MESSAGE_TYPES.HEARTBEAT,
      clockOffsetMs,
      body: { agentVersion, ntpSynced, uptimeSeconds, pinnedSigningKeyId },
    });

    const { status, ok, json } = await postJson(routeUrl(ROUTES.HEARTBEAT), {
      token,
      envelope,
    });

    if (status === 410) {
      return { retired: true };
    }

    if (!ok) {
      throw new AgentProtocolError(
        `heartbeat failed with HTTP ${status}`,
        AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR,
        { status, body: json },
      );
    }

    return json ?? {};
  }

  /**
   * @param {object} params
   * @param {number} [params.maxJobs=1]
   * @param {string[]} [params.supportedActions]
   * @returns {Promise<Array<object>>} jobs array from the response's
   *   `jobs` field (pass-through; server-side shape TBD, see job-payload
   *   schema which lands with the control-plane agent backend)
   */
  async function claim({ maxJobs = 1, supportedActions = [] } = {}) {
    const token = await resolveCredential(getCredential);
    const envelope = buildEnvelope({
      agentId,
      protocolVersion,
      messageType: MESSAGE_TYPES.CLAIM,
      body: { maxJobs, supportedActions },
    });

    const { status, ok, json } = await postJson(routeUrl(ROUTES.CLAIM), {
      token,
      envelope,
    });

    if (!ok) {
      throw new AgentProtocolError(
        `claim failed with HTTP ${status}`,
        AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR,
        { status, body: json },
      );
    }

    return Array.isArray(json?.jobs) ? json.jobs : [];
  }

  /**
   * Reports the terminal outcome of a job attempt. Job execution itself
   * (running the signed job, verifying its Ed25519 signature) is signed-dispatch
   * runtime work; this is only the outbound reporting leg.
   *
   * @param {object} params
   * @param {string} params.jobId
   * @param {string} params.attemptId
   * @param {("succeeded"|"failed"|"rejected"|"blocked")} params.status
   * @param {string|null} [params.rejectionReason]
   * @param {boolean|null} [params.keyRotated]
   * @param {string|null} [params.errorMessage]
   * @param {number|null} [params.clockOffsetMs] see heartbeat(); the schema
   *   expects this on result envelopes too.
   * @returns {Promise<object>} parsed response body
   */
  async function reportResult({
    jobId,
    attemptId,
    status: jobStatus,
    rejectionReason = null,
    keyRotated = null,
    errorMessage = null,
    clockOffsetMs = null,
  }) {
    const token = await resolveCredential(getCredential);
    const envelope = buildEnvelope({
      agentId,
      protocolVersion,
      messageType: MESSAGE_TYPES.RESULT,
      clockOffsetMs,
      body: {
        jobId,
        attemptId,
        status: jobStatus,
        rejectionReason,
        keyRotated,
        errorMessage,
      },
    });

    const { status: httpStatus, ok, json } = await postJson(routeUrl(ROUTES.RESULTS), {
      token,
      envelope,
    });

    if (!ok) {
      throw new AgentProtocolError(
        `reportResult failed with HTTP ${httpStatus}`,
        AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR,
        { status: httpStatus, body: json },
      );
    }

    return json ?? {};
  }

  /**
   * @param {object} params
   * @param {string|null} [params.jobId] null for agent-level evidence not
   *   tied to a specific job
   * @param {Array<object>} params.evidenceItems see evidenceBody in
   *   agent-protocol.schema.json for the per-item shape
   * @returns {Promise<object>} parsed response body
   */
  async function reportEvidence({ jobId = null, evidenceItems }) {
    const token = await resolveCredential(getCredential);
    const envelope = buildEnvelope({
      agentId,
      protocolVersion,
      messageType: MESSAGE_TYPES.EVIDENCE,
      body: { jobId, evidenceItems },
    });

    // NOTE: evidence and result share the same /jobs/results ingestion
    // route per the frozen route namespace (packages/contracts/api/
    // certops-route-compat.contract.json only lists one results route for
    // agents); the messageType field on the envelope disambiguates
    // server-side. Revisit if control-plane work splits this.
    const { status: httpStatus, ok, json } = await postJson(routeUrl(ROUTES.RESULTS), {
      token,
      envelope,
    });

    if (!ok) {
      throw new AgentProtocolError(
        `reportEvidence failed with HTTP ${httpStatus}`,
        AGENT_PROTOCOL_ERROR_CODES.HTTP_ERROR,
        { status: httpStatus, body: json },
      );
    }

    return json ?? {};
  }

  return {
    register,
    heartbeat,
    claim,
    reportResult,
    reportEvidence,
  };
}

module.exports = {
  ROUTES,
  MESSAGE_TYPES,
  AGENT_PROTOCOL_ERROR_CODES,
  AgentProtocolError,
  validateEnvelopeShape,
  jitteredDelay,
  withRetry,
  startPollLoop,
  createProtocolClient,
};
