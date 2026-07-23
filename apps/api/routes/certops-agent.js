"use strict";

/**
 * CertOps agent machine routes (ADR-0002/0003):
 *   POST /api/v1/certops/agent/register     (bootstrap-token auth)
 *   POST /api/v1/certops/agent/heartbeat    (credential auth)
 *   POST /api/v1/certops/agent/jobs/claim   (credential auth)
 *   POST /api/v1/certops/agent/jobs/results (credential auth)
 *
 * Middleware order mirrors apps/api/routes/certops-executor.js:
 * pre-auth rate limit -> auth -> post-auth rate limit -> private-material
 * rejection (422 wins over auth-shaped errors) -> requireCertOpsEnabled ->
 * handler. All transaction logic lives in services/certops/agentDispatch.js.
 */

const router = require("express").Router;
const {
  createAgentBootstrapTokenAuth,
  createAgentCredentialAuth,
} = require("../middleware/agent-auth");
const {
  createCertOpsMachineTokenPreAuthRateLimit,
  createCertOpsMachineTokenRateLimit,
} = require("../middleware/machine-token-rate-limit");
const {
  hasCertOpsExecutorPreAuthLimit,
} = require("../middleware/certops-executor-body-parser");
const {
  requireCertOpsEnabled,
} = require("../middleware/require-certops-enabled");
const { logger } = require("../utils/logger");
const { writeAudit } = require("../services/audit");
const {
  assertNoPrivateKeyMaterial,
  PRIVATE_KEY_MATERIAL_REJECTED,
} = require("../utils/secretMaterial");
const {
  CERTOPS_WORKSPACE_PAUSED,
} = require("../services/certops/workspaceKillSwitch");
const { CERTOPS_DISABLED } = require("../services/certops/settings");
const {
  CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
  CERTOPS_AGENT_JOB_NOT_FOUND,
  CERTOPS_AGENT_REGISTRATION_CONFLICT,
  CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED,
  CERTOPS_AGENT_RESULT_NONCE_REJECTED,
  CERTOPS_AGENT_RESULT_STATUS_INVALID,
  CERTOPS_AGENT_RETIRED,
  CERTOPS_AGENT_SEQUENCE_REGRESSION,
  assertEvidenceClaimOwnership,
  claimJobs,
  enforceAgentSequence,
  ingestResult,
  recordHeartbeat,
  registerAgent,
} = require("../services/certops/agentDispatch");
const {
  createCertificateEvidence,
  createControllerObservationEvidence,
} = require("../services/certops/evidence");
const { CERTOPS_JOB_NOT_FOUND } = require("../services/certops/jobs");

// --- Frozen route paths (certops-route-compat.contract.json) ---
const CERTOPS_AGENT_REGISTER_PATH = "/api/v1/certops/agent/register";
const CERTOPS_AGENT_HEARTBEAT_PATH = "/api/v1/certops/agent/heartbeat";
const CERTOPS_AGENT_JOBS_CLAIM_PATH = "/api/v1/certops/agent/jobs/claim";
const CERTOPS_AGENT_JOBS_RESULTS_PATH = "/api/v1/certops/agent/jobs/results";

// --- Frozen error codes ---
const CERTOPS_AGENT_MESSAGE_INVALID = "CERTOPS_AGENT_MESSAGE_INVALID";
const CERTOPS_AGENT_RETIRED_RESPONSE = Object.freeze({
  error: "CertOps agent is retired",
  code: CERTOPS_AGENT_RETIRED,
});
const AGENT_UNAUTHORIZED_RESPONSE = Object.freeze({
  error: "CertOps agent bootstrap authentication required",
  code: "CERTOPS_AGENT_BOOTSTRAP_UNAUTHORIZED",
});

const PROTOCOL_VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.:-]+$/;
const PLATFORM_VALUES = new Set(["linux", "darwin", "win32"]);
const RESULT_STATUS_VALUES = new Set([
  "succeeded",
  "failed",
  "rejected",
  "blocked",
]);
const EVIDENCE_EVENT_TYPES = new Set([
  "certificate.observed",
  "deployment.checked",
  "deployment.updated",
  "validation.passed",
  "validation.failed",
  "policy.checked",
]);

function messageError(message) {
  const error = new Error(message);
  error.code = CERTOPS_AGENT_MESSAGE_INVALID;
  return error;
}

// Structural envelope validation following agent-protocol.schema.json
// (envelope required fields + per-messageType body), matching the existing
// hand-rolled route validation style (apps/api does not depend on ajv).
function validateEnvelope(body, expectedMessageType) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw messageError("Message envelope must be a JSON object");
  }
  if (body.schemaVersion !== 1) {
    throw messageError("schemaVersion must be 1");
  }
  if (
    typeof body.protocolVersion !== "string" ||
    body.protocolVersion.length > 32 ||
    !PROTOCOL_VERSION_PATTERN.test(body.protocolVersion)
  ) {
    throw messageError("protocolVersion must be a semver string");
  }
  if (body.messageType !== expectedMessageType) {
    throw messageError(`messageType must be ${expectedMessageType}`);
  }
  if (
    typeof body.agentId !== "string" ||
    body.agentId.length < 1 ||
    body.agentId.length > 128 ||
    !AGENT_ID_PATTERN.test(body.agentId)
  ) {
    throw messageError("agentId is invalid");
  }
  if (
    typeof body.sentAt !== "string" ||
    Number.isNaN(Date.parse(body.sentAt))
  ) {
    throw messageError("sentAt must be an ISO date-time string");
  }
  if (
    body.clockOffsetMs !== undefined &&
    body.clockOffsetMs !== null &&
    !Number.isInteger(body.clockOffsetMs)
  ) {
    throw messageError("clockOffsetMs must be an integer or null");
  }
  // Optional per-agent monotonic message counter (plain integer in the
  // schema, never null); enforcement itself lives in agentDispatch.
  if (
    body.sequence !== undefined &&
    (!Number.isInteger(body.sequence) || body.sequence < 1)
  ) {
    throw messageError("sequence must be an integer >= 1 when present");
  }
  return body;
}

function requireBodyObject(envelope) {
  const body = envelope.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw messageError("Message body must be a JSON object");
  }
  return body;
}

function optionalBoundedString(value, name, maxLength) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > maxLength) {
    throw messageError(`${name} is invalid`);
  }
  return value;
}

function validateRegisterBody(envelope) {
  const body = requireBodyObject(envelope);
  if (
    typeof body.bootstrapTokenId !== "string" ||
    body.bootstrapTokenId.length < 1 ||
    body.bootstrapTokenId.length > 128 ||
    !AGENT_ID_PATTERN.test(body.bootstrapTokenId)
  ) {
    throw messageError("bootstrapTokenId is invalid");
  }
  if (
    typeof body.agentVersion !== "string" ||
    body.agentVersion.length < 1 ||
    body.agentVersion.length > 32
  ) {
    throw messageError("agentVersion is invalid");
  }
  optionalBoundedString(body.hostname, "hostname", 255);
  if (
    body.platform !== undefined &&
    body.platform !== null &&
    !PLATFORM_VALUES.has(body.platform)
  ) {
    throw messageError("platform is invalid");
  }
  optionalBoundedString(body.nodeVersion, "nodeVersion", 32);
  for (const [field, maxLen, pattern] of [
    ["declaredTargetSelectors", 256, null],
    ["declaredCommandProfileNames", 128, AGENT_ID_PATTERN],
  ]) {
    const list = body[field];
    if (list === undefined) continue;
    if (!Array.isArray(list) || list.length > 64) {
      throw messageError(`${field} is invalid`);
    }
    for (const item of list) {
      if (
        typeof item !== "string" ||
        item.length < 1 ||
        item.length > maxLen ||
        (pattern && !pattern.test(item))
      ) {
        throw messageError(`${field} contains an invalid entry`);
      }
    }
  }
  return body;
}

function validateHeartbeatBody(envelope) {
  const body = requireBodyObject(envelope);
  if (
    typeof body.agentVersion !== "string" ||
    body.agentVersion.length < 1 ||
    body.agentVersion.length > 32
  ) {
    throw messageError("agentVersion is invalid");
  }
  if (
    body.ntpSynced !== undefined &&
    body.ntpSynced !== null &&
    typeof body.ntpSynced !== "boolean"
  ) {
    throw messageError("ntpSynced is invalid");
  }
  if (
    body.uptimeSeconds !== undefined &&
    body.uptimeSeconds !== null &&
    (!Number.isInteger(body.uptimeSeconds) || body.uptimeSeconds < 0)
  ) {
    throw messageError("uptimeSeconds is invalid");
  }
  if (
    body.pinnedSigningKeyId !== undefined &&
    body.pinnedSigningKeyId !== null &&
    (typeof body.pinnedSigningKeyId !== "string" ||
      body.pinnedSigningKeyId.length > 128 ||
      !AGENT_ID_PATTERN.test(body.pinnedSigningKeyId))
  ) {
    throw messageError("pinnedSigningKeyId is invalid");
  }
  return body;
}

function validateClaimBody(envelope) {
  const body = envelope.body ?? {};
  if (typeof body !== "object" || Array.isArray(body)) {
    throw messageError("Message body must be a JSON object");
  }
  if (
    body.maxJobs !== undefined &&
    (!Number.isInteger(body.maxJobs) || body.maxJobs < 1 || body.maxJobs > 16)
  ) {
    throw messageError("maxJobs is invalid");
  }
  if (body.supportedActions !== undefined) {
    if (
      !Array.isArray(body.supportedActions) ||
      body.supportedActions.length > 16
    ) {
      throw messageError("supportedActions is invalid");
    }
  }
  return body;
}

function validateResultBody(envelope) {
  const body = requireBodyObject(envelope);
  for (const field of ["jobId", "attemptId"]) {
    if (
      typeof body[field] !== "string" ||
      body[field].length < 1 ||
      body[field].length > 128 ||
      !AGENT_ID_PATTERN.test(body[field])
    ) {
      throw messageError(`${field} is invalid`);
    }
  }
  if (!RESULT_STATUS_VALUES.has(body.status)) {
    throw messageError("status is invalid");
  }
  if (
    body.errorMessage !== undefined &&
    body.errorMessage !== null &&
    (typeof body.errorMessage !== "string" || body.errorMessage.length > 1024)
  ) {
    throw messageError("errorMessage is invalid");
  }
  // claimId/nonce ride alongside the schema resultBody fields: the signed
  // dispatch payload carries both and the server needs them for ownership
  // re-proof and single-use nonce consumption (ADR-0003). attemptId doubles
  // as the claimId when a client sends only the schema-required fields.
  optionalBoundedString(body.claimId, "claimId", 128);
  optionalBoundedString(body.nonce, "nonce", 128);
  return body;
}

function validateEvidenceBody(envelope) {
  const body = requireBodyObject(envelope);
  if (
    body.jobId !== undefined &&
    body.jobId !== null &&
    (typeof body.jobId !== "string" ||
      body.jobId.length > 128 ||
      !AGENT_ID_PATTERN.test(body.jobId))
  ) {
    throw messageError("jobId is invalid");
  }
  const items = body.evidenceItems;
  if (!Array.isArray(items) || items.length < 1 || items.length > 16) {
    throw messageError("evidenceItems is invalid");
  }
  for (const item of items) {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw messageError("evidence item is invalid");
    }
    if (!EVIDENCE_EVENT_TYPES.has(item.eventType)) {
      throw messageError("evidence eventType is invalid");
    }
    if (
      typeof item.observedAt !== "string" ||
      Number.isNaN(Date.parse(item.observedAt))
    ) {
      throw messageError("evidence observedAt is invalid");
    }
  }
  return body;
}

// --- Private-material rejection (422 wins over auth-shaped errors) ---

async function writeAgentRejectionAudit(req) {
  await writeAudit({
    actorUserId: null,
    subjectUserId: null,
    action: "CERTOPS_KEY_MATERIAL_REJECTED",
    targetType: "certops_agent",
    targetId: null,
    workspaceId:
      req.certopsAgent?.workspaceId ||
      req.agentBootstrapToken?.workspaceId ||
      null,
    metadata: {
      code: PRIVATE_KEY_MATERIAL_REJECTED,
      method: req.method || null,
      routeFamily: "agent-protocol",
      agentId: req.certopsAgent?.agentId || null,
    },
  });
}

async function rejectAgentPrivateMaterial(req, res, next) {
  try {
    // Sits after authentication but before rollout or handler logic: the
    // machine boundary must synchronously audit and reject key material
    // even for an otherwise unauthorized caller (mirrors the executor
    // route ordering).
    assertNoPrivateKeyMaterial(req.body);
    return next();
  } catch (error) {
    if (error?.code !== PRIVATE_KEY_MATERIAL_REJECTED) return next(error);
    try {
      await writeAgentRejectionAudit(req);
    } catch (auditError) {
      logger.error("CertOps agent key-material rejection audit failed", {
        code: auditError?.code || null,
        routeFamily: "agent-protocol",
      });
      return res.status(503).json({
        error: "CertOps security audit is unavailable",
        code: "CERTOPS_SECURITY_AUDIT_UNAVAILABLE",
      });
    }
    return res.status(422).json({
      error: "Private key material is not accepted on CertOps agent routes",
      code: PRIVATE_KEY_MATERIAL_REJECTED,
    });
  }
}

// --- Shared route guards ---

function requireNonRetiredAgent(req, res, next) {
  // Frozen-retired rule (7.7 item 11): retired agents authenticate but get
  // 410 with no last_seen_at (or any other) update.
  if (req.certopsAgent?.status === "retired") {
    return res.status(410).json(CERTOPS_AGENT_RETIRED_RESPONSE);
  }
  return next();
}

function agentRateLimitIdentity(req, _res, next) {
  // Feed the shared post-auth machine-token limiter (its key resolver reads
  // req.apiToken {workspaceId, tokenPrefix, agentId}).
  const agent = req.certopsAgent || null;
  const bootstrap = req.agentBootstrapToken || null;
  req.apiToken = agent
    ? {
        workspaceId: agent.workspaceId,
        tokenPrefix: `ttagent_${agent.agentId}`,
        agentId: agent.id,
      }
    : {
        workspaceId: bootstrap?.workspaceId || null,
        tokenPrefix: bootstrap?.tokenPrefix || null,
        agentId: null,
      };
  return next();
}

function handleAgentRouteError(res, error) {
  switch (error?.code) {
    case CERTOPS_AGENT_MESSAGE_INVALID:
      return res.status(400).json({
        error: error.message,
        code: CERTOPS_AGENT_MESSAGE_INVALID,
      });
    case CERTOPS_AGENT_REGISTRATION_UNAUTHORIZED:
      // Lost single-use race: same generic body as a bad bootstrap token so
      // callers cannot probe token state.
      return res.status(401).json(AGENT_UNAUTHORIZED_RESPONSE);
    case CERTOPS_AGENT_REGISTRATION_CONFLICT:
      return res.status(409).json({
        error: "An agent with this agentId already exists",
        code: CERTOPS_AGENT_REGISTRATION_CONFLICT,
      });
    case CERTOPS_AGENT_RETIRED:
      return res.status(410).json(CERTOPS_AGENT_RETIRED_RESPONSE);
    case CERTOPS_WORKSPACE_PAUSED:
      // Kill switch blocks dispatch, never results.
      return res.status(409).json({
        error: "CertOps is paused for this workspace",
        code: CERTOPS_WORKSPACE_PAUSED,
      });
    case CERTOPS_DISABLED:
      return res.status(404).json({
        error: "Endpoint not found",
        code: "NOT_FOUND",
      });
    case CERTOPS_AGENT_JOB_NOT_FOUND:
    case CERTOPS_JOB_NOT_FOUND:
      return res.status(404).json({
        error: "Certificate job not found",
        code: CERTOPS_AGENT_JOB_NOT_FOUND,
      });
    case CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH:
      return res.status(409).json({
        error: "Result does not match the current claim for this job",
        code: CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH,
      });
    case CERTOPS_AGENT_RESULT_NONCE_REJECTED:
      return res.status(409).json({
        error: "Result nonce was rejected",
        code: CERTOPS_AGENT_RESULT_NONCE_REJECTED,
      });
    case CERTOPS_AGENT_SEQUENCE_REGRESSION:
      return res.status(409).json({
        error:
          "Message sequence is not greater than the last accepted sequence for this agent",
        code: CERTOPS_AGENT_SEQUENCE_REGRESSION,
      });
    case CERTOPS_AGENT_RESULT_STATUS_INVALID:
      return res.status(400).json({
        error: "Result status is invalid",
        code: CERTOPS_AGENT_RESULT_STATUS_INVALID,
      });
    case PRIVATE_KEY_MATERIAL_REJECTED:
      return res.status(422).json({
        error: "Private key material is not accepted on CertOps agent routes",
        code: PRIVATE_KEY_MATERIAL_REJECTED,
      });
    default:
      logger.error("CertOps agent route failed", {
        code: error?.code || null,
        message: error?.message,
      });
      return res.status(500).json({
        error: "CertOps agent request failed",
        code: "CERTOPS_AGENT_REQUEST_FAILED",
      });
  }
}

// --- Handlers ---

async function registerHandler(req, res, options = {}) {
  try {
    const envelope = validateEnvelope(req.body, "register");
    const body = validateRegisterBody(envelope);
    const result = await (options.registerAgent || registerAgent)({
      dbPool: options.dbPool,
      bootstrapToken: req.agentBootstrapToken,
      envelope,
      body,
      deps: options.registerDeps,
    });
    // Shape consumed by packages/agent register(): agentId, credential
    // (raw ttagent_, shown exactly once), protocolVersion, signingKeyId,
    // signingPublicKeyPem (PUBLIC key material only).
    return res.status(201).json(result);
  } catch (error) {
    return handleAgentRouteError(res, error);
  }
}

async function heartbeatHandler(req, res, options = {}) {
  try {
    const envelope = validateEnvelope(req.body, "heartbeat");
    const body = validateHeartbeatBody(envelope);
    const result = await (options.recordHeartbeat || recordHeartbeat)({
      dbPool: options.dbPool,
      agent: req.certopsAgent,
      envelope,
      body,
      deps: options.heartbeatDeps,
    });
    return res.status(200).json(result);
  } catch (error) {
    return handleAgentRouteError(res, error);
  }
}

async function claimHandler(req, res, options = {}) {
  try {
    const envelope = validateEnvelope(req.body, "claim");
    const body = validateClaimBody(envelope);
    const result = await (options.claimJobs || claimJobs)({
      dbPool: options.dbPool,
      agent: req.certopsAgent,
      envelope,
      body,
      env: options.env,
      deps: options.claimDeps,
    });
    // { jobs: [...] } where each job is the signed dispatch payload the
    // agent client passes to verifyJobSignature (job fields + nonce,
    // issuedAt, expiresAt, signingKeyId, signature).
    return res.status(200).json(result);
  } catch (error) {
    return handleAgentRouteError(res, error);
  }
}

async function resultsHandler(req, res, options = {}) {
  try {
    const messageType = req.body?.messageType;
    if (messageType === "evidence") {
      const envelope = validateEnvelope(req.body, "evidence");
      const body = validateEvidenceBody(envelope);
      if (!body.jobId) {
        // Jobless evidence is the discovery path: agents report observed
        // certificate inventory (certificate.observed) with jobId null.
        // Only that event type has a jobless persistence target; anything
        // else without a jobId stays invalid.
        const onlyObservations = body.evidenceItems.every(
          (item) => item.eventType === "certificate.observed",
        );
        if (!onlyObservations) {
          throw messageError(
            "jobId is required for agent evidence messages other than certificate.observed",
          );
        }
        await (options.enforceAgentSequence || enforceAgentSequence)({
          client: options.dbPool,
          agentRowId: req.certopsAgent.id,
          envelope,
        });
        const persistObservation =
          options.createControllerObservationEvidence ||
          createControllerObservationEvidence;
        const observations = [];
        for (const item of body.evidenceItems) {
          const evidence = await persistObservation({
            client: options.dbPool,
            workspaceId: req.certopsAgent.workspaceId,
            evidenceType: item.eventType,
            metadata: {
              summary: item.summary ?? null,
              fingerprintSha256: item.fingerprintSha256 ?? null,
              agentId: req.certopsAgent.agentId,
              ...(Array.isArray(item.metadata)
                ? Object.fromEntries(
                    item.metadata.map((entry) => [entry.name, entry.value]),
                  )
                : {}),
            },
            observedAt: item.observedAt,
          });
          observations.push(evidence);
        }
        return res
          .status(200)
          .json({ ok: true, evidenceCount: observations.length });
      }
      // Sequence enforcement (post-auth; evidence carries no dispatch
      // nonce, so this is the only anti-replay/ordering gate here). Runs
      // before any evidence row is appended.
      await (options.enforceAgentSequence || enforceAgentSequence)({
        client: options.dbPool,
        agentRowId: req.certopsAgent.id,
        envelope,
      });
      // Claim-ownership binding: only the agent that claimed the job may
      // append evidence to it (409 CERTOPS_AGENT_CLAIM_OWNERSHIP_MISMATCH
      // otherwise). Post-result evidence from the same agent stays valid
      // because claimed_by_agent_id survives completion.
      await (options.assertEvidenceClaimOwnership ||
        assertEvidenceClaimOwnership)({
        dbPool: options.dbPool,
        agent: req.certopsAgent,
        jobId: body.jobId,
      });
      // Lock-free append (no job row lock, no ownership transition):
      // ownership was proven above; createCertificateEvidence only
      // verifies the job exists.
      const persist =
        options.createCertificateEvidence || createCertificateEvidence;
      const created = [];
      for (const item of body.evidenceItems) {
        const evidence = await persist({
          client: options.dbPool,
          workspaceId: req.certopsAgent.workspaceId,
          jobId: body.jobId,
          evidenceType: item.eventType,
          metadata: {
            summary: item.summary ?? null,
            fingerprintSha256: item.fingerprintSha256 ?? null,
            agentId: req.certopsAgent.agentId,
            ...(Array.isArray(item.metadata)
              ? Object.fromEntries(
                  item.metadata.map((entry) => [entry.name, entry.value]),
                )
              : {}),
          },
          observedAt: item.observedAt,
        });
        created.push(evidence);
      }
      return res.status(200).json({ ok: true, evidenceCount: created.length });
    }

    const envelope = validateEnvelope(req.body, "result");
    const body = validateResultBody(envelope);
    const result = await (options.ingestResult || ingestResult)({
      dbPool: options.dbPool,
      agent: req.certopsAgent,
      envelope,
      body: { ...body, claimId: body.claimId ?? body.attemptId },
      deps: options.resultDeps,
    });
    return res.status(200).json(result);
  } catch (error) {
    return handleAgentRouteError(res, error);
  }
}

// --- Router factory ---

function createCertOpsAgentRouter(options = {}) {
  const certOpsAgentRouter = router();
  const preAuthRateLimitMiddleware =
    options.preAuthRateLimitMiddleware ||
    createCertOpsMachineTokenPreAuthRateLimit(
      options.preAuthRateLimitOptions || options.rateLimitOptions || {},
    );
  const bootstrapAuthMiddleware =
    options.bootstrapAuthMiddleware || createAgentBootstrapTokenAuth();
  const credentialAuthMiddleware =
    options.credentialAuthMiddleware || createAgentCredentialAuth();
  const rateLimitMiddleware =
    options.rateLimitMiddleware ||
    createCertOpsMachineTokenRateLimit(options.rateLimitOptions || {});
  const certOpsEnabledMiddleware =
    options.certOpsEnabledMiddleware || requireCertOpsEnabled;
  const rejectPrivateMaterialMiddleware =
    options.rejectPrivateMaterialMiddleware || rejectAgentPrivateMaterial;
  // The production pre-parser boundary (certops-executor-body-parser)
  // already rate limited and parsed exact agent-route POSTs; apply our own
  // pre-auth limiter only when mounted standalone (tests, direct mounts).
  const preAuthRateLimitFallback = (req, res, next) => {
    if (hasCertOpsExecutorPreAuthLimit(req)) return next();
    return preAuthRateLimitMiddleware(req, res, next);
  };

  certOpsAgentRouter.post(
    CERTOPS_AGENT_REGISTER_PATH,
    preAuthRateLimitFallback,
    bootstrapAuthMiddleware,
    agentRateLimitIdentity,
    rateLimitMiddleware,
    rejectPrivateMaterialMiddleware,
    certOpsEnabledMiddleware,
    (req, res) => registerHandler(req, res, options),
  );

  const credentialChain = [
    preAuthRateLimitFallback,
    credentialAuthMiddleware,
    agentRateLimitIdentity,
    rateLimitMiddleware,
    rejectPrivateMaterialMiddleware,
    certOpsEnabledMiddleware,
  ];

  certOpsAgentRouter.post(
    CERTOPS_AGENT_HEARTBEAT_PATH,
    ...credentialChain,
    requireNonRetiredAgent,
    (req, res) => heartbeatHandler(req, res, options),
  );

  certOpsAgentRouter.post(
    CERTOPS_AGENT_JOBS_CLAIM_PATH,
    ...credentialChain,
    requireNonRetiredAgent,
    (req, res) => claimHandler(req, res, options),
  );

  // Results keep the retired 410 consistent with heartbeat/claim: the agent
  // client's postJson treats any non-2xx as terminal for the request, and
  // only heartbeat special-cases 410 into { retired: true } -- a retired
  // agent reporting results gets the same unambiguous "stop" signal.
  // Kill switch is NOT checked here: results are always accepted.
  certOpsAgentRouter.post(
    CERTOPS_AGENT_JOBS_RESULTS_PATH,
    ...credentialChain,
    requireNonRetiredAgent,
    (req, res) => resultsHandler(req, res, options),
  );

  return certOpsAgentRouter;
}

const defaultRouter = createCertOpsAgentRouter();

module.exports = defaultRouter;
module.exports.createCertOpsAgentRouter = createCertOpsAgentRouter;
module.exports._test = {
  AGENT_UNAUTHORIZED_RESPONSE,
  CERTOPS_AGENT_HEARTBEAT_PATH,
  CERTOPS_AGENT_JOBS_CLAIM_PATH,
  CERTOPS_AGENT_JOBS_RESULTS_PATH,
  CERTOPS_AGENT_MESSAGE_INVALID,
  CERTOPS_AGENT_REGISTER_PATH,
  CERTOPS_AGENT_RETIRED_RESPONSE,
  agentRateLimitIdentity,
  claimHandler,
  handleAgentRouteError,
  heartbeatHandler,
  registerHandler,
  rejectAgentPrivateMaterial,
  requireNonRetiredAgent,
  resultsHandler,
  validateClaimBody,
  validateEnvelope,
  validateEvidenceBody,
  validateHeartbeatBody,
  validateRegisterBody,
  validateResultBody,
};

