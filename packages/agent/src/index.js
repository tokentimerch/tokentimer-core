"use strict";

/**
 * TokenTimer Agent - execution-plane entry.
 *
 * Structural scope note (docs/certops/CONTEXT.md): this package is the
 * execution plane, the only component that touches private keys. It holds
 * keys on the host it runs on; TokenTimer's control plane never receives or
 * stores them. Every module here must stay safe to run against an untrusted
 * or compromised control plane (agent-local policy wins, ADR-0002).
 *
 * Bootstrap scope (current): this file wires the landed modules together
 * into a runnable outbound-only process:
 *   - config: config.json + secure credential storage (src/config)
 *   - policy: agent-local allowlist engine, default-deny (src/policy)
 *   - protocol: register/heartbeat/claim/result/evidence client (src/protocol)
 *   - evidence: schema-safe evidence construction + final key-material scan
 *     (src/evidence)
 *   - discovery: observe-only filesystem certificate inventory, reported as
 *     certificate.observed evidence (src/discovery)
 *
 * signed-job dispatch (current, opt-in via config.execution.enabled):
 * jobs claimed from the control plane run through the full trust chain
 * before any execution: Ed25519 signature verification against the pinned
 * signing key (src/signing) -> replay-cache check (src/replay) -> clock
 * window check with drift compensation (src/clock) -> agent-local policy
 * (src/policy) -> replay consume -> execute. Execution modules: src/keys,
 * src/acme, src/deploy, src/reload, src/verify.
 *
 * When execution is NOT enabled (config.execution absent or enabled:false),
 * the agent runs observe-only: register, heartbeat, and filesystem discovery
 * remain fully active, but the agent advertises zero executable/mutating
 * actions and never polls the claim endpoint. Claiming production jobs while
 * unable to execute them previously stranded leases (blocked reports lacked
 * claimId/nonce). handleClaimedJob still treats an unexpected claim as
 * "blocked"/"rejected" defense-in-depth if one ever arrives.
 *
 * Known base-payload deviations (job-payload.schema.json lacks signed-job execution
 * fields; documented for the control-plane backend contract):
 *   - No domains list => the CSR CN and ACME -d domain come from
 *     job.target.reference.
 *   - No keyRotation flag => renew reuses an existing key at
 *     <keysDir>/<certificateId>.key.pem and generates one only when absent;
 *     keyRotated reports whether a new key was generated. A truthy
 *     job.keyRotation (forward-compatible) forces regeneration.
 *   - No certPath field => job.certPath is honored when present; otherwise
 *     target.reference is used as the deploy destination when it is an
 *     absolute path. Neither present/absolute => renew deploys nowhere it
 *     can name, so the job fails with a clear message.
 *   - "deploy" jobs need certificatePem from the control plane; the base
 *     payload has no such field, so deploy without it reports "blocked"
 *     (awaiting the deploy job-type contract).
 *   - "revoke" execution is out of scope for this agent build => always "blocked".
 */

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  resolveConfigDir,
  loadAgentConfig,
  writeSigningKeyPin,
  readSigningKeyPin,
  readCredential,
  persistRegistration,
  recoverPendingRegistration,
  ensureRegistrationId,
  clearRegistrationId,
  readCaBundle,
  createSequenceAllocator,
  deleteBootstrapEnvFile,
} = require("./config");
const { loadPolicyConfig, createPolicyEngine } = require("./policy");
const {
  createProtocolClient,
  createCaAwareFetch,
  startPollLoop,
  validateRegistrationResponse,
} = require("./protocol");
const {
  buildPolicyRejectionEvidence,
  buildEvidenceItem,
  buildEvidenceBody,
  assertEvidencePayloadSafe,
} = require("./evidence");
const { discoverCertificates } = require("./discovery");
const {
  validateClaimedJob,
  hasReportableJobId,
} = require("./claimed-job");
const { defaultAgentLogger } = require("./logging");
const { verifyJobSignature, checkJobTimeWindow, DEFAULT_TIME_WINDOW_TOLERANCE_MS } = require("./signing");
const { createReplayCache } = require("./replay");
const { createClockOffsetEstimator } = require("./clock");
const { generateKeyPairToFile, generateCsr } = require("./keys");
const { createAcmeAdapter } = require("./acme");
const { deployCertificate, getDeployMetrics } = require("./deploy");
const { reloadService } = require("./reload");
const {
  verifyDeployedCertificate,
  computeCertificateFingerprint,
} = require("./verify");
const {
  enqueueOutboxEntry,
  transmitOutboxEntry,
  acknowledgeOutboxEntry,
  drainOutbox,
  createEvidenceBuffer,
} = require("./outbox");

const { version: AGENT_VERSION } = require("../package.json");

/**
 * Maps a claimed job payload (packages/contracts/certops/job-payload.
 * schema.json shape) onto the policy engine's jobDescriptor vocabulary.
 *
 * The claimed-job validator checks the full frozen public job shape first.
 * Action-specific policy dimensions are required in public metadata and are
 * never silently omitted. Signed-dispatch execution fields are additionally
 * verified by the signing/replay/clock modules before any execution.
 *
 * @param {object} job claimed job payload
 * @returns {object} policy jobDescriptor
 */
function buildJobPolicyDescriptor(job) {
  return validateClaimedJob(job).policyDescriptor;
}

/**
 * Policy descriptor mapping for the signed-dispatch path. Signed jobs carry
 * execution fields (issuedAt/expiresAt/nonce/signature/commandRef/...) that
 * the frozen bootstrap job shape does not allow; their full field validation
 * happens inside verifyJobSignature (findSignedFieldProblem) BEFORE this
 * mapping runs, so only the policy-dimension projection is done here.
 *
 * @param {object} job signature-verified claimed job payload
 * @returns {object} policy jobDescriptor
 */
function buildSignedJobPolicyDescriptor(job) {
  const descriptor = {};
  if (job?.target?.reference !== undefined) {
    descriptor.targetSelector = job.target.reference;
  }
  for (const field of ["commandRef", "path", "caEndpoint", "dnsZone", "dnsProvider"]) {
    if (job?.[field] !== undefined) descriptor[field] = job[field];
  }
  // Any custody-shaped intent on a job maps onto the engine's single
  // unconditional key-export rejection flag. No job payload field is
  // expected to carry this today (the schema forbids custody fields), but
  // if a compromised control plane smuggled one in, this is the belt to
  // the schema's suspenders.
  if (
    job?.requestsKeyExport === true ||
    job?.exportPrivateKey === true ||
    job?.keyExport === true
  ) {
    descriptor.requestsKeyExport = true;
  }
  return descriptor;
}

function emitLog(log, message, details) {
  if (typeof log === "function") {
    log(message, details);
    return;
  }
  defaultAgentLogger.error(message, details);
}

function localAttemptId(jobId) {
  return `local-${jobId}-${Date.now()}`;
}

/**
 * Bound applied to errorMessage strings reported through reportResult so a
 * failing step can never flood the control plane (and pre-redacted module
 * excerpts stay small). The evidence module separately enforces its own
 * summary bounds.
 */
const EXECUTION_ERROR_MESSAGE_MAX_CHARS = 512;

/** ACME adapter kinds executeJob accepts from a job payload. */
const SUPPORTED_ACME_KINDS = ["certbot", "acme.sh"];

/**
 * Actions this agent build can actually execute (executeJob): "revoke" is
 * deliberately absent (always blocked in this build). Sent as the claim's
 * supportedActions when execution is enabled so the control plane's claim
 * query only leases jobs this agent can run.
 */
const EXECUTABLE_JOB_ACTIONS = Object.freeze(["noop", "renew", "deploy", "reload"]);

/**
 * Claim scope in observe-only mode (execution disabled): empty. An
 * observe-only agent must never advertise mutating/executable actions and
 * must never poll claim; an empty list is the wire-level expression of
 * "no executable actions" if a claim call is ever made in error.
 */
const OBSERVE_ONLY_CLAIM_ACTIONS = Object.freeze([]);

/**
 * Actions advertised on claim polls. Observe-only agents return [].
 *
 * @param {object|null|undefined} executionContext
 * @returns {readonly string[]}
 */
function resolveClaimSupportedActions(executionContext) {
  if (executionContext !== null && executionContext !== undefined && executionContext.enabled === true) {
    return EXECUTABLE_JOB_ACTIONS;
  }
  return OBSERVE_ONLY_CLAIM_ACTIONS;
}

/**
 * Whether this process should poll the jobs/claim endpoint. Observe-only
 * agents must not claim (B3): discovery and heartbeat stay independent.
 *
 * @param {object|null|undefined} executionContext
 * @returns {boolean}
 */
function shouldPollForJobs(executionContext) {
  return executionContext !== null && executionContext !== undefined && executionContext.enabled === true;
}

/**
 * Exit code used when the control plane retires this agent. Paired with
 * RestartPreventExitStatus in scripts/tokentimer-agent.service so systemd
 * (Restart=on-failure/always) does not respawn a decommissioned agent into
 * a heartbeat 410 loop (ADR-0002 clean retirement).
 */
const AGENT_RETIRED_EXIT_CODE = 86;

/**
 * POSIX-or-Windows absolute path check (same rationale as the acme
 * module's isAbsolutePathLike: agents primarily target POSIX hosts but
 * tests run on Windows too).
 *
 * @param {unknown} candidate
 * @returns {boolean}
 */
function isAbsolutePathLike(candidate) {
  return (
    typeof candidate === "string" &&
    (/^\//.test(candidate) ||
      /^[A-Za-z]:[\\/]/.test(candidate) ||
      /^\\\\/.test(candidate))
  );
}

/**
 * @param {unknown} message
 * @returns {string} message bounded to EXECUTION_ERROR_MESSAGE_MAX_CHARS
 */
function boundErrorMessage(message) {
  return String(message).slice(0, EXECUTION_ERROR_MESSAGE_MAX_CHARS);
}

/**
 * Resolves the deploy destination for a job. base-payload deviation
 * (documented in the module docblock): the payload has no certPath field,
 * so an explicit job.certPath wins, then target.reference when it is an
 * absolute path, else null (the caller fails the job with a clear message).
 *
 * @param {object} job
 * @returns {string|null}
 */
function resolveJobCertPath(job) {
  if (isAbsolutePathLike(job?.certPath)) return job.certPath;
  if (isAbsolutePathLike(job?.target?.reference)) return job.target.reference;
  return null;
}

/**
 * Persists a terminal job outcome (+ evidence) to the durable outbox, then
 * attempts transmission. Transmission failures leave the entry on disk for
 * retry and never rewrite a persisted success as a failure (B8).
 *
 * @param {object} params
 * @param {string} params.outboxDir
 * @param {object} params.client live protocol client (network)
 * @param {object} params.result reportResult payload
 * @param {object[]} [params.evidence] reportEvidence bodies, in order
 * @param {(msg: string, details?: *) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function persistAndTransmitOutcome({
  outboxDir,
  client,
  result,
  evidence = [],
  log = null,
}) {
  const entry = enqueueOutboxEntry(outboxDir, { result, evidence });
  try {
    await transmitOutboxEntry(entry, client);
    acknowledgeOutboxEntry(outboxDir, entry.id);
  } catch (err) {
    emitLog(
      log,
      `tokentimer-agent: failed to transmit outbox entry for job ${result.jobId}; ` +
        "persisted outcome retained for retry (execution result unchanged)",
      err,
    );
  }
  return {
    status: result.status,
    rejectionReason: result.rejectionReason ?? null,
  };
}

/**
 * Reports a trust-layer or policy rejection uniformly: policy.checked
 * evidence built from the { allowed:false, rejectionReason, detail } shape
 * (shared by signing/replay/clock/policy modules), then a "rejected"
 * result. Evidence is deep-scanned for key material before every persist.
 *
 * @param {object} params
 * @param {object} params.client
 * @param {string} params.jobId
 * @param {string} params.attemptId
 * @param {{ rejectionReason: string, detail: string }} params.verdict
 * @param {(msg: string) => void} params.log
 * @param {string} params.outboxDir
 * @returns {Promise<{ status: "rejected", rejectionReason: string }>}
 */
async function reportJobRejection({
  client,
  jobId,
  attemptId,
  claimId = null,
  nonce = null,
  verdict,
  log,
  outboxDir,
}) {
  log(
    `tokentimer-agent: job ${jobId} rejected: ${verdict.rejectionReason}`,
  );
  const evidenceBody = buildPolicyRejectionEvidence({
    rejectionReason: verdict.rejectionReason,
    detail: verdict.detail,
    jobId,
  });
  assertEvidencePayloadSafe(evidenceBody);
  return await persistAndTransmitOutcome({
    outboxDir,
    client,
    result: {
      jobId,
      attemptId,
      claimId,
      nonce,
      status: "rejected",
      rejectionReason: verdict.rejectionReason,
    },
    evidence: [evidenceBody],
    log,
  });
}

/**
 * Builds + safety-scans + reports one evidence body of pre-built items.
 *
 * @param {object} client
 * @param {string} jobId
 * @param {object[]} items evidence items (buildEvidenceItem inputs)
 * @returns {Promise<void>}
 */
async function reportStepEvidence(client, jobId, items) {
  const body = buildEvidenceBody({ jobId, evidenceItems: items });
  assertEvidencePayloadSafe(body);
  await client.reportEvidence(body);
}

/**
 * Handles a single claimed job.
 *
 * Without an execution context (observe-only bootstrap mode, executionContext null or
 * enabled:false): evaluate agent-local policy, then report either a policy
 * rejection (with evidence) or a "blocked" result explaining that execution
 * is not enabled. This branch is byte-for-byte the observe-only bootstrap behavior.
 *
 * With an enabled execution context: run the full trust chain in
 * order -- signature verify -> replay check -> clock window check -> policy
 * evaluateJob -> replay consume -> executeJob. Any { allowed: false }
 * verdict reports policy.checked evidence + a "rejected" result with that
 * rejectionReason. A job missing its signed-dispatch fields is rejected
 * with job_integrity_failed (unsigned jobs must never execute). If no
 * signing key is pinned yet, jobs are "blocked" (never executed) until
 * registration pins one.
 *
 * Never throws for per-job failures; errors are reported through the
 * protocol client and logged.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {object} params.job claimed job payload
 * @param {object} params.policyEngine from createPolicyEngine
 * @param {object} params.client from createProtocolClient
 * @param {object|null} [params.executionContext] from
 *   buildExecutionContext; null preserves observe-only bootstrap behavior
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleClaimedJob({
  job,
  policyEngine,
  client,
  executionContext = null,
  log = null,
}) {
  const reportableJobId = hasReportableJobId(job?.jobId) ? job.jobId : null;
  const executionEnabled =
    executionContext !== null && executionContext.enabled === true;

  if (executionEnabled) {
    if (!reportableJobId) {
      emitLog(log, "claimed job missing a reportable jobId; skipping");
      return { status: "skipped", rejectionReason: "job_integrity_failed" };
    }
    // Signed dispatch assigns attemptId server-side (mirroring claimId);
    // prefer it, then claimId itself, then a local fallback so result
    // reporting stays schema-valid and idempotency-debuggable.
    const signedAttemptId =
      typeof job.attemptId === "string" && job.attemptId.length > 0
        ? job.attemptId
        : typeof job.claimId === "string" && job.claimId.length > 0
          ? job.claimId
          : localAttemptId(reportableJobId);
    return handleSignedJob({
      job,
      jobId: reportableJobId,
      attemptId: signedAttemptId,
      policyEngine,
      client,
      executionContext,
      log,
    });
  }

  let validated;
  try {
    validated = validateClaimedJob(job);
  } catch (err) {
    emitLog(log, "rejected malformed claimed job before policy evaluation", err);
    if (!reportableJobId) {
      return { status: "skipped", rejectionReason: "job_integrity_failed" };
    }
    try {
      const attemptId = localAttemptId(reportableJobId);
      const evidenceBody = buildPolicyRejectionEvidence({
        rejectionReason: "job_integrity_failed",
        detail: "Claimed job failed agent-side shape and policy-dimension validation.",
        jobId: reportableJobId,
      });
      assertEvidencePayloadSafe(evidenceBody);
      await client.reportEvidence(evidenceBody);
      await client.reportResult({
        jobId: reportableJobId,
        attemptId,
        status: "rejected",
        rejectionReason: "job_integrity_failed",
      });
      return { status: "rejected", rejectionReason: "job_integrity_failed" };
    } catch (reportError) {
      emitLog(log, "failed to report malformed claimed job", reportError);
      return { status: "failed", rejectionReason: "job_integrity_failed" };
    }
  }

  const { job: validatedJob, policyDescriptor } = validated;
  const attemptId = localAttemptId(validatedJob.jobId);
  try {
    const verdict = policyEngine.evaluateJob(policyDescriptor);
    if (!verdict.allowed) {
      emitLog(log, `job ${validatedJob.jobId} rejected by agent-local policy`, {
        rejectionReason: verdict.rejectionReason,
      });
      const evidenceBody = buildPolicyRejectionEvidence({
        rejectionReason: verdict.rejectionReason,
        detail: verdict.detail,
        jobId: validatedJob.jobId,
      });
      assertEvidencePayloadSafe(evidenceBody);
      await client.reportEvidence(evidenceBody);
      await client.reportResult({
        jobId: validatedJob.jobId,
        attemptId,
        status: "rejected",
        rejectionReason: verdict.rejectionReason,
      });
      return { status: "rejected", rejectionReason: verdict.rejectionReason };
    }

    // Execution is not configured on this agent: report "blocked" rather
    // than silently dropping so the control plane sees an explicit
    // terminal state.
    await client.reportResult({
      jobId: validatedJob.jobId,
      attemptId,
      status: "blocked",
      errorMessage: "agent execution is not enabled on this agent",
    });
    return { status: "blocked", rejectionReason: null };
  } catch (err) {
    emitLog(log, `failed while handling claimed job ${validatedJob.jobId}`, err);
    return { status: "failed", rejectionReason: null };
  }
}

/**
 * Trust chain for a claimed job when execution is enabled. Order per
 * ADR-0003 (and tests/integration/agent-protocol.test.js
 * runVerificationChain): signature verify -> replay check -> clock window
 * check -> policy -> replay consume -> execute. The replay nonce is
 * consumed only after every gate passed, so a rejected job does not burn
 * its nonce, but it IS consumed before execution starts, so a crash
 * mid-execution can never allow a replay.
 *
 * @param {object} params see handleClaimedJob
 * @returns {Promise<{ status: string, rejectionReason: string|null }>}
 */
async function handleSignedJob({
  job,
  jobId,
  attemptId,
  policyEngine,
  client,
  executionContext,
  log,
}) {
  const { pinnedSigningKey, replayCache, clockEstimator, execution, outboxDir } =
    executionContext;
  // Server-assigned claim id and single-use dispatch nonce: forwarded on
  // every result so the control plane can re-prove claim ownership and
  // consume the nonce in its replay ledger (ADR-0003).
  const claimId =
    typeof job?.claimId === "string" && job.claimId.length > 0
      ? job.claimId
      : null;
  const nonce =
    typeof job?.nonce === "string" && job.nonce.length > 0 ? job.nonce : null;

  const resolvedOutboxDir = outboxDir || execution.outboxDir;
  if (typeof resolvedOutboxDir !== "string" || resolvedOutboxDir.length === 0) {
    throw new Error(
      "tokentimer-agent: execution outboxDir is required when execution is enabled",
    );
  }

  const rejectionArgs = {
    client,
    jobId,
    attemptId,
    claimId,
    nonce,
    log,
    outboxDir: resolvedOutboxDir,
  };

  // No pinned key => integrity of ANY job cannot be established. Blocked,
  // not rejected: this is an agent-side precondition failure, not a verdict
  // about the job itself.
  if (!pinnedSigningKey) {
    return persistAndTransmitOutcome({
      outboxDir: resolvedOutboxDir,
      client,
      result: {
        jobId,
        attemptId,
        claimId,
        nonce,
        status: "blocked",
        errorMessage:
          "execution is enabled but no control-plane signing key is pinned " +
          "yet (the register response did not carry one); unsigned or " +
          "unverifiable jobs are never executed",
      },
      log,
    });
  }

  // 1. Signature (covers the base-payload fallback: a job without signed
  // fields fails field validation inside verifyJobSignature and is
  // rejected with job_integrity_failed).
  const signatureVerdict = verifyJobSignature({
    job,
    publicKeyPem: pinnedSigningKey.publicKeyPem,
    pinnedSigningKeyId: pinnedSigningKey.signingKeyId,
  });
  if (!signatureVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: signatureVerdict });
  }

  // 2. Replay check (no consume yet).
  const replayVerdict = replayCache.check({
    nonce: job.nonce,
    jobId,
    expiresAt: job.expiresAt,
  });
  if (!replayVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: replayVerdict });
  }

  // 3. Clock window with drift compensation.
  const windowVerdict = checkJobTimeWindow({
    job,
    nowMs: Date.now(),
    clockOffsetMs: clockEstimator.getOffsetMs(),
    toleranceMs: execution.clockDriftToleranceMs,
  });
  if (!windowVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: windowVerdict });
  }

  // 4. Agent-local policy (default deny; ADR-0002 local policy wins).
  const policyVerdict = policyEngine.evaluateJob(buildSignedJobPolicyDescriptor(job));
  if (!policyVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: policyVerdict });
  }

  // 5. Consume the nonce before executing (see function doc comment).
  const consumeVerdict = replayCache.consume({
    nonce: job.nonce,
    jobId,
    expiresAt: job.expiresAt,
  });
  if (!consumeVerdict.allowed) {
    return reportJobRejection({ ...rejectionArgs, verdict: consumeVerdict });
  }

  // 6. Execute. Step evidence is buffered locally; the terminal outcome and
  // evidence are persisted to the durable outbox BEFORE any network
  // transmission so a reportResult failure cannot reclassify a real-world
  // success as "failed" (B8).
  const evidenceBuffer = createEvidenceBuffer();
  let outcome;
  try {
    outcome = await executeJob({
      job,
      jobId,
      policyEngine,
      client: evidenceBuffer,
      executionContext,
      log,
    });
  } catch (err) {
    log(`tokentimer-agent: job ${jobId} execution error: ${err.message}`);
    outcome = {
      status: "failed",
      errorMessage: boundErrorMessage(`job execution failed: ${err.message}`),
    };
  }

  const evidenceBodies = evidenceBuffer.takeEvidence();
  for (const body of evidenceBodies) {
    assertEvidencePayloadSafe(body);
  }

  return persistAndTransmitOutcome({
    outboxDir: resolvedOutboxDir,
    client,
    result: {
      jobId,
      attemptId,
      claimId,
      nonce,
      status: outcome.status,
      rejectionReason: outcome.rejectionReason ?? null,
      keyRotated: outcome.keyRotated ?? null,
      errorMessage: outcome.errorMessage ?? null,
      clockOffsetMs: clockEstimator.getOffsetMs(),
    },
    evidence: evidenceBodies,
    log,
  });
}

/**
 * Executes a fully verified + policy-approved job. Never reports the
 * terminal result itself (handleSignedJob does); it DOES report per-step
 * evidence. Returns the fields for reportResult.
 *
 * Dry-run (execution.dryRun true, the default): every gate has already
 * run; this produces a policy.checked "plan" evidence item per step that
 * WOULD run, with zero filesystem/exec side effects (keys/acme/deploy/
 * reload/verify modules are never called), then returns "succeeded" with
 * keyRotated null and a dry-run marker in the evidence metadata.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {object} params.job verified job payload
 * @param {string} params.jobId
 * @param {object} params.policyEngine
 * @param {object} params.client
 * @param {object} params.executionContext from buildExecutionContext
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ status: string, rejectionReason?: string|null, keyRotated?: boolean|null, errorMessage?: string|null }>}
 */
async function executeJob({
  job,
  jobId,
  policyEngine,
  client,
  executionContext,
  log = console.error,
}) {
  const { execution } = executionContext;
  const action = job.action;
  const observedAt = new Date().toISOString();

  if (action === "noop") {
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.passed",
        observedAt,
        summary: `Noop job ${jobId} executed: signature, replay, clock window, and policy gates all passed; no side effects requested.`,
        metadata: [{ name: "action", value: "noop" }],
      }),
    ]);
    return { status: "succeeded", keyRotated: null };
  }

  if (action === "revoke") {
    // Revocation execution is out of scope for this agent build.
    return {
      status: "blocked",
      errorMessage:
        "revoke jobs are not executable by this agent version (revocation " +
        "execution is not supported yet)",
    };
  }

  if (action === "deploy" && typeof job.certificatePem !== "string") {
    // Base-payload deviation: deploy needs certificate bytes from the control
    // plane and the base payload has no such field (awaiting the deploy
    // job-type contract).
    return {
      status: "blocked",
      errorMessage:
        "deploy job carries no certificatePem field; the job payload " +
        "does not define one yet (awaiting the deploy job contract), so " +
        "there is nothing to deploy",
    };
  }

  if (action !== "renew" && action !== "deploy" && action !== "reload") {
    return {
      status: "blocked",
      errorMessage: `unsupported job action "${String(action)}"`,
    };
  }

  if (execution.dryRun) {
    return executeDryRunPlan({ jobId, action, client, observedAt });
  }

  if (action === "renew") {
    return executeRenewJob({ job, jobId, policyEngine, client, executionContext, log });
  }
  if (action === "deploy") {
    return executeDeployJob({ job, jobId, policyEngine, client, log });
  }
  return executeReloadJob({ job, jobId, policyEngine, client, log });
}

/**
 * Dry-run "plan" reporting: one policy.checked evidence item per step the
 * action WOULD run, public fields only, zero side effects. Returns a
 * succeeded result (the agent-protocol resultBody allows "succeeded" with
 * keyRotated/errorMessage null, so a plan-only run is schema-valid).
 *
 * @param {object} params
 * @returns {Promise<{ status: "succeeded", keyRotated: null, errorMessage: null }>}
 */
async function executeDryRunPlan({ jobId, action, client, observedAt }) {
  const plannedSteps = {
    renew: [
      "keys: reuse or generate the certificate key under the configured keysDir",
      "csr: build a CSR with CN from target.reference",
      "acme: run the allowlisted ACME command against job.caEndpoint",
      "deploy: atomically install the renewed certificate at the resolved certPath",
      "reload: validate-then-reload the target service when the job requests it",
      "verify: fingerprint the deployed certificate",
    ],
    deploy: [
      "deploy: atomically install the job-supplied certificate at the resolved certPath",
      "reload: validate-then-reload the target service when the job requests it",
      "verify: fingerprint the deployed certificate",
    ],
    reload: [
      "reload: validate-then-reload the target service via allowlisted command profiles",
    ],
  }[action];

  const items = plannedSteps.map((description, index) =>
    buildEvidenceItem({
      eventType: "policy.checked",
      observedAt,
      summary: `Dry run plan for ${action} job ${jobId}, step ${index + 1}/${plannedSteps.length}: ${description}. No side effects were performed.`,
      metadata: [
        { name: "dryRun", value: true },
        { name: "action", value: action },
        { name: "planStep", value: index + 1 },
      ],
    }),
  );
  await reportStepEvidence(client, jobId, items);
  return { status: "succeeded", keyRotated: null, errorMessage: null };
}

/**
 * Full renew chain: keys -> csr -> acme -> deploy -> reload (optional) ->
 * verify. Semantics documented in the module docblock (base-payload
 * deviations: CN from target.reference, key reuse unless job.keyRotation
 * is truthy, certPath from job.certPath else absolute target.reference).
 *
 * @param {object} params
 * @returns {Promise<object>} reportResult fields
 */
async function executeRenewJob({ job, jobId, policyEngine, client, executionContext, log }) {
  const { execution } = executionContext;
  const commonName = job?.target?.reference;
  if (typeof commonName !== "string" || commonName.length === 0) {
    return {
      status: "failed",
      errorMessage: "renew job has no target.reference to use as the certificate CN",
    };
  }

  const certPath = resolveJobCertPath(job);
  if (certPath === null) {
    return {
      status: "failed",
      errorMessage:
        "renew job names no deploy destination: neither job.certPath nor an " +
        "absolute-path target.reference is present",
    };
  }

  if (typeof job.commandRef !== "string" || job.commandRef.length === 0) {
    return {
      status: "failed",
      errorMessage: "renew job carries no commandRef naming an allowlisted ACME command",
    };
  }
  const commandVerdict = policyEngine.checkCommandRef(job.commandRef);
  if (!commandVerdict.allowed) {
    return {
      status: "rejected",
      rejectionReason: commandVerdict.rejectionReason,
      errorMessage: boundErrorMessage(commandVerdict.detail),
    };
  }

  if (typeof job.caEndpoint !== "string" || job.caEndpoint.length === 0) {
    return {
      status: "failed",
      errorMessage: "renew job carries no caEndpoint",
    };
  }

  const acmeKind = SUPPORTED_ACME_KINDS.includes(job.acmeKind) ? job.acmeKind : "certbot";

  // Step 1: keys. Reuse-if-exists unless job.keyRotation is truthy
  // (forward-compatible field, absent from the base schema).
  fs.mkdirSync(execution.keysDir, { recursive: true });
  const keyPath = path.join(execution.keysDir, `${job.certificateId}.key.pem`);
  const forceRotation = job.keyRotation === true;
  const keyExisted = fs.existsSync(keyPath);
  const keyRotated = forceRotation || !keyExisted;
  if (keyRotated) {
    generateKeyPairToFile({ keyPath, overwrite: forceRotation });
  }

  // Step 2: CSR, written to a job-scoped temp path under keysDir (0600).
  const { csrPem } = generateCsr({
    keyPath,
    subject: { commonName },
    altNames: [commonName],
  });
  const csrPath = path.join(execution.keysDir, `${jobId}.csr.pem`);
  fs.writeFileSync(csrPath, csrPem, { mode: 0o600 });

  // The ACME client writes to a job-scoped staging path; the deploy module
  // then owns the atomic install (with backup/rollback) to certPath.
  const stagedCertPath = path.join(execution.keysDir, `${jobId}.cert.pem`);

  try {
    // Step 3: ACME renewal via the policy-resolved command profile.
    const adapter = createAcmeAdapter({
      kind: acmeKind,
      commandProfile: { argv: commandVerdict.argv },
      execFileImpl: executionContext.acmeExecFileImpl,
    });
    const renewal = await adapter.runRenewal({
      caEndpoint: job.caEndpoint,
      domains: [commonName],
      csrPath,
      outCertPath: stagedCertPath,
      checkCaEndpoint: (endpoint) => policyEngine.checkCaEndpoint(endpoint),
    });
    if (renewal.allowed === false) {
      return {
        status: "rejected",
        rejectionReason: renewal.rejectionReason,
        errorMessage: boundErrorMessage(renewal.detail),
      };
    }
    if (renewal.renewed !== true) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `ACME renewal step failed for job ${jobId} (exit code ${renewal.exitCode}).`,
          metadata: [{ name: "step", value: "acme" }, { name: "exitCode", value: renewal.exitCode }],
        }),
      ]);
      return {
        status: "failed",
        keyRotated,
        errorMessage: boundErrorMessage(
          `acme step failed with exit code ${renewal.exitCode}: ${renewal.stderrExcerpt || "no stderr"}`,
        ),
      };
    }
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.passed",
        observedAt: new Date().toISOString(),
        summary: `ACME renewal step succeeded for job ${jobId}.`,
        metadata: [{ name: "step", value: "acme" }, { name: "exitCode", value: renewal.exitCode }],
      }),
    ]);
  } finally {
    // The CSR is public material, but it is job-scoped scratch: remove it.
    fs.rmSync(csrPath, { force: true });
  }

  // Steps 4-6 are shared with the deploy action.
  let certificatePem;
  try {
    certificatePem = fs.readFileSync(stagedCertPath, "utf8");
  } catch (err) {
    return {
      status: "failed",
      keyRotated,
      errorMessage: boundErrorMessage(
        `acme step reported success but produced no certificate file: ${err.message}`,
      ),
    };
  } finally {
    fs.rmSync(stagedCertPath, { force: true });
  }
  const tail = await runDeployReloadVerify({
    job,
    jobId,
    policyEngine,
    client,
    certificatePem,
    certPath,
    log,
  });
  return { ...tail, keyRotated };
}

/**
 * Rolls back a completed deploy after a later tail step (reload or verify)
 * failed. Without this, a reload/verify failure would leave the NEW
 * certificate installed while the job reports failure -- the operator sees
 * "failed" but the destination silently changed.
 *
 * Only applies when the deploy actually wrote (deployed: true) AND left a
 * backup of the previous content (backupPath). An idempotent skip changed
 * nothing (nothing to roll back), and a first-ever deploy has no previous
 * certificate to restore (deleting the fresh file would be worse: the
 * job's failure report plus the deployment.updated evidence trail already
 * tells the operator exactly what is on disk).
 *
 * The restore goes through deployCertificate itself, so it gets the same
 * policy re-check, atomic write, and metrics as any deploy. After a
 * successful restore, the service reload (when the job requested one and
 * the refs resolve) is re-run best-effort so the service picks the old
 * content back up; its outcome is reported in the rollback evidence but
 * never changes the job's (already failed) result.
 *
 * @param {object} params
 * @returns {Promise<{ rolledBack: boolean, reason: string|null }>}
 */
async function rollbackAfterFailedTail({
  job,
  jobId,
  policyEngine,
  client,
  deployResult,
  failedStep,
  log,
}) {
  if (deployResult?.deployed !== true) {
    return { rolledBack: false, reason: "deploy step made no change (idempotent skip)" };
  }
  if (typeof deployResult.backupPath !== "string" || deployResult.backupPath.length === 0) {
    return { rolledBack: false, reason: "no previous certificate existed to restore" };
  }

  let previousPem;
  try {
    previousPem = fs.readFileSync(deployResult.backupPath, "utf8");
  } catch (err) {
    emitLog(log, `tokentimer-agent: rollback for job ${jobId} could not read the backup: ${err.message}`);
    return { rolledBack: false, reason: "backup file could not be read" };
  }

  const restore = await deployCertificate({
    target: {
      type: job?.target?.type ?? "endpoint",
      reference: job?.target?.reference ?? deployResult.destination,
      certPath: deployResult.destination,
    },
    certificatePem: previousPem,
    checkPath: (candidate) => policyEngine.checkPath(candidate),
  });
  const restored = restore.deployed === true || restore.skipped === true;
  if (!restored) {
    emitLog(log, `tokentimer-agent: rollback restore failed for job ${jobId} at stage ${restore.stage}`);
  }

  // Best-effort re-reload so the service serves the restored content again.
  let reloadNote = "not requested";
  if (restored && typeof job.reloadService === "string" && job.reloadService.length > 0) {
    reloadNote = "skipped (command refs unavailable)";
    const refs = job.reloadCommandRefs;
    if (refs && typeof refs === "object" && typeof refs.validate === "string" && typeof refs.reload === "string") {
      const validateVerdict = policyEngine.checkCommandRef(refs.validate);
      const reloadVerdict = policyEngine.checkCommandRef(refs.reload);
      if (validateVerdict.allowed && reloadVerdict.allowed) {
        try {
          const outcome = await reloadService({
            service: job.reloadService,
            commandProfiles: {
              validateArgv: validateVerdict.argv,
              reloadArgv: reloadVerdict.argv,
            },
          });
          reloadNote = outcome.reloaded === true ? "reloaded" : `reload failed at stage ${outcome.stage}`;
        } catch (err) {
          reloadNote = `reload errored: ${err.message}`;
        }
      }
    }
  }

  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "deployment.updated",
      observedAt: new Date().toISOString(),
      summary: restored
        ? `Rolled back job ${jobId}: previous certificate restored after the ${failedStep} step failed.`
        : `Rollback attempted for job ${jobId} after the ${failedStep} step failed, but the restore did not complete; the backup file still holds the previous content.`,
      metadata: [
        { name: "step", value: "rollback" },
        { name: "failedStep", value: String(failedStep) },
        { name: "restored", value: restored },
        { name: "reloadAfterRestore", value: reloadNote },
      ],
    }),
  ]);

  return restored
    ? { rolledBack: true, reason: null }
    : { rolledBack: false, reason: "restore write failed; backup retained" };
}

/**
 * Appends a rollback disposition note to a failed/rejected tail outcome's
 * errorMessage so the reported result states what is on disk.
 *
 * @param {object} outcome reportResult fields
 * @param {{ rolledBack: boolean, reason: string|null }} rollback
 * @returns {object}
 */
function withRollbackNote(outcome, rollback) {
  const note = rollback.rolledBack
    ? "rolled back to the previous certificate"
    : `not rolled back: ${rollback.reason}`;
  return {
    ...outcome,
    errorMessage: boundErrorMessage(`${outcome.errorMessage} (${note})`),
  };
}

/**
 * Shared deploy -> optional reload -> verify tail used by both renew and
 * deploy actions. Reports per-step evidence (deployment.updated with the
 * deploy module's metrics counters, validation.passed/failed for reload
 * and fingerprint verification). Returns reportResult fields (without
 * keyRotated, which only renew owns).
 *
 * @param {object} params
 * @returns {Promise<object>}
 */
async function runDeployReloadVerify({
  job,
  jobId,
  policyEngine,
  client,
  certificatePem,
  certPath,
  log,
}) {
  // Deploy step (atomic install with backup/rollback; path re-checked
  // against agent-local policy inside the module via checkPath). The
  // target type/reference pass through from the job's schema-valid target.
  const deployResult = await deployCertificate({
    target: {
      type: job?.target?.type ?? "endpoint",
      reference: job?.target?.reference ?? certPath,
      certPath,
    },
    certificatePem,
    checkPath: (candidate) => policyEngine.checkPath(candidate),
  });

  if (deployResult.deployed !== true && deployResult.skipped !== true) {
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: `Deploy step failed for job ${jobId} at stage ${deployResult.stage} (rolledBack: ${deployResult.rolledBack === true}).`,
        metadata: [
          { name: "step", value: "deploy" },
          { name: "stage", value: String(deployResult.stage) },
          { name: "rolledBack", value: deployResult.rolledBack === true },
        ],
      }),
    ]);
    return {
      status: "failed",
      errorMessage: boundErrorMessage(
        `deploy step failed at stage ${deployResult.stage}: ${deployResult.error}`,
      ),
    };
  }

  // Deploy metrics counters for this job's target type, flattened to
  // numeric publicMetadataEntry items (the evidence module only accepts
  // scalar values).
  const targetTypeForMetrics =
    typeof job?.target?.type === "string" ? job.target.type : "unknown";
  const metricsForType = getDeployMetrics()[targetTypeForMetrics] || {};
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "deployment.updated",
      observedAt: new Date().toISOString(),
      summary:
        deployResult.skipped === true
          ? `Deploy step skipped for job ${jobId}: destination already holds this certificate (idempotent).`
          : `Deploy step succeeded for job ${jobId}: certificate installed atomically.`,
      metadata: [
        { name: "step", value: "deploy" },
        { name: "idempotentSkip", value: deployResult.skipped === true },
        ...Object.entries(metricsForType)
          .filter(([, value]) => typeof value === "number")
          .map(([name, value]) => ({ name: `deployMetric_${name}`, value })),
      ],
    }),
  ]);

  // Optional reload step: only when the job names a service AND both
  // command profile refs resolve through the agent-local allowlist.
  const reloadOutcome = await maybeReloadForJob({ job, jobId, policyEngine, client, log });
  if (reloadOutcome !== null && reloadOutcome.status !== "succeeded") {
    const rollback = await rollbackAfterFailedTail({
      job,
      jobId,
      policyEngine,
      client,
      deployResult,
      failedStep: "reload",
      log,
    });
    return withRollbackNote(reloadOutcome, rollback);
  }

  // Verify step: always fingerprint the deployed PEM; probe the live
  // endpoint only when the job provides a host (job.verifyHost).
  const deployedPem = fs.readFileSync(certPath, "utf8");
  const fingerprint = computeCertificateFingerprint(deployedPem);
  let verifySummary = `Verified deployed certificate fingerprint for job ${jobId}.`;
  if (typeof job.verifyHost === "string" && job.verifyHost.length > 0) {
    // Authorization gate: verifyHost/verifyPort are job-controlled and
    // direct the agent to open a TLS connection, so the destination must
    // pass agent-local policy (metadata/link-local hard-denied, loopback
    // and off-target hosts require an explicit allowlist entry).
    const destinationVerdict = policyEngine.checkVerifyHost(job.verifyHost, {
      targetReference: job?.target?.reference,
    });
    if (!destinationVerdict.allowed) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          summary: `Verify step rejected for job ${jobId}: the verify destination is not authorized by agent-local policy.`,
          metadata: [{ name: "step", value: "verify" }],
        }),
      ]);
      const rollback = await rollbackAfterFailedTail({
        job,
        jobId,
        policyEngine,
        client,
        deployResult,
        failedStep: "verify-authorization",
        log,
      });
      return withRollbackNote(
        {
          status: "rejected",
          rejectionReason: destinationVerdict.rejectionReason,
          errorMessage: boundErrorMessage(destinationVerdict.detail),
        },
        rollback,
      );
    }

    const probe = await verifyDeployedCertificate({
      host: job.verifyHost,
      port: typeof job.verifyPort === "number" ? job.verifyPort : undefined,
      expectedFingerprintSha256: fingerprint,
    });
    if (probe.verified !== true) {
      await reportStepEvidence(client, jobId, [
        buildEvidenceItem({
          eventType: "validation.failed",
          observedAt: new Date().toISOString(),
          fingerprintSha256: fingerprint,
          summary: `Live endpoint verification failed for job ${jobId}: the served certificate does not match the deployed one.`,
          metadata: [{ name: "step", value: "verify" }],
        }),
      ]);
      const rollback = await rollbackAfterFailedTail({
        job,
        jobId,
        policyEngine,
        client,
        deployResult,
        failedStep: "verify",
        log,
      });
      return withRollbackNote(
        {
          status: "failed",
          errorMessage: boundErrorMessage(
            "verify step failed: live endpoint does not serve the deployed certificate",
          ),
        },
        rollback,
      );
    }
    verifySummary = `Verified deployed certificate fingerprint for job ${jobId} against live endpoint.`;
  }
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "validation.passed",
      observedAt: new Date().toISOString(),
      fingerprintSha256: fingerprint,
      summary: verifySummary,
      metadata: [{ name: "step", value: "verify" }],
    }),
  ]);

  return { status: "succeeded", errorMessage: null };
}

/**
 * Runs the reload step when the job requests one. Returns null when the
 * job carries no reloadService (step skipped), otherwise reportResult
 * fields for the step outcome.
 *
 * @param {object} params
 * @returns {Promise<object|null>}
 */
async function maybeReloadForJob({ job, jobId, policyEngine, client, log }) {
  if (typeof job.reloadService !== "string" || job.reloadService.length === 0) {
    return null;
  }
  const refs = job.reloadCommandRefs;
  if (
    refs === null ||
    typeof refs !== "object" ||
    typeof refs.validate !== "string" ||
    typeof refs.reload !== "string"
  ) {
    return {
      status: "failed",
      errorMessage:
        "job requests a service reload but reloadCommandRefs.validate/.reload " +
        "command references are missing",
    };
  }
  const validateVerdict = policyEngine.checkCommandRef(refs.validate);
  if (!validateVerdict.allowed) {
    return {
      status: "rejected",
      rejectionReason: validateVerdict.rejectionReason,
      errorMessage: boundErrorMessage(validateVerdict.detail),
    };
  }
  const reloadVerdict = policyEngine.checkCommandRef(refs.reload);
  if (!reloadVerdict.allowed) {
    return {
      status: "rejected",
      rejectionReason: reloadVerdict.rejectionReason,
      errorMessage: boundErrorMessage(reloadVerdict.detail),
    };
  }

  const outcome = await reloadService({
    service: job.reloadService,
    commandProfiles: {
      validateArgv: validateVerdict.argv,
      reloadArgv: reloadVerdict.argv,
    },
  });
  if (outcome.reloaded !== true) {
    log(`tokentimer-agent: reload step failed for job ${jobId}`);
    await reportStepEvidence(client, jobId, [
      buildEvidenceItem({
        eventType: "validation.failed",
        observedAt: new Date().toISOString(),
        summary: `Reload step failed for job ${jobId} at stage ${outcome.stage}.`,
        metadata: [
          { name: "step", value: "reload" },
          { name: "stage", value: String(outcome.stage) },
        ],
      }),
    ]);
    return {
      status: "failed",
      errorMessage: boundErrorMessage(`reload step failed at stage ${outcome.stage}`),
    };
  }
  await reportStepEvidence(client, jobId, [
    buildEvidenceItem({
      eventType: "validation.passed",
      observedAt: new Date().toISOString(),
      summary: `Reload step succeeded for job ${jobId} (service validated then reloaded).`,
      metadata: [{ name: "step", value: "reload" }],
    }),
  ]);
  return { status: "succeeded" };
}

/**
 * Deploy action: deploy + optional reload + verify. certificatePem comes
 * from the job (its presence is checked by executeJob before this runs).
 *
 * @param {object} params
 * @returns {Promise<object>}
 */
async function executeDeployJob({ job, jobId, policyEngine, client, log }) {
  const certPath = resolveJobCertPath(job);
  if (certPath === null) {
    return {
      status: "failed",
      errorMessage:
        "deploy job names no destination: neither job.certPath nor an " +
        "absolute-path target.reference is present",
    };
  }
  return await runDeployReloadVerify({
    job,
    jobId,
    policyEngine,
    client,
    certificatePem: job.certificatePem,
    certPath,
    log,
  });
}

/**
 * Reload action: reload only. The job must request a reloadService.
 *
 * @param {object} params
 * @returns {Promise<object>}
 */
async function executeReloadJob({ job, jobId, policyEngine, client, log }) {
  const outcome = await maybeReloadForJob({ job, jobId, policyEngine, client, log });
  if (outcome === null) {
    return {
      status: "failed",
      errorMessage: "reload job carries no reloadService field",
    };
  }
  if (outcome.status === "succeeded") {
    return { status: "succeeded", errorMessage: null };
  }
  return outcome;
}

/**
 * Runs one observe-only discovery scan over the configured directories and
 * reports parsed certificates as `certificate.observed` evidence. Only
 * public fields ever leave the host: the discovery module never reads key
 * bytes, and metadata here is limited to schema-safe names/values. Evidence
 * bodies are chunked to the schema's 16-item maximum.
 *
 * Exported for direct unit testing.
 *
 * @param {object} params
 * @param {string[]} params.directories
 * @param {object} params.client from createProtocolClient
 * @param {(msg: string) => void} [params.log]
 * @returns {Promise<{ observed: number, warnings: number }>}
 */
async function runDiscoveryScan({ directories, client, log = null }) {
  const { certificates, warnings, truncated } = discoverCertificates(directories, {
    onWarning: (message) => emitLog(log, message),
  });
  if (truncated) {
    emitLog(log, "discovery scan hit a bound and was truncated");
  }

  const items = [];
  const observedAt = new Date().toISOString();
  for (const cert of certificates) {
    if (!cert.parsed) continue;
    items.push(
      buildEvidenceItem({
        eventType: "certificate.observed",
        observedAt,
        fingerprintSha256: cert.fingerprintSha256,
        summary: `Observed certificate at ${cert.path} (subject: ${cert.subject})`,
        metadata: [
          { name: "validTo", value: cert.validTo },
          { name: "coLocatedKeyDetected", value: cert.coLocatedKeyDetected === true },
        ],
      }),
    );
  }

  const EVIDENCE_CHUNK_SIZE = 16;
  for (let start = 0; start < items.length; start += EVIDENCE_CHUNK_SIZE) {
    const body = buildEvidenceBody({
      jobId: null,
      evidenceItems: items.slice(start, start + EVIDENCE_CHUNK_SIZE),
    });
    assertEvidencePayloadSafe(body);
    await client.reportEvidence(body);
  }

  return { observed: items.length, warnings: warnings.length };
}

/**
 * Performs first-run registration when no credential is stored yet.
 * Requires TOKENTIMER_AGENT_BOOTSTRAP_TOKEN (and optionally
 * TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID) in the environment; the bootstrap
 * token is single-use and never persisted by the agent (plan section 7.2).
 *
 * @param {object} params
 * @param {object} params.client
 * @param {object} params.config from loadAgentConfig
 * @param {string} params.configDir
 * @param {NodeJS.ProcessEnv} [params.env]
 * @returns {Promise<string>} the assigned agentId
 */
async function registerIfNeeded({ client, config, configDir, env = process.env }) {
  // Already-registered paths: an earlier run exchanged the bootstrap token,
  // but systemd may still have re-exported it from a leftover bootstrap.env.
  // Scrub it here too so a registered agent never keeps the (already spent)
  // token in its environment or on disk.
  const scrubBootstrapToken = () => {
    if (env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN !== undefined) {
      delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
      delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID;
    }
    deleteBootstrapEnvFile(configDir);
  };

  const recovered = recoverPendingRegistration(configDir);
  if (recovered !== null) {
    clearRegistrationId(configDir);
    scrubBootstrapToken();
    return recovered.agentId;
  }

  const existingCredential = readCredential(configDir);
  if (existingCredential !== null) {
    if (!config.agentId) {
      throw new Error(
        "tokentimer-agent: found a stored credential but no agentId in " +
          "config.json; the config directory is inconsistent. Re-register " +
          "with a fresh bootstrap token or restore config.json.",
      );
    }
    clearRegistrationId(configDir);
    scrubBootstrapToken();
    return config.agentId;
  }

  const bootstrapToken = env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
  if (!bootstrapToken) {
    throw new Error(
      "tokentimer-agent: no stored credential and no " +
        "TOKENTIMER_AGENT_BOOTSTRAP_TOKEN set. Obtain a bootstrap token " +
        "from the dashboard and export it to register this agent.",
    );
  }

  // H1: persist a client-generated registrationId BEFORE the register
  // request so a crash after the server consumes the bootstrap token can
  // retry with the same id and accept an idempotent replayed response.
  const registrationId = ensureRegistrationId(configDir);

  const registration = validateRegistrationResponse(await client.register({
    bootstrapToken,
    bootstrapTokenId: env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID || "unknown",
    agentVersion: AGENT_VERSION,
    hostname: os.hostname(),
    platform: process.platform,
    nodeVersion: process.version,
    declaredTargetSelectors: config.declaredTargetSelectors,
    declaredCommandProfileNames: config.declaredCommandProfileNames,
    registrationId,
  }), config.protocolVersion);

  persistRegistration(configDir, {
    agentId: registration.agentId,
    credential: registration.credential,
  });
  clearRegistrationId(configDir);
  // The bootstrap token is single-use and has now been exchanged for a
  // stored per-agent credential. Scrub it from this process's environment
  // (so it can never leak into child processes or diagnostics) and remove
  // the installer-written bootstrap.env file (so systemd stops re-exporting
  // it on every later start).
  delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN;
  delete env.TOKENTIMER_AGENT_BOOTSTRAP_TOKEN_ID;
  deleteBootstrapEnvFile(configDir);
  // Trust-on-first-use pinning (ADR-0003): when the register response
  // carries the control plane's job-signing key info, persist it so every
  // later run verifies jobs against the same key. Public material only.
  // allowRepin: this IS the explicit registration flow, the only place a
  // pin rotation is legitimate (a fresh bootstrap token was presented);
  // writeSigningKeyPin refuses silent re-pins everywhere else.
  if (registration.signingKeyId && registration.signingPublicKeyPem) {
    writeSigningKeyPin(
      configDir,
      {
        signingKeyId: registration.signingKeyId,
        signingPublicKeyPem: registration.signingPublicKeyPem,
      },
      { allowRepin: true },
    );
  }
  return registration.agentId;
}

function createCandidateAgentId(hostname = os.hostname(), pid = process.pid) {
  const normalizedHostname = String(hostname || "host")
    .normalize("NFKD")
    .replace(/[^A-Za-z0-9_.:-]+/g, "-")
    .replace(/[-_.:]+$/g, "")
    .slice(0, 96) || "host";
  const normalizedPid = Number.isInteger(pid) && pid >= 0 ? String(pid) : "0";
  return `candidate-${normalizedHostname}-${normalizedPid}`.slice(0, 128);
}

/**
 * Builds the execution context from a loaded config. Returns null when
 * execution is not configured or not enabled, which callers treat as "run
 * in observe-only bootstrap mode".
 *
 * Startup fail-loud: a corrupted replay store throws here (surfacing as a
 * startup failure) instead of being silently recreated -- see the replay
 * module's rationale (a tampered store is a security signal).
 *
 * Exported for direct unit testing; tests may inject acmeExecFileImpl to
 * stub the ACME child process.
 *
 * @param {object} params
 * @param {object} params.config from loadAgentConfig
 * @param {Function} [params.acmeExecFileImpl] test-only execFile override
 * @returns {{
 *   enabled: true,
 *   execution: object,
 *   outboxDir: string,
 *   replayCache: object,
 *   clockEstimator: object,
 *   pinnedSigningKey: {signingKeyId: string, publicKeyPem: string}|null,
 *   acmeExecFileImpl: Function|undefined,
 * }|null}
 */
function buildExecutionContext({ config, acmeExecFileImpl } = {}) {
  if (!config?.execution || config.execution.enabled !== true) {
    return null;
  }
  if (typeof config.execution.outboxDir !== "string" || config.execution.outboxDir.length === 0) {
    throw new Error(
      "tokentimer-agent: execution.outboxDir is required when execution is enabled",
    );
  }
  const clockEstimator = createClockOffsetEstimator();
  let replayCache;
  try {
    replayCache = createReplayCache({
      storePath: config.execution.replayStorePath,
      // Retention must cover the same tolerance tail checkJobTimeWindow
      // accepts (expiresAt + tolerance), and the sweep must run on the
      // same offset-adjusted timeline as the acceptance decision --
      // otherwise a nonce could be evicted while its job is still
      // acceptable, reopening the replay window.
      retentionToleranceMs: DEFAULT_TIME_WINDOW_TOLERANCE_MS,
      now: () => Date.now() + (clockEstimator.getOffsetMs() ?? 0),
    });
  } catch (err) {
    throw new Error(
      "tokentimer-agent: failed to load the replay store at " +
        `${config.execution.replayStorePath}: ${err.message}. A corrupted ` +
        "replay store may indicate tampering; refusing to start execution " +
        "until an operator inspects it.",
    );
  }
  return {
    enabled: true,
    execution: config.execution,
    outboxDir: config.execution.outboxDir,
    replayCache,
    clockEstimator,
    pinnedSigningKey: config.pinnedSigningKey,
    acmeExecFileImpl,
  };
}

/**
 * Runs the agent process: load config, register if needed, then run the
 * heartbeat and claim loops until SIGINT/SIGTERM or until the control plane
 * retires this agent (heartbeat HTTP 410 -> clean exit, no respawn loop,
 * ADR-0002).
 *
 * @param {string[]} _argv CLI arguments (none supported yet; configuration
 *   is via config.json and TOKENTIMER_AGENT_* env vars)
 * @param {{ signal?: AbortSignal }} [options] optional external abort
 *   signal, used by tests to stop the loops deterministically
 * @returns {Promise<void>}
 */
async function runAgent(_argv, { signal: externalSignal } = {}) {
  const configDir = resolveConfigDir();
  const config = loadAgentConfig({ configDir });

  // Execution context (null in bootstrap/observe-only mode). Built before
  // any network call so a corrupted replay store fails startup immediately.
  const executionContext = buildExecutionContext({ config });

  const controller = new AbortController();
  const stop = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) return;
    externalSignal.addEventListener("abort", stop, { once: true });
  }
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);

  // Default deny: with no policy block in config.json every allowlist is
  // empty, so the engine rejects all command/path/CA/DNS dimensions. The
  // agent still runs (heartbeats, claims, reports rejections as evidence)
  // so operators can see policy conflicts instead of silent failures.
  const policyEngine = createPolicyEngine(loadPolicyConfig(config.policy || {}), {
    declaredTargetSelectors: config.declaredTargetSelectors,
  });

  const fetchImpl = config.caBundlePath
    ? createCaAwareFetch({ caBundlePem: readCaBundle(config.caBundlePath) })
    : undefined;

  const onServerDate = executionContext
    ? (dateHeaderValue, localNowMs) =>
        executionContext.clockEstimator.estimateFromResponseDate(
          dateHeaderValue,
          localNowMs,
        )
    : undefined;

  // One persisted, crash-safe sequence stream shared by EVERY protocol
  // client this process creates (candidate/registration client included):
  // the control plane hard-rejects sequence regressions, so all outbound
  // messages must draw from a single counter that survives restarts.
  const sequenceAllocator = createSequenceAllocator(configDir);

  const clientForAgentId = (agentId) =>
    createProtocolClient({
      serverUrl: config.serverUrl,
      agentId,
      protocolVersion: config.protocolVersion,
      getCredential: () => readCredential(configDir),
      signal: controller.signal,
      fetchImpl,
      allowInsecureLocalHttp: config.allowInsecureLocalHttp,
      onServerDate,
      sequenceAllocator,
    });

  // For a not-yet-registered agent the envelope needs a client-generated
  // candidate id; the control plane echoes back the assigned id (schema
  // note on agentId). A registered agent uses its stored id.
  let registeredAgentId;
  try {
    const candidateAgentId = config.agentId || createCandidateAgentId();
    registeredAgentId = await registerIfNeeded({
      client: clientForAgentId(candidateAgentId),
      config,
      configDir,
    });
  } catch (err) {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    if (externalSignal) externalSignal.removeEventListener("abort", stop);
    throw err;
  }

  const client = clientForAgentId(registeredAgentId);

  // Registration may have just pinned the signing key; reload it so a
  // first-run agent can execute without a restart.
  if (executionContext && !executionContext.pinnedSigningKey) {
    executionContext.pinnedSigningKey = readSigningKeyPin(configDir);
  }

  // B8: drain any un-acknowledged outbox entries from a prior run before
  // new job polling resumes, so a crash after successful execution but
  // before transmission cannot leave a success stranded or re-executed.
  if (executionContext) {
    await drainOutbox(executionContext.outboxDir, client, {
      onError: (err, entry) =>
        defaultAgentLogger.error(
          `tokentimer-agent: outbox drain failed for ${entry.id}; will retry`,
          err,
        ),
    });
  }

  const startedAtMs = Date.now();

  const heartbeatLoop = startPollLoop({
    intervalMs: config.heartbeatIntervalMs,
    signal: controller.signal,
    startImmediately: true,
    onTick: async () => {
      const response = await client.heartbeat({
        agentVersion: AGENT_VERSION,
        uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
        // With execution enabled, report the measured clock offset and the
        // pinned signing key id so the control plane can spot drift and
        // key-rotation lag. in observe-only bootstrap mode these stay null.
        ...(executionContext
          ? {
              clockOffsetMs: executionContext.clockEstimator.getOffsetMs(),
              pinnedSigningKeyId:
                executionContext.pinnedSigningKey?.signingKeyId ?? null,
            }
          : {}),
      });
      if (response && response.retired === true) {
        defaultAgentLogger.error("control plane retired this agent; exiting cleanly");
        // Distinct exit status so systemd's RestartPreventExitStatus stops
        // respawning a decommissioned agent into a heartbeat 410 loop.
        process.exitCode = AGENT_RETIRED_EXIT_CODE;
        stop();
      }
    },
  });

  // Observe-only discovery loop (filesystem certificate inventory).
  // Only started when config.json opts in with a discovery.directories list;
  // scans run immediately on start, then on the configured interval.
  const loops = [heartbeatLoop];

  // B3: observe-only agents never poll claim (and advertise no actions).
  // Heartbeat + discovery stay fully independent of the execution plane.
  if (shouldPollForJobs(executionContext)) {
    loops.push(
      startPollLoop({
        intervalMs: config.pollIntervalMs,
        signal: controller.signal,
        startImmediately: true,
        onTick: async () => {
          // Retry any outbox entries that failed to transmit before claiming
          // more work (idempotent; never re-executes).
          await drainOutbox(executionContext.outboxDir, client, {
            onError: (err, entry) =>
              defaultAgentLogger.error(
                `tokentimer-agent: outbox drain failed for ${entry.id}; will retry`,
                err,
              ),
          });
          const jobs = await client.claim({
            maxJobs: 1,
            supportedActions: resolveClaimSupportedActions(executionContext),
          });
          for (const job of jobs) {
            if (controller.signal.aborted) break;
            await handleClaimedJob({ job, policyEngine, client, executionContext });
          }
        },
      }),
    );
  }

  if (config.discovery && config.discovery.directories.length > 0) {
    loops.push(
      startPollLoop({
        intervalMs: config.discovery.intervalMs,
        signal: controller.signal,
        startImmediately: true,
        onTick: () =>
          runDiscoveryScan({
            directories: config.discovery.directories,
            client,
          }),
      }),
    );
  }

  try {
    await Promise.all(loops);
  } finally {
    process.removeListener("SIGINT", stop);
    process.removeListener("SIGTERM", stop);
    if (externalSignal) externalSignal.removeEventListener("abort", stop);
  }
}

module.exports = {
  runAgent,
  handleClaimedJob,
  executeJob,
  buildExecutionContext,
  buildJobPolicyDescriptor,
  resolveJobCertPath,
  runDiscoveryScan,
  registerIfNeeded,
  createCandidateAgentId,
  resolveClaimSupportedActions,
  shouldPollForJobs,
  persistAndTransmitOutcome,
  AGENT_VERSION,
  AGENT_RETIRED_EXIT_CODE,
  EXECUTABLE_JOB_ACTIONS,
  OBSERVE_ONLY_CLAIM_ACTIONS,
};
